//! The RandomX engine.

use std::{
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use parking_lot::Mutex;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

use crate::pow::{PowError, PowHasher};

/// One hashing request for the worker thread.
struct Job {
    seed: [u8; 32],
    input: Vec<u8>,
    reply: Sender<Result<[u8; 32], PowError>>,
}

/// A RandomX hasher in light (cache-only, ~256 MiB) mode.
///
/// Light mode is slower per hash than the full 2 GiB dataset, but it is what a verifying
/// node needs, and what keeps the memory floor low for CPU miners. The VM is rebuilt when
/// the seed changes, which happens once per epoch.
///
/// `RandomXVM` wraps raw C pointers and is not `Send`, so the VM lives on one dedicated worker
/// thread and this handle talks to it over a channel. That keeps this crate free of `unsafe`.
/// Hashing is therefore serialized: parallel mining needs one engine per mining thread.
pub struct RandomXEngine {
    jobs: Mutex<Sender<Job>>,
}

impl std::fmt::Debug for RandomXEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RandomXEngine")
    }
}

impl RandomXEngine {
    /// Starts the worker thread, using the best flags for this CPU without the full dataset.
    pub fn new() -> Result<Self, PowError> {
        let (jobs, inbox) = mpsc::channel();
        thread::Builder::new()
            .name("randomx".into())
            .spawn(move || worker(inbox))
            .map_err(|e| PowError::Engine(format!("could not start the RandomX thread: {e}")))?;
        Ok(Self {
            jobs: Mutex::new(jobs),
        })
    }
}

fn worker(inbox: Receiver<Job>) {
    let mut flags = RandomXFlag::get_recommended_flags();
    flags.remove(RandomXFlag::FLAG_FULL_MEM);

    let mut vm: Option<([u8; 32], RandomXVM)> = None;
    // The loop ends when the engine, and with it the sender, is dropped.
    while let Ok(job) = inbox.recv() {
        let result = hash(&mut vm, flags, &job);
        // The requester may have gone away; there is nobody to tell.
        let _ = job.reply.send(result);
    }
}

fn hash(
    vm: &mut Option<([u8; 32], RandomXVM)>,
    flags: RandomXFlag,
    job: &Job,
) -> Result<[u8; 32], PowError> {
    let engine_error = |e: randomx_rs::RandomXError| PowError::Engine(e.to_string());

    if vm.as_ref().is_none_or(|(seed, _)| *seed != job.seed) {
        let cache = RandomXCache::new(flags, &job.seed).map_err(engine_error)?;
        let new_vm = RandomXVM::new(flags, Some(cache), None).map_err(engine_error)?;
        *vm = Some((job.seed, new_vm));
    }

    let (_, vm) = vm
        .as_ref()
        .expect("the VM was just initialized for this seed");
    vm.calculate_hash(&job.input)
        .map_err(engine_error)?
        .try_into()
        .map_err(|_| PowError::Engine("RandomX returned a hash that is not 32 bytes".into()))
}

impl PowHasher for RandomXEngine {
    fn pow_hash(&self, seed: &[u8; 32], input: &[u8]) -> Result<[u8; 32], PowError> {
        let (reply, answer) = mpsc::channel();
        self.jobs
            .lock()
            .send(Job {
                seed: *seed,
                input: input.to_vec(),
                reply,
            })
            .map_err(|_| PowError::Engine("the RandomX worker thread has stopped".into()))?;
        answer
            .recv()
            .map_err(|_| PowError::Engine("the RandomX worker thread stopped mid-hash".into()))?
    }
}
