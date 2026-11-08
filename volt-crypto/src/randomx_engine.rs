//! The RandomX engine.

use std::{
    collections::HashMap,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, OnceLock,
    },
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

/// How many hashes to remember. Every node re-checks the work of every block it receives, and a
/// replay checks the whole chain again, so repeats are common.
const MEMO_CAPACITY: usize = 65_536;

/// How many RandomX keys to keep a VM for. The key changes rarely, but a node briefly checks
/// blocks under both the old and the new key around a change.
const KEYS_KEPT: usize = 2;

/// A RandomX hasher in light (cache-only, ~256 MiB) mode.
///
/// Light mode is slower per hash than the full 2 GiB dataset, but it is what a verifying
/// node needs, and what keeps the memory floor low for CPU miners. A VM is built for each key
/// the first time it is used.
///
/// `RandomXVM` wraps raw C pointers and is not `Send`, so the VMs live on one dedicated worker
/// thread and this handle talks to it over a channel. That keeps this crate free of `unsafe`.
/// Hashing is therefore serialized: parallel mining needs one engine per mining thread.
pub struct RandomXEngine {
    jobs: Mutex<Sender<Job>>,
    memo: Mutex<HashMap<([u8; 32], Vec<u8>), [u8; 32]>>,
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
            memo: Mutex::new(HashMap::new()),
        })
    }

    /// One engine shared by the whole process, for tests and in-process simulations.
    ///
    /// Building a RandomX cache takes about a second and a quarter of a gigabyte, so tests that
    /// each started their own engine would spend their time on that. Sharing one also lets the
    /// hashes of one test's blocks be remembered for the next.
    ///
    /// # Panics
    ///
    /// If the RandomX worker thread cannot start.
    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<RandomXEngine>> = OnceLock::new();
        SHARED
            .get_or_init(|| Arc::new(Self::new().expect("the RandomX engine starts")))
            .clone()
    }
}

fn worker(inbox: Receiver<Job>) {
    let mut flags = RandomXFlag::get_recommended_flags();
    flags.remove(RandomXFlag::FLAG_FULL_MEM);

    // Most recently used first.
    let mut vms: Vec<([u8; 32], RandomXVM)> = Vec::new();
    // The loop ends when the engine, and with it the sender, is dropped.
    while let Ok(job) = inbox.recv() {
        let result = hash(&mut vms, flags, &job);
        // The requester may have gone away; there is nobody to tell.
        let _ = job.reply.send(result);
    }
}

fn hash(
    vms: &mut Vec<([u8; 32], RandomXVM)>,
    flags: RandomXFlag,
    job: &Job,
) -> Result<[u8; 32], PowError> {
    let engine_error = |e: randomx_rs::RandomXError| PowError::Engine(e.to_string());

    match vms.iter().position(|(seed, _)| *seed == job.seed) {
        Some(0) => {}
        Some(i) => vms[..=i].rotate_right(1),
        None => {
            let cache = RandomXCache::new(flags, &job.seed).map_err(engine_error)?;
            let vm = RandomXVM::new(flags, Some(cache), None).map_err(engine_error)?;
            vms.insert(0, (job.seed, vm));
            vms.truncate(KEYS_KEPT);
        }
    }

    vms[0]
        .1
        .calculate_hash(&job.input)
        .map_err(engine_error)?
        .try_into()
        .map_err(|_| PowError::Engine("RandomX returned a hash that is not 32 bytes".into()))
}

impl PowHasher for RandomXEngine {
    fn pow_hash(&self, seed: &[u8; 32], input: &[u8]) -> Result<[u8; 32], PowError> {
        if let Some(known) = self.memo.lock().get(&(*seed, input.to_vec())) {
            return Ok(*known);
        }
        let (reply, answer) = mpsc::channel();
        self.jobs
            .lock()
            .send(Job {
                seed: *seed,
                input: input.to_vec(),
                reply,
            })
            .map_err(|_| PowError::Engine("the RandomX worker thread has stopped".into()))?;
        let computed = answer
            .recv()
            .map_err(|_| PowError::Engine("the RandomX worker thread stopped mid-hash".into()))??;

        let mut memo = self.memo.lock();
        if memo.len() >= MEMO_CAPACITY {
            memo.clear();
        }
        memo.insert((*seed, input.to_vec()), computed);
        Ok(computed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_depend_on_the_key_and_the_input_and_repeat() {
        let engine = RandomXEngine::shared();
        let a = engine.pow_hash(&[1; 32], b"x").unwrap();
        assert_eq!(a, engine.pow_hash(&[1; 32], b"x").unwrap());
        assert_ne!(a, engine.pow_hash(&[2; 32], b"x").unwrap());
        assert_ne!(a, engine.pow_hash(&[1; 32], b"y").unwrap());
        // Going back to the first key still works (and a fresh engine agrees: it is not just the memo).
        let fresh = RandomXEngine::new().unwrap();
        assert_eq!(a, fresh.pow_hash(&[1; 32], b"x").unwrap());
    }
}
