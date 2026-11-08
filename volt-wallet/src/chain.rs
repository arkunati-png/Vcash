//! Scanning the node's chain feed for this wallet's shielded notes.
//!
//! The node lists its accepted chain steps in the order they were applied, with the Sapling
//! tree root after each one. The wallet appends every note commitment to its own tree in that
//! order, tries to decrypt each output with its incoming viewing key, and keeps a witness for
//! every note it owns. After every step the wallet's root must equal the node's, which is the
//! proof that the witnesses it will later spend with are valid.
//!
//! Everything cryptographic here is `sapling-crypto` and `incrementalmerkletree`.

use sapling_crypto::{
    keys::NullifierDerivingKey,
    note::ExtractedNoteCommitment,
    note_encryption::{
        try_sapling_note_decryption, NoteCiphertextBytes, PreparedIncomingViewingKey,
        SaplingDomain, Zip212Enforcement, COMPACT_NOTE_SIZE,
    },
    zip32::DiversifiableFullViewingKey,
    CommitmentTree, IncrementalWitness, Node, Note, Nullifier,
};
use zcash_note_encryption::{note_bytes::NoteBytesData, EphemeralKeyBytes, ShieldedOutput};
use zip32::Scope;

use std::sync::Mutex;

use zcash_primitives::merkle_tree::{
    read_commitment_tree, read_incremental_witness, write_commitment_tree,
    write_incremental_witness,
};

use crate::rpc::{self, StepData};

const SAVE_MAGIC: &[u8; 4] = b"VSC1";

fn put_string(w: &mut Vec<u8>, text: &str) {
    w.extend_from_slice(&(text.len() as u32).to_le_bytes());
    w.extend_from_slice(text.as_bytes());
}

/// Reads the fields of a saved scan.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "a saved scan is cut short".to_owned())?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn string(&mut self) -> Result<String, String> {
        let len = u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| "bad text in a saved scan".to_owned())
    }

    /// Runs a reader that consumes a variable amount, and moves past what it consumed.
    fn read_with<T>(
        &mut self,
        read: impl FnOnce(&mut &'a [u8]) -> std::io::Result<T>,
    ) -> Result<T, String> {
        let mut rest = &self.bytes[self.at..];
        let before = rest.len();
        let value = read(&mut rest).map_err(|e| e.to_string())?;
        self.at += before - rest.len();
        Ok(value)
    }
}

/// A note this wallet can spend, or has spent.
#[derive(Clone)]
pub struct OwnedNote {
    pub note: Note,
    /// The note's position among all Sapling commitments.
    pub position: u64,
    /// Authenticates the note against the tree as of the latest scanned step.
    pub witness: IncrementalWitness,
    /// The 512-byte memo that came with the note.
    pub memo: [u8; 512],
    pub nullifier: Nullifier,
    /// The transaction that created the note, as the node names it.
    pub txid: String,
    /// The chain step the note appeared in.
    pub step: usize,
    pub spent: bool,
    /// The output this note came from, kept so a saved scan can decrypt it again on load
    /// instead of storing secret note fields.
    output: SavedOutput,
}

/// An output as the node sent it: commitment, ephemeral key and encrypted note.
#[derive(Clone)]
struct SavedOutput {
    cmu: [u8; 32],
    epk: [u8; 32],
    enc: [u8; 580],
}

impl OwnedNote {
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }

    /// The memo as text, if it is text. Empty when the sender left it blank.
    pub fn memo_text(&self) -> Option<String> {
        match self.memo[0] {
            0xF6 if self.memo[1..].iter().all(|b| *b == 0) => None,
            b if b <= 0xF4 => {
                let end = self.memo.iter().rposition(|b| *b != 0)? + 1;
                String::from_utf8(self.memo[..end].to_vec()).ok()
            }
            _ => None,
        }
    }
}

/// The wire form of a full 580-byte output, as `sapling-crypto` wants it for decryption.
struct FullOutput {
    cmu: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: NoteCiphertextBytes,
}

impl ShieldedOutput<SaplingDomain> for FullOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.ephemeral_key.clone()
    }

    fn cmstar(&self) -> &ExtractedNoteCommitment {
        &self.cmu
    }

    fn enc_ciphertext(&self) -> Option<&NoteCiphertextBytes> {
        Some(&self.enc_ciphertext)
    }

    fn enc_ciphertext_compact(&self) -> NoteBytesData<COMPACT_NOTE_SIZE> {
        NoteBytesData(
            self.enc_ciphertext.0[..COMPACT_NOTE_SIZE]
                .try_into()
                .expect("slice is the correct length"),
        )
    }
}

/// Why a step could not be applied.
#[derive(Debug, PartialEq, Eq)]
pub enum ScanError {
    /// The step is not the next one the wallet expects.
    OutOfOrder { expected: usize, got: usize },
    /// After applying the step the wallet's tree differs from the node's.
    RootMismatch { step: usize },
    /// The node sent a commitment that is not a valid field element.
    BadCommitment { step: usize },
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfOrder { expected, got } => {
                write!(f, "expected chain step {expected}, the node sent {got}")
            }
            Self::RootMismatch { step } => {
                write!(
                    f,
                    "the wallet's note tree differs from the node's at step {step}"
                )
            }
            Self::BadCommitment { step } => {
                write!(f, "step {step} holds an invalid note commitment")
            }
        }
    }
}

/// What a wallet knows about the chain's shielded state, rebuilt from the node's feed.
pub struct Scanner {
    ivk: PreparedIncomingViewingKey,
    nk: NullifierDerivingKey,
    tree: CommitmentTree,
    leaves: u64,
    /// For each applied step: the chain block that closed it, and the root after it.
    steps: Vec<(String, [u8; 32])>,
    notes: Vec<OwnedNote>,
}

impl Scanner {
    /// A scanner for the account behind `dfvk`, positioned before the first step.
    pub fn new(dfvk: &DiversifiableFullViewingKey) -> Self {
        Self {
            ivk: PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::External)),
            nk: dfvk.to_nk(Scope::External),
            tree: CommitmentTree::empty(),
            leaves: 0,
            steps: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Forgets everything and starts again from the first step.
    pub fn reset(&mut self) {
        self.tree = CommitmentTree::empty();
        self.leaves = 0;
        self.steps.clear();
        self.notes.clear();
    }

    /// The index of the next step to apply.
    pub fn next_step(&self) -> usize {
        self.steps.len()
    }

    /// The chain block that closed the last applied step.
    pub fn last_block(&self) -> Option<&str> {
        self.steps.last().map(|(block, _)| block.as_str())
    }

    /// The Sapling root after the last applied step. Every spend anchors to this or an earlier one.
    pub fn root(&self) -> [u8; 32] {
        self.tree.root().to_bytes()
    }

    /// The notes that are neither spent nor still unconfirmed.
    pub fn unspent(&self) -> Vec<&OwnedNote> {
        self.notes.iter().filter(|n| !n.spent).collect()
    }

    /// Every note ever received, spent or not.
    pub fn all_notes(&self) -> &[OwnedNote] {
        &self.notes
    }

    /// The total value of the unspent notes, in zats.
    pub fn balance(&self) -> u64 {
        self.unspent().iter().map(|n| n.value()).sum()
    }

    /// The scanner's state as bytes, so a later run can pick up where this one stopped.
    ///
    /// Notes are stored as the encrypted outputs they came from plus their witnesses, never as
    /// decrypted fields: loading decrypts them again with the viewing key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(SAVE_MAGIC);
        w.extend_from_slice(&self.leaves.to_le_bytes());
        write_commitment_tree(&self.tree, &mut w).expect("writing to a Vec cannot fail");
        w.extend_from_slice(&(self.steps.len() as u64).to_le_bytes());
        for (block, root) in &self.steps {
            put_string(&mut w, block);
            w.extend_from_slice(root);
        }
        w.extend_from_slice(&(self.notes.len() as u64).to_le_bytes());
        for note in &self.notes {
            w.extend_from_slice(&note.position.to_le_bytes());
            w.extend_from_slice(&(note.step as u64).to_le_bytes());
            w.push(u8::from(note.spent));
            put_string(&mut w, &note.txid);
            w.extend_from_slice(&note.output.cmu);
            w.extend_from_slice(&note.output.epk);
            w.extend_from_slice(&note.output.enc);
            write_incremental_witness(&note.witness, &mut w).expect("writing to a Vec cannot fail");
        }
        w
    }

    /// Restores a scanner saved by [`Scanner::to_bytes`] for the account behind `dfvk`.
    ///
    /// It fails on anything odd: a different account, damage, or a tree that does not match the
    /// saved root. The caller then starts a fresh scan, which is always correct, only slower.
    pub fn from_bytes(dfvk: &DiversifiableFullViewingKey, bytes: &[u8]) -> Result<Self, String> {
        let mut scanner = Self::new(dfvk);
        let mut r = Reader { bytes, at: 0 };
        if r.take(SAVE_MAGIC.len())? != SAVE_MAGIC {
            return Err("not a saved scan".to_owned());
        }
        scanner.leaves = r.u64()?;
        scanner.tree = r.read_with(|rest| read_commitment_tree(rest))?;
        let steps = r.u64()?;
        for _ in 0..steps {
            let block = r.string()?;
            let root: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            scanner.steps.push((block, root));
        }
        let notes = r.u64()?;
        for _ in 0..notes {
            let position = r.u64()?;
            let step = usize::try_from(r.u64()?).map_err(|_| "bad step".to_owned())?;
            let spent = r.take(1)?[0] == 1;
            let txid = r.string()?;
            let cmu: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            let epk: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            let enc: [u8; 580] = r.take(580)?.try_into().expect("580 bytes");
            let witness = r.read_with(|rest| read_incremental_witness(rest))?;
            let output = FullOutput {
                cmu: Option::from(ExtractedNoteCommitment::from_bytes(&cmu))
                    .ok_or("a saved note has an invalid commitment")?,
                ephemeral_key: EphemeralKeyBytes(epk),
                enc_ciphertext: NoteBytesData(enc),
            };
            let (note, _address, memo) =
                try_sapling_note_decryption(&scanner.ivk, &output, Zip212Enforcement::GracePeriod)
                    .ok_or("a saved note no longer decrypts: this is a different account")?;
            let nullifier = note.nf(&scanner.nk, position);
            scanner.notes.push(OwnedNote {
                note,
                position,
                witness,
                memo,
                nullifier,
                txid,
                step,
                spent,
                output: SavedOutput { cmu, epk, enc },
            });
        }
        if r.at != bytes.len() {
            return Err("trailing bytes in a saved scan".to_owned());
        }
        match scanner.steps.last() {
            Some((_, root)) if scanner.tree.root().to_bytes() == *root => Ok(scanner),
            Some(_) => Err("the saved tree does not match the saved root".to_owned()),
            None if scanner.leaves == 0 => Ok(scanner),
            None => Err("a saved scan has notes but no steps".to_owned()),
        }
    }

    /// Applies the next step of the feed, checking it against the node's root.
    pub fn apply(&mut self, step: &StepData) -> Result<(), ScanError> {
        if step.index != self.steps.len() {
            return Err(ScanError::OutOfOrder {
                expected: self.steps.len(),
                got: step.index,
            });
        }

        for tx in &step.txs {
            // Mark spends. A note can only be spent once the step that created it is over, so
            // matching on the nullifiers revealed so far is enough.
            for nullifier in &tx.nullifiers {
                for note in self.notes.iter_mut().filter(|n| !n.spent) {
                    if note.nullifier.0 == *nullifier {
                        note.spent = true;
                    }
                }
            }

            for (i, commitment) in tx.commitments.iter().enumerate() {
                let cmu = Option::from(ExtractedNoteCommitment::from_bytes(commitment))
                    .ok_or(ScanError::BadCommitment { step: step.index })?;
                let node = Node::from_cmu(&cmu);

                // Every witness we hold has to see every later leaf.
                for owned in &mut self.notes {
                    owned
                        .witness
                        .append(node)
                        .map_err(|()| ScanError::RootMismatch { step: step.index })?;
                }
                self.tree
                    .append(node)
                    .map_err(|_| ScanError::RootMismatch { step: step.index })?;
                let position = self.leaves;
                self.leaves += 1;

                // Is this output ours?
                let Some((epk, enc)) = tx.outputs.get(i) else {
                    continue;
                };
                let Ok(enc) = <[u8; 580]>::try_from(enc.as_slice()) else {
                    continue;
                };
                let output = FullOutput {
                    cmu,
                    ephemeral_key: EphemeralKeyBytes(*epk),
                    enc_ciphertext: NoteBytesData(enc),
                };
                if let Some((note, _address, memo)) =
                    try_sapling_note_decryption(&self.ivk, &output, Zip212Enforcement::GracePeriod)
                {
                    let witness = IncrementalWitness::from_tree(self.tree.clone())
                        .expect("the tree is not empty: a leaf was just appended");
                    let nullifier = note.nf(&self.nk, position);
                    self.notes.push(OwnedNote {
                        note,
                        position,
                        witness,
                        memo,
                        nullifier,
                        txid: tx.txid.clone(),
                        step: step.index,
                        spent: false,
                        output: SavedOutput {
                            cmu: *commitment,
                            epk: *epk,
                            enc,
                        },
                    });
                }
            }
        }

        if self.tree.root().to_bytes() != step.root || self.leaves != step.notes {
            return Err(ScanError::RootMismatch { step: step.index });
        }
        self.steps.push((step.block.clone(), step.root));
        Ok(())
    }
}

/// What a sync did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Steps applied this time.
    pub applied: usize,
    /// Whether the node's chain changed under the wallet and it had to start again.
    pub rescanned: bool,
}

/// Brings the shared `scanner` up to the node's latest step.
///
/// To notice a reorg it re-reads the last step it already has: if the node now names a
/// different block there, the wallet throws its state away and scans from the start. A step
/// whose root does not match is treated the same way, once. The scanner is only locked while
/// steps are applied, never while waiting for the network.
pub fn sync(scanner: &Mutex<Scanner>, service: &str) -> Result<SyncReport, String> {
    let mut report = SyncReport::default();
    let mut restarted = false;
    loop {
        let (have, last) = {
            let s = scanner.lock().expect("scanner lock");
            (s.next_step(), s.last_block().map(str::to_owned))
        };
        let from = have.saturating_sub(1);
        let (total, mut steps) = rpc::steps(service, from, 200)?;

        if total < have {
            // The node has a shorter chain than we scanned: it reorged or it is a different chain.
            scanner.lock().expect("scanner lock").reset();
            report.rescanned = true;
            continue;
        }
        if have > 0 {
            match steps.first() {
                Some(first) if first.index == from => {
                    if Some(first.block.as_str()) != last.as_deref() {
                        scanner.lock().expect("scanner lock").reset();
                        report.rescanned = true;
                        continue;
                    }
                    steps.remove(0);
                }
                _ => return Err("the node did not return the step the wallet asked for".to_owned()),
            }
        }
        if steps.is_empty() {
            return Ok(report);
        }
        let mut s = scanner.lock().expect("scanner lock");
        for step in &steps {
            if let Err(error) = s.apply(step) {
                if restarted {
                    return Err(error.to_string());
                }
                // A root that does not match after a reorg we did not see: start over once.
                restarted = true;
                s.reset();
                report.rescanned = true;
                break;
            }
            report.applied += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        sync::Arc,
    };

    use sapling_crypto::Node;

    use super::*;
    use crate::keys;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn scanner() -> Scanner {
        let ufvk = keys::viewing_key(PHRASE).unwrap();
        Scanner::new(ufvk.sapling().unwrap())
    }

    /// A made-up chain: each step is a block name and the commitments it adds.
    type FakeChain = Vec<(String, Vec<u64>)>;

    fn commitment(n: u64) -> [u8; 32] {
        Node::from_scalar(bls12_381::Scalar::from(n + 1_000)).to_bytes()
    }

    /// What a node would answer to `STEPS from max` for this chain.
    fn steps_line(chain: &FakeChain, from: usize, max: usize) -> String {
        let mut tree = CommitmentTree::empty();
        let mut leaves = 0u64;
        let mut rows = Vec::new();
        for (index, (block, notes)) in chain.iter().enumerate() {
            for n in notes {
                let cmu = ExtractedNoteCommitment::from_bytes(&commitment(*n)).unwrap();
                tree.append(Node::from_cmu(&cmu)).unwrap();
                leaves += 1;
            }
            if index >= from && rows.len() < max {
                let txs = if notes.is_empty() {
                    "-".to_owned()
                } else {
                    let cms: Vec<String> = notes.iter().map(|n| hex(&commitment(*n))).collect();
                    format!("{}/-/{}/-", hex(&[index as u8; 32]), cms.join("+"))
                };
                rows.push(format!(
                    "{index},{block},{},{leaves},{txs}",
                    hex(&tree.root().to_bytes())
                ));
            }
        }
        format!("OK {} {}", chain.len(), rows.join(";"))
    }

    /// A node that answers `STEPS` from whatever chain is currently in the shared cell.
    fn fake_node(chain: Arc<Mutex<FakeChain>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let chain = chain.clone();
                std::thread::spawn(move || {
                    let mut stream = stream.unwrap();
                    let mut line = String::new();
                    BufReader::new(stream.try_clone().unwrap())
                        .read_line(&mut line)
                        .unwrap();
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let (from, max) = (parts[1].parse().unwrap(), parts[2].parse().unwrap());
                    let reply = steps_line(&chain.lock().unwrap(), from, max);
                    writeln!(stream, "{reply}").unwrap();
                });
            }
        });
        addr
    }

    fn named(blocks: &[(&str, &[u64])]) -> FakeChain {
        blocks
            .iter()
            .map(|(b, n)| ((*b).to_owned(), n.to_vec()))
            .collect()
    }

    #[test]
    fn steps_must_arrive_in_order_and_match_the_nodes_root() {
        let chain = named(&[("g", &[]), ("a", &[1, 2])]);
        let line = steps_line(&chain, 0, 10);
        let body = line.strip_prefix("OK 2 ").unwrap();
        // Parse through the real parser by serving it.
        let cell = Arc::new(Mutex::new(chain));
        let service = fake_node(cell);
        let (_, steps) = rpc::steps(&service, 0, 10).unwrap();
        assert_eq!(steps.len(), 2, "{body}");

        let mut s = scanner();
        assert_eq!(
            s.apply(&steps[1]),
            Err(ScanError::OutOfOrder {
                expected: 0,
                got: 1
            })
        );
        s.apply(&steps[0]).unwrap();
        let mut forged = steps[1].clone();
        forged.root = [7; 32];
        assert_eq!(s.apply(&forged), Err(ScanError::RootMismatch { step: 1 }));
    }

    #[test]
    fn a_reorg_makes_the_wallet_rescan_and_land_on_the_new_chain() {
        let long = named(&[("g", &[]), ("a", &[1]), ("b", &[2, 3]), ("c", &[4])]);
        let cell = Arc::new(Mutex::new(long.clone()));
        let service = fake_node(cell.clone());

        let scanner = Mutex::new(scanner());
        let report = sync(&scanner, &service).unwrap();
        assert_eq!(report.applied, 4);
        assert!(!report.rescanned);
        let old_root = scanner.lock().unwrap().root();

        // Nothing new: nothing applied.
        assert_eq!(sync(&scanner, &service).unwrap(), SyncReport::default());

        // The node follows a different branch from step 2 on.
        let reorged = named(&[
            ("g", &[]),
            ("a", &[1]),
            ("b2", &[9]),
            ("c2", &[]),
            ("d2", &[5]),
        ]);
        *cell.lock().unwrap() = reorged.clone();
        let report = sync(&scanner, &service).unwrap();
        assert!(report.rescanned, "{report:?}");
        let new_root = scanner.lock().unwrap().root();
        assert_ne!(new_root, old_root);
        let expected = {
            let mut t = CommitmentTree::empty();
            for n in [1, 9, 5] {
                let cmu = ExtractedNoteCommitment::from_bytes(&commitment(n)).unwrap();
                t.append(Node::from_cmu(&cmu)).unwrap();
            }
            t.root().to_bytes()
        };
        assert_eq!(new_root, expected);
        assert_eq!(scanner.lock().unwrap().next_step(), 5);

        // A shorter chain than the wallet has seen is also a reorg.
        *cell.lock().unwrap() = named(&[("g", &[]), ("a", &[1])]);
        let report = sync(&scanner, &service).unwrap();
        assert!(report.rescanned);
        assert_eq!(scanner.lock().unwrap().next_step(), 2);
    }
}
