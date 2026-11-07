//! The append-only block log.
//!
//! File layout:
//!
//! ```text
//! "VOLTLOG1" | genesis hash (32 bytes) | record*
//! record = payload length (u32 LE) | Blake2b-64 of payload | payload
//! ```

use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use thiserror::Error;
use volt_core::VoltHash;

const MAGIC: &[u8; 8] = b"VOLTLOG1";
const HEADER_LEN: u64 = 8 + 32;
const RECORD_HEADER_LEN: u64 = 4 + 8;

/// The largest record accepted, in bytes. A block is far smaller; this bounds what a corrupt
/// length field can make the reader allocate.
const MAX_RECORD_BYTES: u32 = 64 * 1024 * 1024;

/// Errors from the block log.
#[derive(Debug, Error)]
pub enum LogError {
    /// The file system failed.
    #[error("block log I/O error on {path}: {source}")]
    Io {
        /// The log file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The file is not a Voltcash block log.
    #[error("{0} is not a Voltcash block log")]
    BadMagic(PathBuf),

    /// The log belongs to a different network.
    #[error("the block log was written for genesis {found}, this node uses genesis {expected}")]
    WrongGenesis {
        /// The genesis hash this node expects.
        expected: VoltHash,
        /// The genesis hash recorded in the log.
        found: VoltHash,
    },

    /// A record in the middle of the log is damaged.
    ///
    /// This is not a torn write, since valid data follows it. The log is not repaired
    /// automatically, because that would silently discard blocks.
    #[error("the block log is corrupt at byte {offset}: {reason}")]
    Corrupt {
        /// Where the damaged record starts.
        offset: u64,
        /// What is wrong with it.
        reason: &'static str,
    },
}

/// When appended records are forced to disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncPolicy {
    /// `fsync` after every record: a block is durable once it is accepted. Slower.
    Always,
    /// Leave flushing to the operating system. A crash can lose recent blocks, which peers can
    /// supply again, but never corrupts earlier ones.
    Never,
}

/// What opening a log found and repaired.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenReport {
    /// Valid records in the log.
    pub records: u64,
    /// Bytes of a torn final record that were truncated.
    pub truncated_bytes: u64,
}

/// An open, append-only block log.
#[derive(Debug)]
pub struct BlockLog {
    path: PathBuf,
    file: File,
    sync: SyncPolicy,
    /// The end of the last valid record.
    end: u64,
}

/// Copies the first `N` bytes of `bytes` into an array. Callers pass slices of fixed-size headers
/// that are known to be long enough.
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

fn checksum(payload: &[u8]) -> [u8; 8] {
    let hash = blake2b_simd::Params::new()
        .hash_length(8)
        .personal(b"VoltBlockLog____")
        .hash(payload);
    let mut out = [0; 8];
    out.copy_from_slice(hash.as_bytes());
    out
}

impl BlockLog {
    fn io(path: &Path) -> impl Fn(io::Error) -> LogError {
        let path = path.to_path_buf();
        move |source| LogError::Io {
            path: path.clone(),
            source,
        }
    }

    /// Opens the log at `path`, creating it for `genesis` if it does not exist.
    ///
    /// Every record is checksummed. A torn final record is truncated. A damaged record with
    /// valid data after it is reported as [`LogError::Corrupt`].
    pub fn open(
        path: impl AsRef<Path>,
        genesis: &VoltHash,
        sync: SyncPolicy,
    ) -> Result<(Self, OpenReport), LogError> {
        let path = path.as_ref().to_path_buf();
        let io = Self::io(&path);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(&io)?;
        let length = file.metadata().map_err(&io)?.len();

        if length == 0 {
            let mut header = Vec::with_capacity(HEADER_LEN as usize);
            header.extend_from_slice(MAGIC);
            header.extend_from_slice(&genesis.0);
            file.write_all(&header).map_err(&io)?;
            file.sync_all().map_err(&io)?;
            return Ok((
                Self {
                    path,
                    file,
                    sync,
                    end: HEADER_LEN,
                },
                OpenReport::default(),
            ));
        }

        if length < HEADER_LEN {
            return Err(LogError::BadMagic(path));
        }
        let mut header = [0u8; HEADER_LEN as usize];
        file.seek(SeekFrom::Start(0)).map_err(&io)?;
        file.read_exact(&mut header).map_err(&io)?;
        if &header[..8] != MAGIC {
            return Err(LogError::BadMagic(path));
        }
        let found = VoltHash(array(&header[8..]));
        if found != *genesis {
            return Err(LogError::WrongGenesis {
                expected: *genesis,
                found,
            });
        }

        let (end, records) = Self::scan(&path, &mut file, length)?;
        let truncated_bytes = length - end;
        if truncated_bytes > 0 {
            file.set_len(end).map_err(&io)?;
            file.sync_all().map_err(&io)?;
        }

        Ok((
            Self {
                path,
                file,
                sync,
                end,
            },
            OpenReport {
                records,
                truncated_bytes,
            },
        ))
    }

    /// Walks every record from the start, returning the end of the last valid one.
    fn scan(path: &Path, file: &mut File, length: u64) -> Result<(u64, u64), LogError> {
        let io = Self::io(path);
        file.seek(SeekFrom::Start(HEADER_LEN)).map_err(&io)?;
        let mut reader = BufReader::new(&mut *file);

        let mut offset = HEADER_LEN;
        let mut records = 0;
        while offset < length {
            let remaining = length - offset;
            if remaining < RECORD_HEADER_LEN {
                break; // a torn record header
            }

            let mut header = [0u8; RECORD_HEADER_LEN as usize];
            reader.read_exact(&mut header).map_err(&io)?;
            let payload_len = u32::from_le_bytes(array(&header[..4]));
            let expected: [u8; 8] = array(&header[4..]);

            if payload_len > MAX_RECORD_BYTES {
                // A wild length is garbage whether or not anything follows it.
                return Err(LogError::Corrupt {
                    offset,
                    reason: "record length is implausibly large",
                });
            }
            let record_end = offset + RECORD_HEADER_LEN + u64::from(payload_len);
            if record_end > length {
                break; // the payload was cut short: a torn write
            }

            let mut payload = vec![0u8; payload_len as usize];
            reader.read_exact(&mut payload).map_err(&io)?;
            if checksum(&payload) != expected {
                if record_end == length {
                    break; // the very last record is damaged: treat it as torn
                }
                return Err(LogError::Corrupt {
                    offset,
                    reason: "checksum mismatch with valid data after it",
                });
            }

            offset = record_end;
            records += 1;
        }
        Ok((offset, records))
    }

    /// Appends one record and, under [`SyncPolicy::Always`], forces it to disk.
    pub fn append(&mut self, payload: &[u8]) -> Result<(), LogError> {
        let io = Self::io(&self.path);
        let len = u32::try_from(payload.len())
            .ok()
            .filter(|l| *l <= MAX_RECORD_BYTES)
            .ok_or(LogError::Corrupt {
                offset: self.end,
                reason: "record is too large to store",
            })?;

        let mut record = Vec::with_capacity(RECORD_HEADER_LEN as usize + payload.len());
        record.extend_from_slice(&len.to_le_bytes());
        record.extend_from_slice(&checksum(payload));
        record.extend_from_slice(payload);

        // One write, so a crash leaves at most one torn record at the end.
        self.file.seek(SeekFrom::Start(self.end)).map_err(&io)?;
        self.file.write_all(&record).map_err(&io)?;
        if self.sync == SyncPolicy::Always {
            self.file.sync_data().map_err(&io)?;
        }
        self.end += record.len() as u64; // lossless: a Vec length fits in u64
        Ok(())
    }

    /// Returns an iterator over every record's payload, from the start of the log.
    ///
    /// Records were validated when the log was opened; the iterator yields I/O errors only if
    /// the file changes underneath it.
    pub fn records(&self) -> Result<Records, LogError> {
        let io = Self::io(&self.path);
        let mut file = File::open(&self.path).map_err(&io)?;
        file.seek(SeekFrom::Start(HEADER_LEN)).map_err(&io)?;
        Ok(Records {
            path: self.path.clone(),
            reader: BufReader::new(file),
            remaining: self.end - HEADER_LEN,
        })
    }

    /// The path of the log file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// An iterator over the payloads of a [`BlockLog`].
#[derive(Debug)]
pub struct Records {
    path: PathBuf,
    reader: BufReader<File>,
    remaining: u64,
}

impl Iterator for Records {
    type Item = Result<Vec<u8>, LogError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let io = BlockLog::io(&self.path);
        let result = (|| {
            let mut header = [0u8; RECORD_HEADER_LEN as usize];
            self.reader.read_exact(&mut header).map_err(&io)?;
            let len = u32::from_le_bytes(array(&header[..4]));
            let mut payload = vec![0u8; len as usize];
            self.reader.read_exact(&mut payload).map_err(&io)?;
            self.remaining = self
                .remaining
                .saturating_sub(RECORD_HEADER_LEN + u64::from(len));
            Ok(payload)
        })();
        if result.is_err() {
            self.remaining = 0;
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis() -> VoltHash {
        VoltHash([7; 32])
    }

    fn payloads(log: &BlockLog) -> Vec<Vec<u8>> {
        log.records().unwrap().map(Result::unwrap).collect()
    }

    #[test]
    fn appends_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.log");

        let (mut log, report) = BlockLog::open(&path, &genesis(), SyncPolicy::Always).unwrap();
        assert_eq!(report, OpenReport::default());
        log.append(b"first").unwrap();
        log.append(b"").unwrap();
        log.append(&[9; 5_000]).unwrap();
        drop(log);

        let (log, report) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
        assert_eq!(report.records, 3);
        assert_eq!(report.truncated_bytes, 0);
        assert_eq!(
            payloads(&log),
            vec![b"first".to_vec(), vec![], vec![9; 5_000]]
        );
    }

    #[test]
    fn a_torn_final_record_is_truncated_and_earlier_records_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.log");
        let (mut log, _) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
        log.append(b"keep me").unwrap();
        log.append(b"this one gets torn").unwrap();
        drop(log);

        // Cut the file in the middle of the last record's payload.
        let length = std::fs::metadata(&path).unwrap().len();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(length - 5).unwrap();
        drop(file);

        let (mut log, report) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
        assert_eq!(report.records, 1);
        assert_eq!(report.truncated_bytes, RECORD_HEADER_LEN + 18 - 5);
        assert_eq!(payloads(&log), vec![b"keep me".to_vec()]);

        // The log is usable again after repair.
        log.append(b"after repair").unwrap();
        drop(log);
        let (log, report) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
        assert_eq!(report.records, 2);
        assert_eq!(
            payloads(&log),
            vec![b"keep me".to_vec(), b"after repair".to_vec()]
        );
    }

    #[test]
    fn every_possible_tear_point_recovers() {
        // Cut the file at every byte of the final record: each must open cleanly, keeping
        // exactly the records that were completely written.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.log");
        let (mut log, _) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
        log.append(b"alpha").unwrap();
        let before_last = std::fs::metadata(&path).unwrap().len();
        log.append(b"omega-omega").unwrap();
        drop(log);
        let full = std::fs::read(&path).unwrap();

        for cut in before_last..full.len() as u64 {
            std::fs::write(&path, &full[..cut as usize]).unwrap();
            let (log, report) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
            assert_eq!(report.records, 1, "cut at {cut}");
            assert_eq!(payloads(&log), vec![b"alpha".to_vec()], "cut at {cut}");
        }
    }

    #[test]
    fn a_damaged_final_record_is_treated_as_torn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.log");
        let (mut log, _) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
        log.append(b"good").unwrap();
        log.append(b"bad tail").unwrap();
        drop(log);

        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        std::fs::write(&path, bytes).unwrap();

        let (log, report) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
        assert_eq!(report.records, 1);
        assert_eq!(payloads(&log), vec![b"good".to_vec()]);
    }

    #[test]
    fn mid_file_corruption_is_an_error_not_a_silent_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.log");
        let (mut log, _) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
        log.append(b"first record").unwrap();
        log.append(b"second record").unwrap();
        log.append(b"third record").unwrap();
        drop(log);

        // Damage a byte inside the first record's payload.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_LEN as usize + RECORD_HEADER_LEN as usize + 2] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        match BlockLog::open(&path, &genesis(), SyncPolicy::Never) {
            Err(LogError::Corrupt { offset, .. }) => assert_eq!(offset, HEADER_LEN),
            other => panic!("expected corruption to be reported, got {other:?}"),
        }
        // And nothing was truncated: the file is untouched.
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn a_wild_length_field_is_rejected_without_allocating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.log");
        let (mut log, _) = BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();
        log.append(b"ok").unwrap();
        drop(log);

        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]);
        std::fs::write(&path, bytes).unwrap();

        assert!(matches!(
            BlockLog::open(&path, &genesis(), SyncPolicy::Never),
            Err(LogError::Corrupt { .. })
        ));
    }

    #[test]
    fn the_wrong_network_and_foreign_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.log");
        BlockLog::open(&path, &genesis(), SyncPolicy::Never).unwrap();

        let other = VoltHash([8; 32]);
        assert!(matches!(
            BlockLog::open(&path, &other, SyncPolicy::Never),
            Err(LogError::WrongGenesis { .. })
        ));

        let foreign = dir.path().join("notes.txt");
        std::fs::write(
            &foreign,
            b"this is definitely not a block log at all, sorry",
        )
        .unwrap();
        assert!(matches!(
            BlockLog::open(&foreign, &genesis(), SyncPolicy::Never),
            Err(LogError::BadMagic(_))
        ));
    }
}
