//! Runs `volt-node` as a child process of the wallet, optionally mining to this wallet.
//!
//! The wallet never links the node's code: it starts the `volt-node` executable, passes it the
//! wallet's own transparent address as the mining payout, and stops it when the wallet closes.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::settings;

const EXE_NAME: &str = if cfg!(windows) {
    "volt-node.exe"
} else {
    "volt-node"
};

/// Where the node keeps its blocks.
pub fn node_data_dir() -> PathBuf {
    settings::data_dir().join("node")
}

/// Finds `volt-node`: the configured path if it exists, otherwise next to the wallet, otherwise
/// the repository's `target/release` when the wallet is run from a source checkout.
pub fn find_node_exe(configured: &str) -> Option<PathBuf> {
    let configured = configured.trim();
    if !configured.is_empty() {
        let path = PathBuf::from(configured);
        return path.is_file().then_some(path);
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    [
        dir.join(EXE_NAME),
        dir.join("../../../target/release").join(EXE_NAME),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

/// The command-line for `volt-node run`.
pub fn node_args(
    data_dir: &Path,
    listen: &str,
    rpc: &str,
    mine: bool,
    payout: &str,
    extra: &str,
) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--data-dir".to_owned(),
        data_dir.display().to_string(),
        "--listen".to_owned(),
        listen.to_owned(),
        "--rpc".to_owned(),
        rpc.to_owned(),
        // The node checks real proofs and signatures. The proof-less devnet is for tests only.
        "--real-txs".to_owned(),
    ];
    if mine {
        args.push("--mine".to_owned());
        args.push("--payout".to_owned());
        args.push(payout.to_owned());
    }
    args.extend(extra.split_whitespace().map(str::to_owned));
    args
}

/// Two free loopback ports in a row, for a second node's peer port and wallet-service port.
pub fn free_port_pair() -> Option<(u16, u16)> {
    use std::net::TcpListener;
    (8447u16..8700).step_by(2).find_map(|p| {
        let a = TcpListener::bind(("127.0.0.1", p)).ok()?;
        let b = TcpListener::bind(("127.0.0.1", p + 1)).ok()?;
        drop((a, b));
        Some((p, p + 1))
    })
}

/// The last few lines of the node's log, without colour codes.
fn log_tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = text
        .lines()
        .map(|line| {
            let mut clean = String::new();
            let mut chars = line.chars();
            while let Some(c) = chars.next() {
                if c == '\u{1b}' {
                    for c in chars.by_ref() {
                        if c == 'm' {
                            break;
                        }
                    }
                } else {
                    clean.push(c);
                }
            }
            clean.trim().to_owned()
        })
        .filter(|line| !line.is_empty())
        .collect();
    let keep = lines.len().saturating_sub(3);
    lines.drain(..keep);
    lines.join(" | ")
}

/// A readable reason the node stopped on its own.
fn describe_exit(code: Option<i32>, log: Option<&Path>) -> String {
    let tail = log.map(log_tail).unwrap_or_default();
    let code = code.map_or("unknown".to_owned(), |c| c.to_string());
    if tail.contains("Only one usage of each socket address") || tail.contains("already in use") {
        return "The node could not start because its port is already in use. Another node is probably running on this address; Core can use that one, or stop it first.".to_owned();
    }
    format!("The node stopped by itself (exit code {code}). Last log lines: {tail}")
}

#[derive(Default)]
pub struct LocalNode {
    child: Option<Child>,
    mining: bool,
    log: Option<PathBuf>,
    exited: Option<String>,
}

impl LocalNode {
    /// Whether the child process is still alive. Reaps it if it has exited.
    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut().map(Child::try_wait) {
            Some(Ok(None)) => true,
            Some(result) => {
                let code = result.ok().flatten().and_then(|status| status.code());
                self.exited = Some(describe_exit(code, self.log.as_deref()));
                self.child = None;
                self.mining = false;
                false
            }
            None => false,
        }
    }

    /// Why the node stopped on its own, once, if it did.
    pub fn take_exit(&mut self) -> Option<String> {
        self.exited.take()
    }

    pub fn is_mining(&mut self) -> bool {
        self.is_running() && self.mining
    }

    // Each argument is one thing the node needs; a struct would only move them elsewhere.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        exe: &Path,
        data_dir: &Path,
        listen: &str,
        rpc: &str,
        mine: bool,
        payout: &str,
        extra: &str,
    ) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }
        std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
        let log_path = data_dir.join("node.log");
        // Start each run with a clean log, so a failure message is about this run.
        let log = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)
            .map_err(|e| e.to_string())?;
        let log_err = log.try_clone().map_err(|e| e.to_string())?;

        let mut command = Command::new(exe);
        command
            .args(node_args(data_dir, listen, rpc, mine, payout, extra))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW: the node must not pop up a console.
            command.creation_flags(0x0800_0000);
        }
        let child = command
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", exe.display()))?;
        self.child = Some(child);
        self.log = Some(log_path);
        self.exited = None;
        self.mining = mine;
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.mining = false;
    }
}

impl Drop for LocalNode {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_only_carry_a_payout_when_mining() {
        let dir = Path::new("data");
        let idle = node_args(dir, "127.0.0.1:8445", "127.0.0.1:8446", false, "VoX", "");
        assert_eq!(
            idle,
            [
                "run",
                "--data-dir",
                "data",
                "--listen",
                "127.0.0.1:8445",
                "--rpc",
                "127.0.0.1:8446",
                "--real-txs"
            ]
        );
        let mining = node_args(
            dir,
            "127.0.0.1:8445",
            "127.0.0.1:8446",
            true,
            "VoX",
            "--economics faucet",
        );
        assert_eq!(
            &mining[8..],
            ["--mine", "--payout", "VoX", "--economics", "faucet"]
        );
    }

    #[test]
    fn a_port_clash_is_explained() {
        let dir = std::env::temp_dir().join("voltcore-log-test");
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("node.log");
        std::fs::write(
            &log,
            "\u{1b}[2m12:00\u{1b}[0m Error: cannot start\nCaused by:\n    Only one usage of each socket address (os error 10048)\n",
        )
        .unwrap();
        let message = describe_exit(Some(1), Some(&log));
        assert!(message.contains("port is already in use"), "{message}");
        std::fs::write(&log, "\u{1b}[2mboom\u{1b}[0m\n").unwrap();
        let message = describe_exit(Some(3), Some(&log));
        assert!(
            message.contains("exit code 3") && message.contains("boom"),
            "{message}"
        );
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn a_missing_configured_binary_is_not_silently_replaced() {
        assert_eq!(find_node_exe("Z:/definitely/not/here.exe"), None);
    }

    #[test]
    fn a_process_that_exits_is_reaped() {
        let mut node = LocalNode::default();
        assert!(!node.is_running());
        let exe = if cfg!(windows) {
            PathBuf::from("C:/Windows/System32/whoami.exe")
        } else {
            PathBuf::from("/bin/true")
        };
        if exe.is_file() {
            node.child = Some(Command::new(&exe).stdout(Stdio::null()).spawn().unwrap());
            for _ in 0..50 {
                if !node.is_running() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            assert!(!node.is_running());
        }
    }
}
