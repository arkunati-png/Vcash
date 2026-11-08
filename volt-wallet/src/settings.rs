//! Where the wallet keeps its files and its non-secret settings.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const DEFAULT_NODE_ADDR: &str = "127.0.0.1:8445";
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8446";

/// The wallet folder: `%APPDATA%\Voltcash` on Windows. `VOLT_WALLET_DIR` overrides it.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("VOLT_WALLET_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Voltcash")
}

pub fn vault_path() -> PathBuf {
    data_dir().join("wallet.vault")
}

fn settings_path() -> PathBuf {
    data_dir().join("settings.json")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Address of the `volt-node` this wallet talks to.
    pub node_addr: String,
    /// Address of the devnet wallet service (`volt-node --rpc`) used for balance and sending.
    pub rpc_addr: String,
    /// Path of the `volt-node` program to start from the wallet. Empty means auto-detect.
    pub node_exe: String,
    /// Where the local node keeps its chain. Empty means the wallet folder's `node` directory.
    pub node_data_dir: String,
    /// Extra options passed to the local node, split on spaces (for example `--economics faucet`).
    pub node_args: String,
    /// Other nodes this one peers with, as `host:port` separated by spaces. Set when the app
    /// joins a node that is already running.
    pub peer_seeds: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            node_addr: DEFAULT_NODE_ADDR.to_owned(),
            rpc_addr: DEFAULT_RPC_ADDR.to_owned(),
            node_exe: String::new(),
            node_data_dir: String::new(),
            node_args: String::new(),
            peer_seeds: String::new(),
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        std::fs::read(settings_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        std::fs::create_dir_all(data_dir()).map_err(|e| e.to_string())?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(settings_path(), json).map_err(|e| e.to_string())
    }
}
