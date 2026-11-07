//! Where the wallet keeps its files and its non-secret settings.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const DEFAULT_NODE_ADDR: &str = "127.0.0.1:8445";

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
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            node_addr: DEFAULT_NODE_ADDR.to_owned(),
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
