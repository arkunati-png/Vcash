//! A background check that the configured `volt-node` is reachable.
//!
//! This is a plain TCP connect to the node's listen address. It says the port is open, nothing
//! more: the wallet has no sync protocol to speak yet (`volt-node` does not serve one).

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Checking,
    Reachable,
    Unreachable(String),
}

pub struct NodeMonitor {
    status: Arc<Mutex<NodeStatus>>,
    addr: Arc<Mutex<String>>,
    stop: Arc<AtomicBool>,
}

impl NodeMonitor {
    pub fn start(addr: String, ctx: eframe::egui::Context) -> Self {
        let status = Arc::new(Mutex::new(NodeStatus::Checking));
        let addr = Arc::new(Mutex::new(addr));
        let stop = Arc::new(AtomicBool::new(false));

        let (t_status, t_addr, t_stop) = (status.clone(), addr.clone(), stop.clone());
        std::thread::spawn(move || {
            while !t_stop.load(Ordering::Relaxed) {
                let target = t_addr.lock().expect("monitor lock").clone();
                let next = probe(&target);
                let changed = {
                    let mut current = t_status.lock().expect("monitor lock");
                    let changed = *current != next;
                    *current = next;
                    changed
                };
                if changed {
                    ctx.request_repaint();
                }
                // Sleep in short steps so shutdown and address changes are noticed quickly.
                for _ in 0..30 {
                    if t_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });

        Self { status, addr, stop }
    }

    pub fn status(&self) -> NodeStatus {
        self.status.lock().expect("monitor lock").clone()
    }

    pub fn set_addr(&self, addr: String) {
        *self.addr.lock().expect("monitor lock") = addr;
        *self.status.lock().expect("monitor lock") = NodeStatus::Checking;
    }
}

impl Drop for NodeMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn probe(target: &str) -> NodeStatus {
    let addrs = match target.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return NodeStatus::Unreachable("invalid address".into()),
    };
    let mut last = "no address".to_owned();
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) {
            Ok(_) => return NodeStatus::Reachable,
            Err(e) => last = e.kind().to_string(),
        }
    }
    NodeStatus::Unreachable(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_sees_open_and_closed_ports() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().to_string();
        assert_eq!(probe(&open), NodeStatus::Reachable);
        drop(listener);
        assert!(matches!(probe(&open), NodeStatus::Unreachable(_)));
        assert!(matches!(
            probe("not an address"),
            NodeStatus::Unreachable(_)
        ));
    }
}
