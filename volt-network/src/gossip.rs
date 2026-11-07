//! An in-process gossip hub for simulated nodes.

use std::sync::Arc;

use tokio::sync::broadcast::{self, error::RecvError};
use tracing::warn;

use crate::message::VoltMessage;

/// A message on the wire: the sender's id and the encoded bytes.
type Frame = (u32, Arc<Vec<u8>>);

/// A broadcast channel that simulated nodes join as [`GossipPeer`]s.
///
/// Messages travel as encoded bytes, so every receiver runs the same bounded decoder a real
/// network connection would.
#[derive(Clone, Debug)]
pub struct GossipHub {
    sender: broadcast::Sender<Frame>,
}

impl GossipHub {
    /// Creates a hub that buffers up to `capacity` messages per receiver.
    pub fn new(capacity: usize) -> Self {
        Self {
            sender: broadcast::channel(capacity).0,
        }
    }

    /// Joins the hub as peer `id`.
    pub fn join(&self, id: u32) -> GossipPeer {
        GossipPeer {
            id,
            sender: self.sender.clone(),
            receiver: self.sender.subscribe(),
        }
    }
}

/// One node's connection to the hub.
#[derive(Debug)]
pub struct GossipPeer {
    id: u32,
    sender: broadcast::Sender<Frame>,
    receiver: broadcast::Receiver<Frame>,
}

impl GossipPeer {
    /// This peer's id.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Sends `message` to every other peer. Returns how many peers were listening.
    pub fn broadcast(&self, message: &VoltMessage) -> usize {
        // `send` fails only when nobody is subscribed, which is not an error for gossip.
        self.sender
            .send((self.id, Arc::new(message.encode())))
            .map_or(0, |receivers| receivers.saturating_sub(1))
    }

    /// Waits for the next valid message from another peer.
    ///
    /// Messages that do not decode are dropped with a warning. Returns `None` once every other
    /// handle to the hub is gone.
    pub async fn recv(&mut self) -> Option<(u32, VoltMessage)> {
        loop {
            match self.receiver.recv().await {
                Ok((from, _)) if from == self.id => continue,
                Ok((from, bytes)) => match VoltMessage::decode(&bytes) {
                    Ok(message) => return Some((from, message)),
                    Err(error) => warn!(from, %error, "dropping malformed gossip message"),
                },
                Err(RecvError::Lagged(missed)) => {
                    warn!(
                        peer = self.id,
                        missed, "gossip receiver lagged; messages were dropped"
                    );
                }
                Err(RecvError::Closed) => return None,
            }
        }
    }

    /// Returns the next buffered valid message without waiting, or `None` if there is none.
    pub fn try_recv(&mut self) -> Option<(u32, VoltMessage)> {
        loop {
            match self.receiver.try_recv() {
                Ok((from, _)) if from == self.id => continue,
                Ok((from, bytes)) => match VoltMessage::decode(&bytes) {
                    Ok(message) => return Some((from, message)),
                    Err(error) => warn!(from, %error, "dropping malformed gossip message"),
                },
                Err(broadcast::error::TryRecvError::Lagged(missed)) => {
                    warn!(
                        peer = self.id,
                        missed, "gossip receiver lagged; messages were dropped"
                    );
                }
                Err(_) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peers_hear_everyone_but_themselves() {
        let hub = GossipHub::new(16);
        let mut a = hub.join(1);
        let mut b = hub.join(2);
        let mut c = hub.join(3);

        assert_eq!(a.broadcast(&VoltMessage::NewTx(vec![7])), 2);

        assert_eq!(b.recv().await, Some((1, VoltMessage::NewTx(vec![7]))));
        assert_eq!(c.recv().await, Some((1, VoltMessage::NewTx(vec![7]))));
        assert_eq!(a.try_recv(), None, "a does not hear its own message");
    }

    #[tokio::test]
    async fn malformed_frames_are_dropped() {
        let hub = GossipHub::new(16);
        let a = hub.join(1);
        let mut b = hub.join(2);

        // Inject garbage bytes directly, then a valid message.
        a.sender.send((1, Arc::new(vec![0xff, 0xff]))).unwrap();
        a.broadcast(&VoltMessage::NewTx(vec![1]));

        assert_eq!(b.recv().await, Some((1, VoltMessage::NewTx(vec![1]))));
    }
}
