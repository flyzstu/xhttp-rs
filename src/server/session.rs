//! Session state and downlink transport machinery for the HTTP server.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::body::Bytes;
use bytes::BytesMut;
use dashmap::mapref::entry::Entry;
use futures_util::{Stream, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Notify, mpsc, oneshot},
};

use super::{ServerState, backend};

pub(crate) struct Session {
    pub(crate) sender: mpsc::Sender<Packet>,
    pub(crate) downlink: Arc<Mutex<DownlinkState>>,
    pub(crate) connected: AtomicBool,
}

/// Downstream delivery state for one session.
///
/// Every byte the backend produced between `acked` (contiguous position the
/// client confirmed) and `total` (position produced so far) stays buffered in
/// `chunks` until acknowledged. Delivery is by range: a GET attachment or a
/// POST piggyback both snapshot "everything from X" and label the response
/// with `x-dl-from: X`, so the client can deduplicate and reassemble regardless
/// of which path delivered a given byte, and no byte is ever lost unless the
/// client confirmed it first. This is what makes GET reattachment safe.
pub(crate) struct DownlinkState {
    /// `(start_offset, data)` with strictly increasing starts. The head may
    /// start below `acked` (partially acknowledged chunk); consumers trim it.
    pub(crate) chunks: VecDeque<(u64, Bytes)>,
    /// Next offset the backend read loop will produce.
    pub(crate) total: u64,
    /// Contiguous downstream position confirmed received by the client.
    pub(crate) acked: u64,
    pub(crate) max_pending_bytes: usize,
    /// Current GET consumer: `(generation, channel into the response body)`.
    pub(crate) active: Option<(u64, mpsc::Sender<Result<Bytes, std::io::Error>>)>,
    /// Offsets at or above this value are streamed to the live GET directly;
    /// everything below was already included in its attach snapshot.
    pub(crate) deliver_from: u64,
    /// Dropping this sender aborts the previous GET response body.
    pub(crate) kill: Option<oneshot::Sender<()>>,
    /// Set once the backend stream ended; `chunks` may still hold data.
    pub(crate) backend_closed: bool,
    /// Bumped on every GET attachment; the producer snapshots it so it can
    /// detect consumer changes without holding the lock across awaits.
    pub(crate) generation: u64,
    /// Wakes the producer when acknowledgements free buffer space.
    pub(crate) ack_notify: Arc<Notify>,
}

impl DownlinkState {
    pub(crate) fn new(max_pending_bytes: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            total: 0,
            acked: 0,
            max_pending_bytes,
            active: None,
            deliver_from: 0,
            kill: None,
            backend_closed: false,
            generation: 0,
            ack_notify: Arc::new(Notify::new()),
        }
    }

    /// Record a client acknowledgement. Claims beyond `total` are clamped and
    /// the value never regresses; fully acknowledged chunks are dropped.
    pub(crate) fn acknowledge(&mut self, claim: u64) {
        self.acked = self.acked.max(claim.min(self.total));
        while let Some((offset, chunk)) = self.chunks.front() {
            if *offset + chunk.len() as u64 <= self.acked {
                self.chunks.pop_front();
            } else {
                break;
            }
        }
        self.ack_notify.notify_waiters();
    }

    /// Snapshot the buffered bytes for delivery starting exactly at `from`.
    /// The concatenation of the returned pieces is exactly `[from, ..)`; a
    /// head chunk straddling `from` is trimmed so the first piece starts at
    /// `from` and the client can place the range without re-alignment.
    pub(crate) fn snapshot_from(&self, from: u64) -> Vec<Bytes> {
        let mut pieces = Vec::new();
        for (offset, chunk) in &self.chunks {
            let end = *offset + chunk.len() as u64;
            if end <= from {
                continue;
            }
            if *offset < from {
                let skip = (from - *offset) as usize;
                if skip < chunk.len() {
                    pieces.push(chunk.slice(skip..));
                }
            } else {
                pieces.push(chunk.clone());
            }
        }
        pieces
    }
}

pub(crate) struct Packet {
    pub(crate) sequence: u64,
    pub(crate) payload: Bytes,
}

/// End a response body stream as soon as `kill` resolves. Used to terminate
/// a superseded GET consumer without tearing down the session.
pub(crate) fn attach_kill_stream<S>(
    stream: S,
    kill: oneshot::Receiver<()>,
) -> impl Stream<Item = S::Item>
where
    S: Stream,
{
    stream.take_until(kill)
}

pub(crate) fn get_session(state: &Arc<ServerState>, id: &str) -> Option<Arc<Session>> {
    if id.len() > state.config.transport.max_session_id_length {
        return None;
    }
    if let Some(v) = state.sessions.get(id) {
        return Some(v.clone());
    }
    if state
        .active_sessions
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            (value < state.config.transport.max_sessions).then_some(value + 1)
        })
        .is_err()
    {
        return None;
    }
    let (sender, mut receiver) =
        mpsc::channel::<Packet>(state.config.transport.max_buffered_packets);
    let downlink = Arc::new(Mutex::new(DownlinkState::new(
        state.config.transport.h1_max_pending_bytes,
    )));
    let session = Arc::new(Session {
        sender,
        downlink: downlink.clone(),
        connected: AtomicBool::new(false),
    });
    match state.sessions.entry(id.to_owned()) {
        Entry::Occupied(v) => {
            state.active_sessions.fetch_sub(1, Ordering::AcqRel);
            return Some(v.get().clone());
        }
        Entry::Vacant(v) => {
            v.insert(session.clone());
        }
    }

    let front = backend(state);
    let (mut backend_read, mut backend_write) = tokio::io::split(front);

    let state_upload = Arc::downgrade(state);
    let id_upload = id.to_owned();
    let max_buffered = state.config.transport.max_buffered_packets;

    tokio::spawn(async move {
        let mut pending = BTreeMap::new();
        let mut next = 0;
        while let Some(packet) = receiver.recv().await {
            if packet.sequence < next {
                continue;
            }
            if pending.len() >= max_buffered && !pending.contains_key(&packet.sequence) {
                if let Some(state) = state_upload.upgrade() {
                    remove_session(&state, &id_upload);
                }
                return;
            }
            pending.insert(packet.sequence, packet.payload);
            while let Some(payload) = pending.remove(&next) {
                if backend_write.write_all(&payload).await.is_err() {
                    if let Some(state) = state_upload.upgrade() {
                        remove_session(&state, &id_upload);
                    }
                    return;
                }

                next += 1;
            }
        }
        let _ = backend_write.shutdown().await;
    });

    let downlink_for_read = downlink;
    let state_downlink = Arc::downgrade(state);
    let id_downlink = id.to_owned();
    tokio::spawn(async move {
        let mut buffer = BytesMut::with_capacity(32 * 1024);
        'read: loop {
            // Backpressure: pause reading while the unacknowledged window is
            // full. The lock is never held across the wait.
            while {
                let dl = downlink_for_read.lock().await;
                dl.total - dl.acked > dl.max_pending_bytes as u64
            } {
                let notify = downlink_for_read.lock().await.ack_notify.clone();
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                }
            }
            buffer.clear();
            match backend_read.read_buf(&mut buffer).await {
                Ok(0) => break 'read,
                Ok(_) => {
                    let chunk = buffer.split().freeze();
                    // Append to the range store, then hand the chunk to the
                    // live GET if it falls into that consumer's range. The
                    // send happens OUTSIDE the lock so a stalled consumer
                    // cannot block attaches or piggyback handling; on
                    // consumer death the chunk stays buffered and is
                    // re-delivered by the next attach.
                    let target = {
                        let mut dl = downlink_for_read.lock().await;
                        let offset = dl.total;
                        dl.total += chunk.len() as u64;
                        dl.chunks.push_back((offset, chunk.clone()));
                        dl.active
                            .as_ref()
                            .filter(|_| offset >= dl.deliver_from)
                            .map(|(generation, tx)| (*generation, tx.clone()))
                    };
                    if let Some((generation, tx)) = target {
                        let send_failed = tx.send(Ok(chunk)).await.is_err();
                        if send_failed {
                            let mut dl = downlink_for_read.lock().await;
                            if dl.active.as_ref().is_some_and(|(g, _)| *g == generation) {
                                dl.active = None;
                                dl.kill = None;
                            }
                        }
                    }
                }
                Err(e) => {
                    let target = {
                        let mut dl = downlink_for_read.lock().await;
                        let active = dl.active.take();
                        let kill = dl.kill.take();
                        active.map(|(_, tx)| (tx, kill))
                    };
                    if let Some((tx, _)) = target {
                        let _ = tx.send(Err(e)).await;
                    }
                    break 'read;
                }
            }
        }
        {
            let mut dl = downlink_for_read.lock().await;
            dl.backend_closed = true;
            dl.active = None;
            dl.kill = None;
        }
        if let Some(state) = state_downlink.upgrade() {
            let timeout = state.config.transport.session_timeout();
            tokio::time::sleep(timeout).await;
            remove_session(&state, &id_downlink);
        }
    });

    let weak = Arc::downgrade(state);
    let id = id.to_owned();
    let timeout = state.config.transport.session_timeout();
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        if let Some(state) = weak.upgrade()
            && state
                .sessions
                .get(&id)
                .is_some_and(|v| !v.connected.load(Ordering::Acquire))
        {
            remove_session(&state, &id);
        }
    });
    Some(session)
}

pub(crate) fn remove_session(state: &ServerState, id: &str) {
    if state.sessions.remove(id).is_some() {
        state.active_sessions.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downlink_acknowledge_clamps_and_trims() {
        let mut dl = DownlinkState::new(2 * 1024 * 1024);
        dl.chunks.push_back((0, Bytes::from(vec![0u8; 100])));
        dl.chunks.push_back((100, Bytes::from(vec![1u8; 100])));
        dl.total = 200;

        // Acknowledging past the produced range is clamped.
        dl.acknowledge(500);
        assert_eq!(dl.acked, 200);
        // Both chunks are fully covered and trimmed.
        assert!(dl.chunks.is_empty());

        dl.chunks.push_back((200, Bytes::from(vec![2u8; 10])));
        dl.total = 210;
        // Acknowledgements never regress.
        dl.acknowledge(5);
        assert_eq!(dl.acked, 200);
        assert_eq!(dl.chunks.len(), 1);
    }
}
