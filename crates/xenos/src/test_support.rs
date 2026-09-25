//! Test-only support: a scripted server peer for unit tests.
//!
//! The peer frames with syntheke's header codec (`FrameHeader`), not this
//! crate's, so every test that passes checks the client's framing against
//! the contract crate's independent implementation.
#![expect(
    clippy::expect_used,
    reason = "test scaffolding: a failed step must abort the scripted peer loudly"
)]

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use syntheke::{
    Admitted, Auth, ClientHello, DEFAULT_MAX_BODY, FrameHeader, HARD_MAX_BODY, HEADER_LEN, Nonce,
    ServerHello, TenantId, VersionChoice, auth_transcript,
};

use crate::frame::WireMessage;

/// Tenant used throughout the tests.
pub(crate) const TENANT: TenantId = TenantId::from_bytes([0x11; 16]);

/// Server nonce the peer sends.
pub(crate) const SERVER_NONCE: Nonce = Nonce::from_bytes([0x5a; 16]);

/// Short bound for tests that expect a timeout. Every test using it holds
/// the peer still, or trickles bytes that cannot complete within it, so the
/// outcome is a timeout however slow the host is; the bound only sets how
/// long the test takes.
pub(crate) const SHORT: Duration = Duration::from_millis(50);

/// Gap between trickled bytes, well under [`SHORT`], so a client that
/// bounded each system call instead of the whole operation would never
/// time out.
pub(crate) const TRICKLE_GAP: Duration = Duration::from_millis(2);

/// Bound for tests that expect success; generous so a loaded host cannot
/// turn a pass into a timeout.
pub(crate) const LONG: Duration = Duration::from_secs(10);

/// The test tenant's signing key (fixed, synthetic).
pub(crate) fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

/// The server side of a socket pair.
pub(crate) struct Peer {
    stream: UnixStream,
}

impl Peer {
    /// Wraps the server half of a connection.
    pub(crate) const fn new(stream: UnixStream) -> Self {
        Self { stream }
    }

    /// Writes raw bytes.
    pub(crate) fn send_bytes(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("peer write");
    }

    /// Writes a well-formed frame, header by syntheke.
    pub(crate) fn send<M: WireMessage>(&mut self, message: &M) {
        let body = message.encode_body().expect("peer encode");
        let len = u32::try_from(body.len()).expect("body fits u32");
        self.send_bytes(&FrameHeader::new(M::KIND, len).encode());
        self.send_bytes(&body);
    }

    /// Reads one frame, header by syntheke, and decodes it as `M`.
    pub(crate) fn recv<M: WireMessage>(&mut self) -> M {
        let (header, body) = self.recv_raw();
        assert_eq!(header.kind(), M::KIND, "peer expected {:?}", M::KIND);
        M::decode_body(&body, HARD_MAX_BODY).expect("peer decode")
    }

    /// Reads one frame's header (validated by syntheke) and body.
    pub(crate) fn recv_raw(&mut self) -> (FrameHeader, Vec<u8>) {
        self.try_recv_raw().expect("peer read frame")
    }

    /// As [`Self::recv_raw`], but `None` when the client closed first.
    pub(crate) fn try_recv_raw(&mut self) -> Option<(FrameHeader, Vec<u8>)> {
        let mut head = [0_u8; HEADER_LEN];
        self.stream.read_exact(&mut head).ok()?;
        let header = FrameHeader::decode(&head, HARD_MAX_BODY).expect("syntheke accepts header");
        let len = usize::try_from(header.len()).expect("len fits usize");
        let mut body = vec![0_u8; len];
        self.stream.read_exact(&mut body).ok()?;
        Some((header, body))
    }

    /// Writes `bytes`, returning `false` when the client has closed.
    pub(crate) fn try_send_bytes(&mut self, bytes: &[u8]) -> bool {
        self.stream.write_all(bytes).is_ok()
    }

    /// Writes `bytes` one byte at a time, [`TRICKLE_GAP`] apart. Returns
    /// `true` when the client closed before every byte was written.
    ///
    /// WHY the sleep: it paces the peer, not the assertion. A client that
    /// bounds the whole read gives up while bytes are still arriving, which
    /// this reports; a client that bounds each system call never would.
    pub(crate) fn trickle(&mut self, bytes: &[u8]) -> bool {
        for byte in bytes {
            if !self.try_send_bytes(std::slice::from_ref(byte)) {
                return true;
            }
            thread::sleep(TRICKLE_GAP);
        }
        false
    }

    /// Reads at most `chunk` bytes per read, [`TRICKLE_GAP`] apart, until
    /// the client closes. Returns the byte count read.
    pub(crate) fn drain_slowly(&mut self, chunk: usize) -> usize {
        let mut buf = vec![0_u8; chunk];
        let mut total = 0_usize;
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) | Err(_) => return total,
                Ok(count) => total = total.saturating_add(count),
            }
            thread::sleep(TRICKLE_GAP);
        }
    }

    /// Asserts the client closed the connection without sending more.
    pub(crate) fn expect_eof(&mut self) {
        let mut rest = Vec::new();
        self.stream
            .read_to_end(&mut rest)
            .expect("peer read to end");
        assert!(
            rest.is_empty(),
            "client sent {} unexpected bytes",
            rest.len()
        );
    }

    /// Server half of a successful handshake at version 1 with `max_frame`.
    /// Returns the hello and the auth frame received.
    pub(crate) fn admit(&mut self, max_frame: u32) -> (ClientHello, Auth) {
        let hello: ClientHello = self.recv();
        self.send(&ServerHello {
            version: VersionChoice::Chosen(1),
            server_nonce: SERVER_NONCE,
            max_frame,
        });
        let auth: Auth = self.recv();
        let transcript = auth_transcript(1, hello.tenant, &hello.client_nonce, &SERVER_NONCE);
        let signature = ed25519_dalek::Signature::from_bytes(&auth.signature);
        signing_key()
            .verifying_key()
            .verify_strict(&transcript, &signature)
            .expect("client signature verifies");
        self.send(&Admitted);
        (hello, auth)
    }
}

/// A scripted peer running on its own thread.
pub(crate) struct Scripted<T> {
    handle: JoinHandle<T>,
    release: mpsc::Sender<()>,
}

impl<T> Scripted<T> {
    /// Lets a peer blocked in [`Gate::wait`] continue, then joins it.
    pub(crate) fn finish(self) -> T {
        // NOTE: a peer that never waits has dropped its receiver; the send
        // error is irrelevant then.
        let _ = self.release.send(());
        self.handle.join().expect("peer thread panicked")
    }
}

/// Lets a peer hold still until the test has observed the client.
pub(crate) struct Gate(mpsc::Receiver<()>);

impl Gate {
    /// Blocks until the test calls [`Scripted::finish`].
    pub(crate) fn wait(&self) {
        // NOTE: a dropped sender also ends the wait.
        let _ = self.0.recv();
    }
}

/// Spawns `script` on the server half of a new socket pair; returns the
/// client half.
pub(crate) fn spawn<T, F>(script: F) -> (UnixStream, Scripted<T>)
where
    T: Send + 'static,
    F: FnOnce(Peer, Gate) -> T + Send + 'static,
{
    let (client, server) = UnixStream::pair().expect("socket pair");
    let (release, gate) = mpsc::channel();
    let handle = thread::spawn(move || script(Peer { stream: server }, Gate(gate)));
    (client, Scripted { handle, release })
}

/// The default negotiated bound, for scripts that do not test bounds.
pub(crate) const MAX: u32 = DEFAULT_MAX_BODY;
