//! Test-only harness for the server: a tenant directory, a scriptable
//! dispatcher, a running server in a private directory, and a raw-framing
//! client.
//!
//! The client frames bytes itself (magic, kind byte, flags, reserved,
//! little-endian length) instead of calling the server's frame code, so a
//! framing bug on the server cannot be mirrored and hidden by the client.
//! It uses syntheke only to encode and decode message bodies.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use syntheke::{
    Auth, ClientHello, Failure, Fault, GrantId, Mode, Nonce, ReadChunk, Request, RequestBody,
    Response, ResponseBody, ServerHello, TenantId, VersionChoice, auth_transcript, decode, encode,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::{ConnIdentity, Dispatcher, Limits, Server, TenantAuth, TenantDirectory};
use crate::cancel::CancelSignal;

/// Boxed error for test results.
pub(super) type TestResult<T = ()> = Result<T, Box<dyn StdError>>;

/// Kind bytes, spelled out independently of `syntheke::FrameKind`.
pub(super) mod kind {
    pub(crate) const CLIENT_HELLO: u8 = 1;
    pub(crate) const SERVER_HELLO: u8 = 2;
    pub(crate) const AUTH: u8 = 3;
    pub(crate) const ADMITTED: u8 = 4;
    pub(crate) const REQUEST: u8 = 5;
    pub(crate) const CANCEL: u8 = 6;
    pub(crate) const RESPONSE: u8 = 7;
    pub(crate) const FAULT: u8 = 8;
}

/// The registered test tenant.
pub(super) const TENANT: TenantId = TenantId::from_bytes([0x11; 16]);
/// Seed of the registered test tenant's signing key.
pub(super) const TENANT_KEY: [u8; 32] = [0x21; 32];
/// A tenant registered with a uid the test process does not run as.
pub(super) const UNBOUND_TENANT: TenantId = TenantId::from_bytes([0x12; 16]);
/// A tenant the directory does not know.
pub(super) const UNKNOWN_TENANT: TenantId = TenantId::from_bytes([0x13; 16]);
/// A key registered to no tenant.
pub(super) const STRANGER_KEY: [u8; 32] = [0x22; 32];
/// The client nonce every test hello carries.
pub(super) const CLIENT_NONCE: Nonce = Nonce::from_bytes([0x31; 16]);

/// The effective uid of this process, as a socket peer sees it.
pub(super) fn own_uid() -> TestResult<u32> {
    let (left, _right) = UnixStream::pair()?;
    Ok(left.peer_cred()?.uid())
}

/// A fixed tenant table.
pub(super) struct StaticDirectory(HashMap<TenantId, TenantAuth>);

impl TenantDirectory for StaticDirectory {
    fn lookup(&self, tenant: TenantId) -> Option<TenantAuth> {
        self.0.get(&tenant).cloned()
    }
}

/// The test tenants: [`TENANT`] bound to this process's uid, and
/// [`UNBOUND_TENANT`] with the same key bound to the next uid.
pub(super) fn directory() -> TestResult<StaticDirectory> {
    let uid = own_uid()?;
    let other = uid.checked_add(1).ok_or("uid space exhausted")?;
    let key = SigningKey::from_bytes(&TENANT_KEY)
        .verifying_key()
        .to_bytes();
    let mut table = HashMap::new();
    table.insert(
        TENANT,
        TenantAuth {
            verifying_key: key,
            bound_uids: vec![uid],
        },
    );
    table.insert(
        UNBOUND_TENANT,
        TenantAuth {
            verifying_key: key,
            bound_uids: vec![other],
        },
    );
    Ok(StaticDirectory(table))
}

/// What the test dispatcher does with one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Behavior {
    /// Answer `InProgress` at once.
    Immediate,
    /// Wait for the cancel signal, report it, answer `Cancelled`.
    UntilCancel,
    /// Never answer.
    Hang,
    /// Panic.
    Panic,
    /// Answer with a chunk larger than the pre-auth bound.
    Oversize,
}

/// What the test dispatcher observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    /// A dispatch began.
    Started {
        /// The request.
        request_id: u64,
        /// The identity the server passed.
        conn: ConnIdentity,
        /// Time left until the deadline the server passed.
        remaining: Duration,
    },
    /// The dispatcher saw its cancel signal fire.
    Cancelled {
        /// The request.
        request_id: u64,
    },
}

/// A dispatcher whose behavior is chosen per request.
pub(super) struct TestDispatcher {
    events: mpsc::UnboundedSender<Event>,
    behavior: fn(&Request) -> Behavior,
}

impl TestDispatcher {
    /// A dispatcher reporting to `events`.
    pub(super) fn new(
        events: mpsc::UnboundedSender<Event>,
        behavior: fn(&Request) -> Behavior,
    ) -> Self {
        Self { events, behavior }
    }
}

impl Dispatcher for TestDispatcher {
    fn dispatch(
        &self,
        conn: ConnIdentity,
        request: Request,
        cancel: CancelSignal,
        deadline: Instant,
    ) -> impl Future<Output = Response> + Send {
        let events = self.events.clone();
        let behavior = (self.behavior)(&request);
        let request_id = request.request_id;
        async move {
            // WHY ignored: a test that stopped listening does not care.
            let _sent = events.send(Event::Started {
                request_id,
                conn,
                remaining: deadline.saturating_duration_since(Instant::now()),
            });
            match behavior {
                Behavior::Immediate => answer(request_id, ResponseBody::InProgress),
                Behavior::UntilCancel => {
                    cancel.cancelled().await;
                    let _sent = events.send(Event::Cancelled { request_id });
                    answer(request_id, ResponseBody::Failed(Failure::Cancelled))
                }
                Behavior::Hang => std::future::pending().await,
                Behavior::Panic => panic!("the test dispatcher panics on request"),
                Behavior::Oversize => answer(
                    request_id,
                    ResponseBody::Chunk(ReadChunk {
                        offset: 0,
                        bytes: vec![0; 8192],
                        total_len: 8192,
                    }),
                ),
            }
        }
    }
}

fn answer(request_id: u64, body: ResponseBody) -> Response {
    Response {
        request_id,
        invocation: None,
        body,
    }
}

/// A server running in a private directory.
pub(super) struct Harness {
    /// Keeps the directory alive for the test.
    pub(super) _dir: tempfile::TempDir,
    /// The socket path.
    pub(super) path: PathBuf,
    /// Dispatcher observations.
    pub(super) events: mpsc::UnboundedReceiver<Event>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Harness {
    /// Starts a server with `limits` whose dispatcher uses `behavior`.
    pub(super) fn start(limits: Limits, behavior: fn(&Request) -> Behavior) -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("run").join("dioptron.sock");
        let (events_tx, events) = mpsc::unbounded_channel();
        let dispatcher = TestDispatcher::new(events_tx, behavior);
        let server = Server::bind(&path, limits, directory()?, dispatcher)?;
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(server.serve(async move {
            // WHY ignored: a dropped sender also means stop.
            let _stop = stopped.await;
        }));
        Ok(Self {
            _dir: dir,
            path,
            events,
            stop: Some(stop),
            task: Some(task),
        })
    }

    /// Connects a raw client.
    pub(super) async fn connect(&self) -> TestResult<Client> {
        Ok(Client {
            stream: UnixStream::connect(&self.path).await?,
        })
    }

    /// Connects and completes the handshake as [`TENANT`].
    pub(super) async fn admitted(&self) -> TestResult<Client> {
        let mut client = self.connect().await?;
        client.handshake(TENANT, &TENANT_KEY).await?;
        Ok(client)
    }

    /// The next dispatcher observation.
    pub(super) async fn event(&mut self) -> TestResult<Event> {
        Ok(self.events.recv().await.ok_or("dispatcher events ended")?)
    }

    /// Signals shutdown and waits for `serve` to return.
    pub(super) async fn shutdown(&mut self) -> TestResult {
        if let Some(stop) = self.stop.take() {
            stop.send(()).map_err(|()| "server already stopped")?;
        }
        if let Some(task) = self.task.take() {
            task.await?;
        }
        Ok(())
    }
}

/// A frame as the raw client parsed it.
pub(super) type RawFrame = (u8, Vec<u8>);

/// A client that frames bytes by hand.
pub(super) struct Client {
    stream: UnixStream,
}

impl Client {
    /// Writes raw bytes.
    pub(super) async fn send_raw(&mut self, bytes: &[u8]) -> TestResult {
        self.stream.write_all(bytes).await?;
        Ok(())
    }

    /// Writes one frame with a well-formed header.
    pub(super) async fn send(&mut self, kind: u8, body: &[u8]) -> TestResult {
        self.send_raw(&header(kind, u32::try_from(body.len())?))
            .await?;
        self.send_raw(body).await
    }

    /// Reads one frame, or `None` at end of stream.
    pub(super) async fn recv(&mut self) -> TestResult<Option<RawFrame>> {
        let mut head = [0_u8; 12];
        let mut filled = 0;
        while filled < head.len() {
            let read = self
                .stream
                .read(head.get_mut(filled..).ok_or("header")?)
                .await?;
            if read == 0 {
                return if filled == 0 {
                    Ok(None)
                } else {
                    Err("stream ended inside a header".into())
                };
            }
            filled = filled.checked_add(read).ok_or("overflow")?;
        }
        let [m0, m1, m2, m3, kind, flags, r0, r1, l0, l1, l2, l3] = head;
        if [m0, m1, m2, m3] != *b"DPT1" || flags != 0 || [r0, r1] != [0, 0] {
            return Err("server sent a malformed header".into());
        }
        let mut body = vec![0_u8; usize::try_from(u32::from_le_bytes([l0, l1, l2, l3]))?];
        self.stream.read_exact(&mut body).await?;
        Ok(Some((kind, body)))
    }

    /// Reads one frame; fails at end of stream.
    pub(super) async fn frame(&mut self) -> TestResult<RawFrame> {
        Ok(self.recv().await?.ok_or("stream ended")?)
    }

    /// Reads a `Fault` frame followed by end of stream; returns the raw
    /// frame bytes and the decoded failure.
    pub(super) async fn fault_then_close(&mut self) -> TestResult<(Vec<u8>, Failure)> {
        let (kind, body) = self.frame().await?;
        if kind != kind::FAULT {
            return Err(format!("expected a fault frame, got kind {kind}").into());
        }
        let fault: Fault = decode(&body, 4096)?;
        self.expect_closed().await?;
        let mut raw = header(kind, u32::try_from(body.len())?).to_vec();
        raw.extend_from_slice(&body);
        Ok((raw, fault.failure))
    }

    /// Asserts the server closed the stream without another frame.
    pub(super) async fn expect_closed(&mut self) -> TestResult {
        match self.recv().await? {
            None => Ok(()),
            Some((kind, _)) => Err(format!("expected end of stream, got kind {kind}").into()),
        }
    }

    /// Sends a hello for `tenant` offering `min..=max`; returns the decoded
    /// server hello.
    pub(super) async fn hello(
        &mut self,
        tenant: TenantId,
        min: u16,
        max: u16,
    ) -> TestResult<ServerHello> {
        let hello = ClientHello {
            version_min: min,
            version_max: max,
            tenant,
            client_nonce: CLIENT_NONCE,
        };
        self.send(kind::CLIENT_HELLO, &encode(&hello)?).await?;
        let (kind, body) = self.frame().await?;
        if kind != kind::SERVER_HELLO {
            return Err(format!("expected a server hello, got kind {kind}").into());
        }
        if body.len() > 4096 {
            return Err("server hello exceeds the pre-auth bound".into());
        }
        Ok(decode(&body, 4096)?)
    }

    /// Sends an auth frame carrying `signature`.
    pub(super) async fn auth(&mut self, signature: [u8; 64]) -> TestResult {
        self.send(kind::AUTH, &encode(&Auth { signature })?).await
    }

    /// Signs the transcript for `hello` with `key`.
    pub(super) fn sign(tenant: TenantId, server: &ServerHello, key: &[u8; 32]) -> [u8; 64] {
        let version = match server.version {
            VersionChoice::Chosen(version) => version,
            _ => 0,
        };
        let transcript = auth_transcript(version, tenant, &CLIENT_NONCE, &server.server_nonce);
        SigningKey::from_bytes(key).sign(&transcript).to_bytes()
    }

    /// Completes the handshake; returns the server hello and the signature.
    pub(super) async fn handshake(
        &mut self,
        tenant: TenantId,
        key: &[u8; 32],
    ) -> TestResult<(ServerHello, [u8; 64])> {
        let server = self.hello(tenant, 1, 1).await?;
        let signature = Self::sign(tenant, &server, key);
        self.auth(signature).await?;
        let (kind, body) = self.frame().await?;
        if kind == kind::FAULT {
            let fault: Fault = decode(&body, 4096)?;
            return Err(format!("expected admitted, got {:?}", fault.failure).into());
        }
        if kind != kind::ADMITTED || body.len() > 4096 {
            return Err(format!("expected admitted, got kind {kind}").into());
        }
        Ok((server, signature))
    }

    /// Sends a request.
    pub(super) async fn request(&mut self, request: &Request) -> TestResult {
        self.send(kind::REQUEST, &encode(request)?).await
    }

    /// Sends a cancel.
    pub(super) async fn cancel(&mut self, request_id: u64) -> TestResult {
        self.send(kind::CANCEL, &encode(&syntheke::Cancel { request_id })?)
            .await
    }

    /// Reads one response.
    pub(super) async fn response(&mut self) -> TestResult<Response> {
        let (kind, body) = self.frame().await?;
        if kind != kind::RESPONSE {
            return Err(format!("expected a response, got kind {kind}").into());
        }
        Ok(decode(&body, 4 * 1024 * 1024)?)
    }
}

/// A well-formed header for `kind` and `len`.
pub(super) fn header(kind: u8, len: u32) -> [u8; 12] {
    let [l0, l1, l2, l3] = len.to_le_bytes();
    [b'D', b'P', b'T', b'1', kind, 0, 0, 0, l0, l1, l2, l3]
}

/// A dry-run `SessionCreate` request.
pub(super) fn request(request_id: u64, deadline_ms: u32) -> Request {
    Request {
        request_id,
        grant: GrantId::from_bytes([0x41; 16]),
        idempotency_key: None,
        mode: Mode::DryRun,
        deadline_ms,
        body: RequestBody::SessionCreate,
    }
}

/// A bound short enough to keep timeout tests fast and long enough to be
/// measured.
pub(super) const SHORT: Duration = Duration::from_millis(300);

/// Headroom for timing assertions on a loaded machine. Timers never fire
/// early, so only the upper side needs it.
pub(super) const SLACK: Duration = Duration::from_secs(10);

/// Asserts `elapsed` is at least `bound` and not wildly past it.
pub(super) fn assert_fired(elapsed: Duration, bound: Duration, what: &str) {
    assert!(
        elapsed >= bound,
        "{what}: fired after {elapsed:?}, before {bound:?}"
    );
    assert!(
        elapsed < bound.saturating_add(SLACK),
        "{what}: fired after {elapsed:?}, long after {bound:?}"
    );
}

/// Test limits. Timeouts are long so that only tests which shorten one
/// ever reach it.
pub(super) fn limits() -> Limits {
    Limits {
        frame_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_mins(1),
        max_deadline: Duration::from_secs(30),
        dispatch_grace: Duration::from_secs(2),
        shutdown_grace: Duration::from_secs(5),
        max_in_flight: 4,
        ..Limits::default()
    }
}

/// A behavior that answers every request at once.
pub(super) fn immediate(_: &Request) -> Behavior {
    Behavior::Immediate
}

/// A behavior that waits for cancellation on every request.
pub(super) fn until_cancel(_: &Request) -> Behavior {
    Behavior::UntilCancel
}
