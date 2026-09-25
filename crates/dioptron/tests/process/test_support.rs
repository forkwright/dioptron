//! A daemon under test: a tempdir with a root key, a store, a fixture
//! script, and a clock file; the `dioptron` binary spawned over it; and
//! `xenos` clients connected to its socket.
#![expect(clippy::expect_used, reason = "test helpers must fail loudly")]

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use syntheke::{
    CaptureLimits, CaptureRequest, Ceilings, GrantId, GrantIssueRequest, IdempotencyKey, Mode,
    Request, RequestBody, Response, SessionId, SessionScope, TenantId, Timestamp,
};
use xenos::{Client, Timeouts, supported_versions};

/// The binary under test.
pub const BIN: &str = env!("CARGO_BIN_EXE_dioptron");

/// The instant the clock file holds unless a test moves it.
pub const NOW_MS: i64 = 1_800_000_000_000;

/// Validity every test grant lies inside.
pub const NOT_BEFORE_MS: i64 = 0;
pub const EXPIRES_MS: i64 = 4_000_000_000_000;

/// Targets the fixture script answers.
pub const OK: &str = "https://example.com/article";
pub const LARGE: &str = "https://example.com/large";
pub const DOWN: &str = "https://example.com/down";
pub const RESET: &str = "https://example.com/reset";
pub const BAD: &str = "https://example.com/bad";
pub const STALL: &str = "https://example.com/stall";
pub const LATE: &str = "https://example.com/late";

/// The envelope the `OK` target delivers.
pub const ENVELOPE: &[u8] = b"<html><body>XENOS-FIXTURE-ENVELOPE example.com</body></html>";

/// The text view the `OK` target delivers.
pub const TEXT: &str = "XENOS fixture text";

/// The envelope the `LARGE` target delivers: 2.5 MiB, over one frame.
pub fn large_envelope() -> Vec<u8> {
    (0..2_621_440_u32)
        .map(|index| u8::try_from(index % 253).unwrap_or(0))
        .collect()
}

const SCRIPT: &str = "\
https://example.com/article\tdeliver\tenvelope.bin\tzetesis.evidence.v1\tfixture-1\tfp-article\ttext.txt
https://example.com/large\tdeliver\tlarge.bin\tzetesis.evidence.v1\tfixture-1\tfp-large\t-
https://example.com/late\tdeliver-on-cancel\tenvelope.bin\tzetesis.evidence.v1\tfixture-1\tfp-late\ttext.txt
https://example.com/down\tunavailable\tfalse
https://example.com/reset\ttransfer\tReset
https://example.com/bad\textraction\tMalformed
https://example.com/stall\tstall\tfalse
";

/// A tenant's identity and signing key.
#[derive(Clone, Debug)]
pub struct Tenant {
    pub id: TenantId,
    pub key: SigningKey,
}

impl Tenant {
    /// A tenant whose id and key derive from `seed`.
    pub fn new(seed: u8) -> Self {
        Self {
            id: TenantId::from_bytes([seed; 16]),
            key: SigningKey::from_bytes(&[seed.wrapping_add(0x40); 32]),
        }
    }

    /// The verifying key as hex.
    pub fn verifying_hex(&self) -> String {
        self.key
            .verifying_key()
            .to_bytes()
            .iter()
            .fold(String::new(), |mut hex, byte| {
                let _written = write!(hex, "{byte:02x}");
                hex
            })
    }
}

/// The operator.
pub fn operator() -> Tenant {
    Tenant::new(0x0a)
}

/// An agent under the operator.
pub fn agent() -> Tenant {
    Tenant::new(0x0b)
}

/// A sub-agent under the agent (registered only by tests that need it).
pub fn sub_agent() -> Tenant {
    Tenant::new(0x0c)
}

/// A second agent that holds no grant over the first agent's sessions.
pub fn stranger() -> Tenant {
    Tenant::new(0x0f)
}

/// The operator's root grant.
pub const ROOT: GrantId = GrantId::from_bytes([0xa0; 16]);

/// This process's effective uid, which the daemon sees as the peer uid.
pub fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// One daemon's files.
pub struct Harness {
    dir: tempfile::TempDir,
    requests: AtomicU64,
}

impl Harness {
    /// A tempdir with a root key, an empty store, and the fixture script.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let harness = Self {
            dir,
            requests: AtomicU64::new(1),
        };
        std::fs::write(harness.path("envelope.bin"), ENVELOPE).expect("envelope");
        std::fs::write(harness.path("large.bin"), large_envelope()).expect("large");
        std::fs::write(harness.path("text.txt"), TEXT).expect("text");
        std::fs::write(harness.path("script.tsv"), SCRIPT).expect("script");
        harness.set_clock(NOW_MS);
        harness.admin(&["keygen", harness.arg("root.key").as_str()]);
        harness.admin(&[
            "init",
            "--store",
            &harness.arg("store"),
            "--root-key",
            &harness.arg("root.key"),
        ]);
        harness
    }

    /// The standard cast: the operator with `ROOT`, bound to this uid; an
    /// agent and a stranger under it, bound to this uid.
    pub fn with_cast() -> Self {
        let harness = Self::new();
        harness.add_operator(&operator());
        harness.add_tenant(&agent(), "agent", own_uid(), &operator());
        harness.add_tenant(&stranger(), "agent", own_uid(), &operator());
        harness
    }

    /// A path inside the tempdir.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn arg(&self, name: &str) -> String {
        self.path(name).display().to_string()
    }

    /// The socket the daemon binds.
    pub fn socket(&self) -> PathBuf {
        self.path("sock").join("dioptron.sock")
    }

    /// Sets the time the daemon reads (with the `test-clock` feature).
    pub fn set_clock(&self, millis: i64) {
        std::fs::write(self.path("clock"), millis.to_string()).expect("clock");
    }

    /// The binary with the harness environment.
    pub fn command(&self) -> Command {
        let mut command = Command::new(BIN);
        command
            .env("DIOPTRON_TEST_CLOCK", self.path("clock"))
            .env_remove("DIOPTRON_FAILPOINT");
        command
    }

    /// Runs an admin command and asserts it succeeds; returns stdout.
    pub fn admin(&self, args: &[&str]) -> String {
        let output = self.command().args(args).output().expect("run admin");
        assert!(
            output.status.success(),
            "admin {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("utf-8")
    }

    /// Registers the operator with the root grant.
    pub fn add_operator(&self, tenant: &Tenant) {
        let uid = own_uid().to_string();
        let root = ROOT.to_string();
        let id = tenant.id.to_string();
        let key = tenant.verifying_hex();
        self.admin(&[
            "tenant",
            "add",
            "--store",
            &self.arg("store"),
            "--root-key",
            &self.arg("root.key"),
            "--tenant",
            &id,
            "--class",
            "operator",
            "--verifying-key",
            &key,
            "--uid",
            &uid,
            "--root-grant",
            &root,
            "--not-before",
            &NOT_BEFORE_MS.to_string(),
            "--expires-at",
            &EXPIRES_MS.to_string(),
        ]);
    }

    /// Registers `tenant` as a child of `parent`, bound to `uid`.
    pub fn add_tenant(&self, tenant: &Tenant, class: &str, uid: u32, parent: &Tenant) {
        let id = tenant.id.to_string();
        let key = tenant.verifying_hex();
        let parent = parent.id.to_string();
        self.admin(&[
            "tenant",
            "add",
            "--store",
            &self.arg("store"),
            "--root-key",
            &self.arg("root.key"),
            "--tenant",
            &id,
            "--class",
            class,
            "--verifying-key",
            &key,
            "--uid",
            &uid.to_string(),
            "--parent",
            &parent,
        ]);
    }

    /// Starts the daemon with the fixture producer.
    pub fn start(&self) -> Daemon {
        self.start_with(&[])
    }

    /// Starts the daemon with extra environment variables.
    pub fn start_with(&self, env: &[(&str, &str)]) -> Daemon {
        let fixture = format!("fixture:{}", self.arg("script.tsv"));
        self.serve(&["--producer", &fixture], env)
    }

    /// Starts the daemon with its default producer.
    pub fn start_default(&self) -> Daemon {
        self.serve(&[], &[])
    }

    fn serve(&self, extra: &[&str], env: &[(&str, &str)]) -> Daemon {
        let mut command = self.command();
        command
            .args([
                "serve",
                "--store",
                &self.arg("store"),
                "--root-key",
                &self.arg("root.key"),
                "--socket-dir",
                &self.arg("sock"),
            ])
            .args(extra)
            .envs(env.iter().copied())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Daemon::spawn(command)
    }

    /// Producer calls the fixture recorded, across every daemon run.
    pub fn calls(&self) -> usize {
        std::fs::read_to_string(self.path("script.tsv.calls"))
            .map_or(0, |text| text.lines().count())
    }

    /// Waits until the fixture has recorded `calls` calls.
    pub fn wait_calls(&self, calls: usize) {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(20))
            .expect("deadline");
        while self.calls() < calls {
            assert!(
                Instant::now() < deadline,
                "producer never reached {calls} calls"
            );
            std::thread::yield_now();
        }
    }

    /// An admitted client for `tenant`.
    pub fn connect(&self, tenant: &Tenant) -> Client {
        Client::connect(
            self.socket(),
            tenant.id,
            &tenant.key,
            supported_versions(),
            Timeouts::default(),
        )
        .expect("admitted")
    }

    /// The stopped daemon's store, opened directly.
    pub fn open_store(&self) -> phylake::Store {
        let root = phylake::keyfile::RootKey::load(&self.path("root.key")).expect("root key");
        let clock: std::sync::Arc<dyn epitrope::Clock + Send + Sync> =
            std::sync::Arc::new(epitrope::FixedClock(Timestamp::from_unix_millis(NOW_MS)));
        phylake::StoreOptions::new(self.path("store"), clock)
            .open(&root)
            .expect("open store")
    }

    /// The logical digest of the stopped daemon's store.
    pub fn digest(&self) -> [u8; 32] {
        self.open_store().logical_digest().expect("digest")
    }

    /// A request with a fresh request id.
    pub fn request(
        &self,
        grant: GrantId,
        key: Option<&str>,
        mode: Mode,
        body: RequestBody,
    ) -> Request {
        Request {
            request_id: self.requests.fetch_add(1, Ordering::SeqCst),
            grant,
            idempotency_key: key.map(idem),
            mode,
            deadline_ms: 30_000,
            body,
        }
    }
}

/// An idempotency key from a label, padded to 16 bytes.
pub fn idem(label: &str) -> IdempotencyKey {
    let mut bytes = label.as_bytes().to_vec();
    bytes.resize(bytes.len().max(16), b'.');
    IdempotencyKey::new(bytes).expect("key length")
}

/// A capture of `target` into `session`.
pub fn capture(session: SessionId, target: &str) -> RequestBody {
    RequestBody::Capture(CaptureRequest {
        session,
        target: target.to_owned(),
        limits: CaptureLimits {
            max_output_bytes: Some(1_024),
            max_transfer_bytes: Some(4 * 1024 * 1024),
        },
        egress_policy: None,
    })
}

/// A grant request for `holder` with `capabilities` over its own sessions
/// on example.com.
pub fn child_grant(holder: TenantId, capabilities: Vec<syntheke::Capability>) -> GrantIssueRequest {
    GrantIssueRequest {
        holder,
        capabilities,
        session_scope: SessionScope::Own,
        target_scope: vec!["example.com".to_owned()],
        ceilings: Ceilings::default(),
        not_before: Timestamp::from_unix_millis(NOT_BEFORE_MS),
        expires_at: Timestamp::from_unix_millis(EXPIRES_MS),
        max_depth: None,
    }
}

/// A running daemon. Dropping it kills the process.
pub struct Daemon {
    child: Option<Child>,
}

impl Daemon {
    fn spawn(mut command: Command) -> Self {
        let mut child = command.spawn().expect("spawn daemon");
        let stdout = child.stdout.take().expect("stdout");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("ready line");
        if !line.starts_with("ready ") {
            let output = child.wait_with_output().expect("daemon output");
            panic!(
                "daemon did not start: {line:?} {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Self { child: Some(child) }
    }

    /// Sends `SIGTERM` and asserts a clean exit.
    pub fn stop(mut self) {
        let status = self.terminate();
        assert!(
            status.success(),
            "daemon exits cleanly on SIGTERM: {status:?}"
        );
    }

    fn terminate(&mut self) -> ExitStatus {
        let mut child = self.child.take().expect("running");
        let pid = rustix::process::Pid::from_child(&child);
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("signal");
        child.wait().expect("wait")
    }

    /// Waits for the daemon to abort at its failpoint.
    #[cfg(feature = "failpoints")]
    pub fn wait_abort(mut self) {
        let status = self.child.take().expect("running").wait().expect("wait");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(6),
            "the daemon aborts at the failpoint: {status:?}"
        );
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _killed = child.kill();
            let _reaped = child.wait();
        }
    }
}

/// The contract bytes of a response, for byte-identity checks.
pub fn bytes(response: &Response) -> Vec<u8> {
    syntheke::encode(response).expect("encode").to_vec()
}

/// Opens a session for `tenant` under `grant` and returns it.
pub fn open_session(
    harness: &Harness,
    client: &mut Client,
    grant: GrantId,
    key: &str,
) -> SessionId {
    let request = harness.request(grant, Some(key), Mode::Execute, RequestBody::SessionCreate);
    match client.call(&request).expect("session create").body {
        syntheke::ResponseBody::SessionOpened(opened) => opened.session,
        other => panic!("session not opened: {other:?}"),
    }
}

/// Issues `request` under `ROOT` as the operator and returns the child.
pub fn issue(
    harness: &Harness,
    client: &mut Client,
    request: GrantIssueRequest,
    key: &str,
) -> GrantId {
    let request = harness.request(
        ROOT,
        Some(key),
        Mode::Execute,
        RequestBody::GrantIssue(request),
    );
    match client.call(&request).expect("grant issue").body {
        syntheke::ResponseBody::GrantIssued(issued) => issued.grant,
        other => panic!("grant not issued: {other:?}"),
    }
}
