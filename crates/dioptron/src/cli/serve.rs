//! `dioptron serve`.

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use snafu::ResultExt as _;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::Instant;
use tracing::{info, warn};

use super::Serve;
use crate::cancel::CancelSignal;
use crate::clock::daemon_clock;
use crate::error::{Error, RuntimeSnafu, SignalSnafu, StoreSnafu};
use crate::fixture::{FixtureProducer, call_log_for};
use crate::orchestrator::Orchestrator;
use crate::producer::{
    AcquireRequest, Producer, ProducerError, ProducerOutput, UnavailableProducer,
};
use crate::server::{Limits, Server};
use crate::tenants::StoreTenants;

/// The socket's file name inside `--socket-dir`.
pub const SOCKET_NAME: &str = "dioptron.sock";

/// How long the daemon waits, after the server stops, for request tasks
/// to settle what they started. Recovery at the next start finishes
/// anything left.
const DRAIN_GRACE: Duration = Duration::from_secs(10);

/// The producer `serve` was configured with.
#[derive(Debug)]
enum DaemonProducer {
    Unavailable(UnavailableProducer),
    Fixture(FixtureProducer),
}

impl Producer for DaemonProducer {
    async fn acquire(
        &self,
        request: AcquireRequest,
        cancel: CancelSignal,
        deadline: Instant,
    ) -> Result<ProducerOutput, ProducerError> {
        match self {
            Self::Unavailable(producer) => producer.acquire(request, cancel, deadline).await,
            Self::Fixture(producer) => producer.acquire(request, cancel, deadline).await,
        }
    }
}

/// Opens the store, recovers, and serves until a shutdown signal.
pub(super) fn serve(options: &Serve) -> Result<(), Error> {
    let producer = match &options.fixture {
        None => DaemonProducer::Unavailable(UnavailableProducer),
        Some(script) => DaemonProducer::Fixture(
            FixtureProducer::load(script)?.with_call_log(call_log_for(script)?),
        ),
    };
    let clock = daemon_clock();
    let store = Arc::new(open(options, Arc::clone(&clock))?);
    let report = store.recover().context(StoreSnafu)?;
    info!(
        released = report.released,
        unknown_effect = report.unknown_effect,
        published = report.published,
        settled = report.settled,
        "recovered"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context(RuntimeSnafu)?;
    runtime.block_on(async move {
        let mut interrupt = signal(SignalKind::interrupt()).context(SignalSnafu)?;
        let mut terminate = signal(SignalKind::terminate()).context(SignalSnafu)?;
        let (orchestrator, drain) = Orchestrator::new(Arc::clone(&store), producer, clock);
        let path = options.socket_dir.join(SOCKET_NAME);
        let server = Server::bind(
            &path,
            Limits::default(),
            StoreTenants::new(Arc::clone(&store)),
            orchestrator,
        )?;
        announce(&path);
        server
            .serve(async move {
                tokio::select! {
                    _signal = interrupt.recv() => {}
                    _signal = terminate.recv() => {}
                }
            })
            .await;
        if tokio::time::timeout(DRAIN_GRACE, drain.wait())
            .await
            .is_err()
        {
            warn!("request tasks outlived the drain grace; recovery will finish them");
        }
        Ok(())
    })
}

/// Opens the store, with the process failpoint when built for it.
fn open(
    options: &Serve,
    clock: Arc<dyn epitrope::Clock + Send + Sync>,
) -> Result<phylake::Store, Error> {
    #[cfg(feature = "failpoints")]
    if let Some(failpoint) = crate::failpoint::AbortAt::from_env()? {
        let root = phylake::keyfile::RootKey::load(&options.root_key).context(StoreSnafu)?;
        return phylake::StoreOptions::new(&options.store, clock)
            .failpoint(Arc::new(failpoint))
            .open(&root)
            .context(StoreSnafu);
    }
    super::open_store(&options.store, &options.root_key, clock)
}

/// Tells a supervisor the socket is bound.
fn announce(path: &std::path::Path) {
    let mut stdout = std::io::stdout().lock();
    // WHY ignored: a closed standard output does not stop the daemon.
    let _written = writeln!(stdout, "ready {}", path.display()).and_then(|()| stdout.flush());
}
