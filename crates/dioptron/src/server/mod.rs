//! The Unix socket server (contract § Wire protocol).
//!
//! [`Server::bind`] prepares the socket (see [`Limits`] for every bound);
//! [`Server::serve`] accepts connections until its shutdown future
//! completes. Each accepted connection:
//!
//! 1. takes a permit from the global connection semaphore, or is closed at
//!    once when none is free;
//! 2. reads the peer's user id and process id from the socket;
//! 3. completes the handshake within [`Limits::handshake_timeout`], with
//!    every frame bounded by the 4 KiB pre-authentication cap, or receives
//!    a single `Fault` and is closed;
//! 4. then carries requests, each dispatched as its own task through
//!    [`Dispatcher`] with a [`crate::CancelSignal`] and a deadline, and
//!    answered in completion order, tagged by request id.
//!
//! Any protocol violation after admission (an invalid header or body, a
//! frame kind a client may not send, a duplicate in-flight request id, the
//! in-flight bound exceeded, a partial frame that times out) ends the
//! connection with one `Fault(ProtocolError)`.

mod connection;
mod frame;
mod handshake;
mod seams;
mod socket;

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use snafu::ResultExt as _;
use syntheke::{DEFAULT_MAX_BODY, Failure, HANDSHAKE_TIMEOUT_MS, HARD_MAX_BODY, PRE_AUTH_MAX_BODY};
use tokio::net::UnixListener;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tracing::{Instrument as _, debug, info, info_span, warn};

pub use seams::{ConnIdentity, Dispatcher, TenantAuth, TenantDirectory};

use crate::error::{BindSnafu, Error, SignalSnafu};

/// Longest configurable duration; keeps every deadline sum far from
/// monotonic clock overflow.
const MAX_DURATION: Duration = Duration::from_hours(24);

/// Pause after a failed `accept` (for example, the process is out of file
/// descriptors) before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Bounds applied by the server. [`Limits::default`] gives the contract
/// defaults; [`Server::bind`] clamps every field into its valid range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Concurrent connections, admitted or not (at least 1).
    pub max_connections: usize,
    /// Requests in flight on one connection (at least 1). One more is a
    /// protocol error.
    pub max_in_flight: usize,
    /// Time for the whole handshake; at most the contract's 5 seconds.
    pub handshake_timeout: Duration,
    /// Time for the rest of a frame once its first byte arrives, and for
    /// writing one frame.
    pub frame_timeout: Duration,
    /// An admitted connection with nothing in flight and no traffic for
    /// this long is closed.
    pub idle_timeout: Duration,
    /// Upper bound on a request's deadline.
    pub max_deadline: Duration,
    /// Time a dispatcher gets past its deadline, and after cancellation at
    /// close or shutdown, before the server drops it.
    pub dispatch_grace: Duration,
    /// Time [`Server::serve`] waits for connections to finish at shutdown.
    pub shutdown_grace: Duration,
    /// Negotiated maximum frame body offered after the handshake, within
    /// 4 KiB..=4 MiB.
    pub max_frame: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_in_flight: 16,
            handshake_timeout: Duration::from_millis(u64::from(HANDSHAKE_TIMEOUT_MS)),
            frame_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(5),
            max_deadline: Duration::from_mins(2),
            dispatch_grace: Duration::from_secs(2),
            shutdown_grace: Duration::from_secs(5),
            max_frame: DEFAULT_MAX_BODY,
        }
    }
}

impl Limits {
    /// These limits with every field clamped into its valid range.
    #[must_use]
    pub fn clamped(self) -> Self {
        let handshake_cap = Duration::from_millis(u64::from(HANDSHAKE_TIMEOUT_MS));
        Self {
            max_connections: self.max_connections.clamp(1, Semaphore::MAX_PERMITS),
            max_in_flight: self.max_in_flight.max(1),
            handshake_timeout: self.handshake_timeout.min(handshake_cap),
            frame_timeout: self.frame_timeout.min(MAX_DURATION),
            idle_timeout: self.idle_timeout.min(MAX_DURATION),
            max_deadline: self.max_deadline.min(MAX_DURATION),
            dispatch_grace: self.dispatch_grace.min(MAX_DURATION),
            shutdown_grace: self.shutdown_grace.min(MAX_DURATION),
            max_frame: self.max_frame.clamp(PRE_AUTH_MAX_BODY, HARD_MAX_BODY),
        }
    }
}

/// Why a connection ended.
#[derive(Debug)]
enum Close {
    /// The peer closed the stream at a frame boundary.
    PeerClosed,
    /// The stream failed, or the peer closed inside a frame.
    Io(io::Error),
    /// Idle timeout with nothing in flight.
    Idle,
    /// The daemon is shutting down.
    Shutdown,
    /// No common wire version; the `ServerHello` said so.
    Incompatible,
    /// A local failure unrelated to the peer's frames.
    Internal(&'static str),
    /// A connection-level failure, answered with one `Fault` frame.
    Fault(Failure, &'static str),
}

impl Close {
    /// The failure to send in a `Fault` frame, if any.
    fn fault(&self) -> Option<Failure> {
        match self {
            Self::Fault(failure, _) => Some(*failure),
            Self::PeerClosed
            | Self::Io(_)
            | Self::Idle
            | Self::Shutdown
            | Self::Incompatible
            | Self::Internal(_) => None,
        }
    }

    /// Records why the connection ended. Reasons are fixed strings; no
    /// frame content reaches the log.
    fn log(&self) {
        match self {
            Self::PeerClosed => debug!("peer closed"),
            Self::Io(error) => debug!(%error, "connection i/o failed"),
            Self::Idle => debug!("idle timeout"),
            Self::Shutdown => debug!("closing for shutdown"),
            Self::Incompatible => debug!("no common wire version"),
            Self::Internal(reason) => warn!(reason, "connection failed locally"),
            Self::Fault(failure, reason) => {
                info!(failure = %failure.kind(), reason, "closing with fault");
            }
        }
    }
}

/// State shared by every connection task.
struct Shared<T, D> {
    limits: Limits,
    directory: T,
    dispatcher: Arc<D>,
}

/// A bound, not yet serving, Unix socket server.
#[derive(Debug)]
pub struct Server<T, D> {
    listener: UnixListener,
    path: PathBuf,
    shared: Arc<Shared<T, D>>,
}

impl<T, D> std::fmt::Debug for Shared<T, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<T, D> Server<T, D>
where
    T: TenantDirectory,
    D: Dispatcher,
{
    /// Binds the socket at `path`, creating its parent directory with mode
    /// 0700 when missing.
    ///
    /// Must be called within a tokio runtime (the listener registers with
    /// its reactor).
    ///
    /// # Errors
    ///
    /// [`Error::NoSocketParent`], [`Error::SocketDir`], or
    /// [`Error::InsecureSocketDir`] for the directory;
    /// [`Error::SocketPathOccupied`], [`Error::SocketInUse`], or
    /// [`Error::InspectSocket`] for an existing path that is not a provably
    /// stale socket; [`Error::Bind`] when binding fails.
    pub fn bind(
        path: impl Into<PathBuf>,
        limits: Limits,
        directory: T,
        dispatcher: D,
    ) -> Result<Self, Error> {
        let path = path.into();
        let listener = socket::bind(&path)?;
        let listener = match UnixListener::from_std(listener).context(BindSnafu { path: &path }) {
            Ok(listener) => listener,
            Err(error) => {
                // WHY best effort: leave no socket behind for a later start.
                let _removed = std::fs::remove_file(&path);
                return Err(error);
            }
        };
        Ok(Self {
            listener,
            path,
            shared: Arc::new(Shared {
                limits: limits.clamped(),
                directory,
                dispatcher: Arc::new(dispatcher),
            }),
        })
    }

    /// The bound socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts connections until `shutdown` completes, then stops
    /// accepting, removes the socket file, cancels in-flight requests, and
    /// waits up to [`Limits::shutdown_grace`] for connections to finish
    /// before aborting the rest.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) {
        let Self {
            listener,
            path,
            shared,
        } = self;
        let span = info_span!("server");
        async move {
            let limits = shared.limits;
            let permits = Arc::new(Semaphore::new(limits.max_connections));
            let (stop_tx, stop_rx) = watch::channel(false);
            let mut connections = JoinSet::new();
            let mut shutdown = std::pin::pin!(shutdown);
            info!("serving");
            loop {
                tokio::select! {
                    biased;
                    () = &mut shutdown => break,
                    Some(_finished) = connections.join_next(), if !connections.is_empty() => {}
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _peer)) => {
                            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                                debug!("connection bound reached; refusing");
                                continue;
                            };
                            let shared = Arc::clone(&shared);
                            let stop = stop_rx.clone();
                            connections.spawn(
                                async move {
                                    connection::serve(stream, shared, stop).await;
                                    drop(permit);
                                }
                                .in_current_span(),
                            );
                        }
                        Err(error) => {
                            warn!(%error, "accept failed");
                            sleep(ACCEPT_BACKOFF).await;
                        }
                    },
                }
            }
            drop(listener);
            if let Err(error) = std::fs::remove_file(&path) {
                warn!(%error, "socket file not removed");
            }
            info!("shutting down");
            stop_tx.send_replace(true);
            let drained = timeout(limits.shutdown_grace, async {
                while connections.join_next().await.is_some() {}
            })
            .await;
            if drained.is_err() {
                warn!("connections outlived the shutdown grace; aborting them");
            }
            connections.shutdown().await;
        }
        .instrument(span)
        .await;
    }
}

/// Completes on the first `SIGINT` or `SIGTERM`.
///
/// # Errors
///
/// [`Error::Signal`] when a handler cannot be installed.
pub async fn shutdown_signal() -> Result<(), Error> {
    let mut interrupt = listen(SignalKind::interrupt())?;
    let mut terminate = listen(SignalKind::terminate())?;
    tokio::select! {
        _signal = interrupt.recv() => {}
        _signal = terminate.recv() => {}
    }
    Ok(())
}

/// Installs a handler for `kind`.
fn listen(kind: SignalKind) -> Result<Signal, Error> {
    signal(kind).context(SignalSnafu)
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
