//! The two seams through which the server reaches the rest of the daemon.

use std::future::Future;

use syntheke::{Request, TenantId};
use tokio::time::Instant;

use crate::cancel::CancelSignal;

/// What the server needs to authenticate one tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantAuth {
    /// The tenant's registered Ed25519 verifying key.
    pub verifying_key: [u8; 32],
    /// Local user ids a connection for this tenant may come from.
    pub bound_uids: Vec<u32>,
}

/// The registry of tenants the handshake authenticates against. The custody
/// store implements it.
pub trait TenantDirectory: Send + Sync + 'static {
    /// The tenant's authentication record, or `None` when the tenant is
    /// unknown or its record cannot be read.
    ///
    /// The server calls this on the connection's task, once per handshake,
    /// inside the handshake timeout: it must be a short point read (an
    /// in-memory or cached keyed lookup), never a scan or a network call.
    /// A `None` for an unreadable record fails the handshake closed with the
    /// same `AuthFailed` as every other cause.
    fn lookup(&self, tenant: TenantId) -> Option<TenantAuth>;
}

/// The identity of an admitted connection, fixed at the handshake.
///
/// Requests carry no tenant field; this value is the only source of the
/// acting tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnIdentity {
    /// The tenant the connection authenticated as.
    pub tenant: TenantId,
    /// The peer's user id, read from the socket at accept.
    pub uid: u32,
    /// The peer's process id at connect time, when the kernel reports one.
    /// Informational only: a pid can be reused and never authorizes.
    pub pid: Option<i32>,
    /// The negotiated wire version.
    pub version: u16,
    /// The negotiated maximum frame body. A [`syntheke::Response`] must
    /// encode within it; the server closes a connection whose dispatcher
    /// returns a larger one (chunk reads instead).
    pub max_frame: u32,
}

/// Executes one admitted request. The invocation lifecycle implements it.
///
/// The server spawns each call as its own task, tracks it against the
/// connection's in-flight bound, and writes the returned response tagged
/// with the request's id (it overwrites any other id the dispatcher sets).
pub trait Dispatcher: Send + Sync + 'static {
    /// Runs `request` for the connection `conn`.
    ///
    /// `cancel` fires on a `Cancel` frame for this request, when the
    /// connection closes, and at shutdown. `deadline` is on the server's
    /// monotonic clock, already clamped to the server's maximum. The
    /// dispatcher answers `Cancelled` or `DeadlineExceeded` itself so the
    /// lifecycle can settle or release first.
    ///
    /// A dispatcher that has not answered by `deadline` plus the server's
    /// dispatch grace is dropped and the server answers
    /// `DeadlineExceeded`; the same grace bounds the wait after a
    /// connection closes or the daemon shuts down. Work that must outlive
    /// the future (settling a reservation) belongs in a task the dispatcher
    /// owns.
    fn dispatch(
        &self,
        conn: ConnIdentity,
        request: Request,
        cancel: CancelSignal,
        deadline: Instant,
    ) -> impl Future<Output = syntheke::Response> + Send;
}
