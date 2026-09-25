//! The authenticated client: handshake, then requests and cancels.

use std::ops::RangeInclusive;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer as _, SigningKey};
use snafu::{ResultExt as _, ensure};
use syntheke::{
    Admitted, Auth, Cancel, ClientHello, HANDSHAKE_TIMEOUT_MS, NONCE_LEN, Nonce, PRE_AUTH_MAX_BODY,
    Request, Response, ServerHello, TenantId, VersionChoice, WIRE_VERSION, auth_transcript,
};

use crate::error::{
    BrokenSnafu, ConnectSnafu, Error, IncompatibleSnafu, IoSnafu, RandomSnafu,
    UnexpectedResponseSnafu, VersionOutOfRangeSnafu,
};
use crate::frame::{self, deadline_after};
use crate::raw::RawConn;

/// Time bounds for a client connection.
///
/// Each bound covers a whole operation, not one system call, so a server
/// that trickles bytes cannot extend it. A bound too large for the clock
/// fails closed at once with [`Error::Timeout`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// Bound on the whole handshake, from the first byte sent to `Admitted`.
    pub handshake: Duration,
    /// Bound on sending one frame, and on waiting for and reading one
    /// frame, once admitted.
    pub frame: Duration,
}

impl Default for Timeouts {
    /// The contract's 5 s handshake bound and a 60 s frame bound, above the
    /// first consumer's 30 s request deadline.
    fn default() -> Self {
        Self {
            handshake: Duration::from_millis(u64::from(HANDSHAKE_TIMEOUT_MS)),
            frame: Duration::from_mins(1),
        }
    }
}

/// An admitted connection to a Dioptron daemon.
///
/// Requests may be pipelined with [`Client::send_request`] and
/// [`Client::recv_response`]; [`Client::call`] is the one-at-a-time form.
///
/// Every frame before `Admitted`, in either direction, is held to the
/// contract's 4 KiB pre-auth bound; after `Admitted` the negotiated
/// [`Client::max_frame`] applies both ways.
///
/// A request refused locally (contract check, over-bound body) writes
/// nothing and leaves the client usable. Any failure once a send or read
/// has started, including a timeout, a fault, an unexpected frame, or an
/// invalid body, leaves the framing state unknown or the server closing:
/// the client then answers every further call with [`Error::Broken`].
#[derive(Debug)]
pub struct Client {
    conn: RawConn,
    version: u16,
    max_frame: u32,
    timeouts: Timeouts,
    broken: bool,
}

impl Client {
    /// Connects to the daemon socket at `path` and runs the handshake as
    /// `tenant`, offering wire `versions`.
    ///
    /// # Errors
    ///
    /// [`Error::Connect`] when the socket cannot be connected, or any
    /// [`Client::handshake`] error.
    pub fn connect(
        path: impl AsRef<Path>,
        tenant: TenantId,
        signing_key: &SigningKey,
        versions: RangeInclusive<u16>,
        timeouts: Timeouts,
    ) -> Result<Self, Error> {
        let path = path.as_ref();
        let stream = UnixStream::connect(path).context(ConnectSnafu { path })?;
        Self::handshake(stream, tenant, signing_key, versions, timeouts)
    }

    /// Runs the handshake over an already connected stream: `ClientHello`,
    /// then `ServerHello`, then `Auth` signed over syntheke's transcript,
    /// then `Admitted`.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] when no nonce can be drawn; [`Error::Contract`] for
    /// an empty version range or an invalid server frame body;
    /// [`Error::Incompatible`] or [`Error::VersionOutOfRange`] for the
    /// server's version decision; [`Error::AuthFailed`] or [`Error::Fault`]
    /// when the server refuses; [`Error::UnexpectedFrame`] for a frame out of
    /// sequence; and any framing or socket error, including
    /// [`Error::Timeout`] when the handshake bound elapses.
    pub fn handshake(
        stream: UnixStream,
        tenant: TenantId,
        signing_key: &SigningKey,
        versions: RangeInclusive<u16>,
        timeouts: Timeouts,
    ) -> Result<Self, Error> {
        Self::handshake_with(
            stream,
            tenant,
            signing_key,
            versions,
            timeouts,
            getrandom::fill,
        )
    }

    /// [`Client::handshake`] with an injected nonce source.
    pub(crate) fn handshake_with(
        stream: UnixStream,
        tenant: TenantId,
        signing_key: &SigningKey,
        versions: RangeInclusive<u16>,
        timeouts: Timeouts,
        random: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
    ) -> Result<Self, Error> {
        let deadline = deadline_after(timeouts.handshake);
        // WHY: the deadline logic relies on socket timeouts, which a
        // nonblocking stream would turn into immediate `Timeout` errors.
        stream.set_nonblocking(false).context(IoSnafu)?;
        let (min, max) = (*versions.start(), *versions.end());
        let mut nonce = [0_u8; NONCE_LEN];
        random(&mut nonce).context(RandomSnafu)?;
        let client_nonce = Nonce::from_bytes(nonce);
        let mut conn = RawConn::from_stream(stream, timeouts.frame);

        let hello = ClientHello {
            version_min: min,
            version_max: max,
            tenant,
            client_nonce,
        };
        conn.send_message_by(&hello, PRE_AUTH_MAX_BODY, deadline)?;
        let reply: ServerHello = conn
            .read_frame_by(PRE_AUTH_MAX_BODY, deadline)?
            .decode(PRE_AUTH_MAX_BODY)?;
        let version = match reply.version {
            VersionChoice::Chosen(version) => version,
            // WHY the wildcard fails closed as Incompatible: a decision this
            // contract version does not define names no version the client
            // can speak.
            VersionChoice::Incompatible | _ => return IncompatibleSnafu { min, max }.fail(),
        };
        ensure!(
            versions.contains(&version),
            VersionOutOfRangeSnafu {
                chosen: version,
                min,
                max
            }
        );

        let transcript = auth_transcript(version, tenant, &client_nonce, &reply.server_nonce);
        let auth = Auth {
            signature: signing_key.sign(&transcript).to_bytes(),
        };
        conn.send_message_by(&auth, PRE_AUTH_MAX_BODY, deadline)?;
        let Admitted = conn
            .read_frame_by(PRE_AUTH_MAX_BODY, deadline)?
            .decode(PRE_AUTH_MAX_BODY)?;
        Ok(Self {
            conn,
            version,
            max_frame: reply.max_frame,
            timeouts,
            broken: false,
        })
    }

    /// The negotiated wire version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// The negotiated body bound, applied to frames in both directions.
    #[must_use]
    pub const fn max_frame(&self) -> u32 {
        self.max_frame
    }

    /// The time bounds in force.
    #[must_use]
    pub const fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// Hands over the admitted connection for adversarial use after the
    /// handshake, such as an oversized or corrupt request frame.
    #[must_use]
    pub fn into_raw(self) -> RawConn {
        self.conn
    }

    /// Runs `op` on the connection, marking the client broken if it fails.
    fn guarded<T>(
        &mut self,
        op: impl FnOnce(&mut RawConn, u32, Instant) -> Result<T, Error>,
    ) -> Result<T, Error> {
        ensure!(!self.broken, BrokenSnafu);
        let deadline = deadline_after(self.timeouts.frame);
        let result = op(&mut self.conn, self.max_frame, deadline);
        self.broken = result.is_err();
        result
    }

    /// Sends a request without waiting for its response.
    ///
    /// A request that fails its contract check or exceeds the negotiated
    /// bound is refused before any byte is written and leaves the client
    /// usable.
    ///
    /// # Errors
    ///
    /// [`Error::Broken`], [`Error::Contract`], [`Error::FrameTooLarge`], or a
    /// send error.
    pub fn send_request(&mut self, request: &Request) -> Result<(), Error> {
        self.send_message(request)
    }

    /// Sends a `Cancel` for `request_id`.
    ///
    /// # Errors
    ///
    /// [`Error::Broken`] or a send error.
    pub fn cancel(&mut self, request_id: u64) -> Result<(), Error> {
        self.send_message(&Cancel { request_id })
    }

    /// Frames `message` under the negotiated bound, refusing it locally
    /// before any byte is written, then sends it.
    fn send_message<M: frame::WireMessage>(&mut self, message: &M) -> Result<(), Error> {
        ensure!(!self.broken, BrokenSnafu);
        let bytes = frame::frame_bytes(message, self.max_frame)?;
        self.guarded(|conn, _, deadline| conn.send_bytes_by(&bytes, deadline))
    }

    /// Reads the next response.
    ///
    /// # Errors
    ///
    /// [`Error::Broken`]; [`Error::AuthFailed`] or [`Error::Fault`] when the
    /// server sends a fault; [`Error::UnexpectedFrame`] for a frame other
    /// than a response; [`Error::Contract`] for an invalid body; or any
    /// framing or socket error.
    pub fn recv_response(&mut self) -> Result<Response, Error> {
        self.guarded(|conn, cap, deadline| conn.read_frame_by(cap, deadline)?.decode(cap))
    }

    /// Sends `request` and reads its response. No other request may be
    /// outstanding.
    ///
    /// # Errors
    ///
    /// As [`Client::send_request`] and [`Client::recv_response`], or
    /// [`Error::UnexpectedResponse`] when the response names another
    /// request.
    pub fn call(&mut self, request: &Request) -> Result<Response, Error> {
        self.send_request(request)?;
        let response = self.recv_response()?;
        let expected = request.request_id;
        if response.request_id != expected {
            self.broken = true;
            return UnexpectedResponseSnafu {
                expected,
                found: response.request_id,
            }
            .fail();
        }
        Ok(response)
    }
}

/// The version range this crate speaks: exactly [`WIRE_VERSION`].
#[must_use]
pub const fn supported_versions() -> RangeInclusive<u16> {
    WIRE_VERSION..=WIRE_VERSION
}

#[cfg(test)]
mod tests;
