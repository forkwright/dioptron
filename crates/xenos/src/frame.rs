//! The client's own frame codec: header emit and parse, length checks, and
//! deadline-bounded reads and writes over a blocking unix stream.
//!
//! Nothing here calls syntheke's header codec. syntheke supplies the
//! constants, the kind byte table, and the body schema; the header layout
//! and its checks are written again from the contract text so that a
//! mistake in one implementation shows up as a disagreement with the other.

use std::io::{self, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use snafu::{IntoError as _, OptionExt as _, ResultExt as _, ensure};
use syntheke::{
    Admitted, Auth, Cancel, ClientHello, Failure, Fault, FrameFlags, FrameKind, HARD_MAX_BODY,
    HEADER_LEN, MAGIC, Message, Request, Response, ServerHello,
};

use crate::error::{
    AuthFailedSnafu, BadMagicSnafu, ClosedSnafu, ContractSnafu, Error, FaultSnafu,
    FrameTooLargeSnafu, IoSnafu, NonzeroReservedSnafu, TimeoutSnafu, TruncatedSnafu,
    UnexpectedFrameSnafu, UnknownFlagsSnafu, UnknownFrameKindSnafu,
};

mod sealed {
    /// Restricts [`super::WireMessage`] to the contract's frame bodies.
    pub trait Sealed {}
}

/// A contract message that travels as one frame body.
///
/// Implemented for every frame body syntheke defines. The body schema is
/// syntheke's; the frame around it is this crate's.
pub trait WireMessage: Message + sealed::Sealed {
    /// Serializes the body, running the contract's invariant check first.
    ///
    /// # Errors
    ///
    /// [`Error::Contract`] when the check or the serializer fails.
    fn encode_body(&self) -> Result<Vec<u8>, Error>;

    /// Validates and deserializes a body of at most `cap` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Contract`] when the body is over `cap`, fails archive
    /// validation, or fails the contract's invariant check.
    fn decode_body(body: &[u8], cap: u32) -> Result<Self, Error>;
}

macro_rules! wire_message {
    ($($ty:ty),* $(,)?) => {$(
        impl sealed::Sealed for $ty {}

        impl WireMessage for $ty {
            fn encode_body(&self) -> Result<Vec<u8>, Error> {
                syntheke::encode(self).map(|body| body.to_vec()).context(ContractSnafu)
            }

            fn decode_body(body: &[u8], cap: u32) -> Result<Self, Error> {
                syntheke::decode::<$ty>(body, cap).context(ContractSnafu)
            }
        }
    )*};
}

wire_message!(
    ClientHello,
    ServerHello,
    Auth,
    Admitted,
    Request,
    Cancel,
    Response,
    Fault
);

/// Emits 12 header bytes with every field chosen by the caller, including
/// values the contract forbids, so tests can put malformed headers on the
/// wire.
///
/// # Examples
///
/// ```
/// let header = xenos::header_bytes(5, 0x80, 0, 16);
/// assert_eq!(&header[..4], b"DPT1");
/// assert_eq!(header[5], 0x80);
/// ```
#[must_use]
pub const fn header_bytes(kind: u8, flags: u8, reserved: u16, len: u32) -> [u8; HEADER_LEN] {
    let [m0, m1, m2, m3] = MAGIC;
    let [r0, r1] = reserved.to_le_bytes();
    let [l0, l1, l2, l3] = len.to_le_bytes();
    [m0, m1, m2, m3, kind, flags, r0, r1, l0, l1, l2, l3]
}

/// Parses and checks 12 received header bytes against a body bound.
///
/// Checks run in the contract's order: magic, kind, flags, reserved, then
/// length. `cap` is clamped to [`HARD_MAX_BODY`]. Returns the kind and the
/// declared body length.
///
/// # Errors
///
/// [`Error::BadMagic`], [`Error::UnknownFrameKind`], [`Error::UnknownFlags`],
/// [`Error::NonzeroReserved`], or [`Error::FrameTooLarge`].
///
/// # Examples
///
/// ```
/// use syntheke::{FrameKind, PRE_AUTH_MAX_BODY};
///
/// let header = xenos::header_bytes(8, 0, 0, 3);
/// assert_eq!(xenos::parse_header(&header, PRE_AUTH_MAX_BODY)?, (FrameKind::Fault, 3));
/// assert!(xenos::parse_header(&xenos::header_bytes(8, 1, 0, 3), PRE_AUTH_MAX_BODY).is_err());
/// # Ok::<(), xenos::Error>(())
/// ```
pub fn parse_header(bytes: &[u8; HEADER_LEN], cap: u32) -> Result<(FrameKind, u32), Error> {
    let [m0, m1, m2, m3, kind, flags, r0, r1, l0, l1, l2, l3] = *bytes;
    let found = [m0, m1, m2, m3];
    ensure!(found == MAGIC, BadMagicSnafu { found });
    let kind = FrameKind::from_u8(kind).context(UnknownFrameKindSnafu { kind })?;
    ensure!(flags & !FrameFlags::KNOWN == 0, UnknownFlagsSnafu { flags });
    let reserved = u16::from_le_bytes([r0, r1]);
    ensure!(reserved == 0, NonzeroReservedSnafu { reserved });
    let len = u32::from_le_bytes([l0, l1, l2, l3]);
    let cap = cap.min(HARD_MAX_BODY);
    ensure!(
        len <= cap,
        FrameTooLargeSnafu {
            len: u64::from(len),
            cap
        }
    );
    Ok((kind, len))
}

/// Builds a complete frame (header then body) for a message, refusing a
/// body over `cap` before anything is written.
pub(crate) fn frame_bytes<M: WireMessage>(message: &M, cap: u32) -> Result<Vec<u8>, Error> {
    let body = message.encode_body()?;
    let cap = cap.min(HARD_MAX_BODY);
    let len = u32::try_from(body.len())
        .ok()
        .filter(|&len| len <= cap)
        .context(FrameTooLargeSnafu {
            len: u64::try_from(body.len()).unwrap_or(u64::MAX),
            cap,
        })?;
    let mut frame = Vec::with_capacity(HEADER_LEN.saturating_add(body.len()));
    frame.extend_from_slice(&header_bytes(M::KIND.to_u8(), 0, 0, len));
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// A received frame whose header passed every check. The body has not been
/// validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    kind: FrameKind,
    body: Vec<u8>,
}

impl Frame {
    /// The frame kind.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }

    /// The raw body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Decodes the body as `M`.
    ///
    /// A `Fault` frame where `M` is another kind becomes the error it
    /// reports: [`Error::AuthFailed`] or [`Error::Fault`].
    ///
    /// # Errors
    ///
    /// [`Error::AuthFailed`] or [`Error::Fault`] for a fault frame,
    /// [`Error::UnexpectedFrame`] for any other kind than `M`'s, or
    /// [`Error::Contract`] when the body fails validation.
    pub fn decode<M: WireMessage>(&self, cap: u32) -> Result<M, Error> {
        if self.kind == FrameKind::Fault && M::KIND != FrameKind::Fault {
            let fault = Fault::decode_body(&self.body, cap)?;
            ensure!(fault.failure != Failure::AuthFailed, AuthFailedSnafu);
            return FaultSnafu {
                failure: fault.failure,
            }
            .fail();
        }
        ensure!(
            self.kind == M::KIND,
            UnexpectedFrameSnafu {
                expected: M::KIND,
                found: self.kind
            }
        );
        M::decode_body(&self.body, cap)
    }
}

/// Where a read stopped short.
enum Short {
    /// End of stream (or a reset) after `received` bytes.
    Eof { received: usize },
    /// Any other failure.
    Failed(Error),
}

/// The instant `span` from now. A span too large for the clock is treated
/// as already elapsed, so the operation fails closed with
/// [`Error::Timeout`] instead of waiting without bound.
pub(crate) fn deadline_after(span: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(span).unwrap_or(now)
}

/// Whether an I/O error kind means the socket timeout fired.
fn is_timeout(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// Fills `buf` from `stream`, re-arming the read timeout to the time left
/// before `deadline` on every read so a peer trickling bytes cannot extend
/// the bound.
fn fill(stream: &mut UnixStream, buf: &mut [u8], deadline: Instant) -> Result<(), Short> {
    let mut received = 0_usize;
    while let Some(rest) = buf.get_mut(received..).filter(|rest| !rest.is_empty()) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Short::Failed(TimeoutSnafu.build()));
        }
        stream
            .set_read_timeout(Some(left))
            .context(IoSnafu)
            .map_err(Short::Failed)?;
        match stream.read(rest) {
            Ok(0) => return Err(Short::Eof { received }),
            Ok(count) => received = received.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                return Err(Short::Eof { received });
            }
            Err(error) if is_timeout(error.kind()) => {
                return Err(Short::Failed(TimeoutSnafu.build()));
            }
            Err(error) => return Err(Short::Failed(IoSnafu.into_error(error))),
        }
    }
    Ok(())
}

/// Reads one frame: header, header checks against `cap`, then exactly the
/// declared body, all before `deadline`.
pub(crate) fn read_frame(
    stream: &mut UnixStream,
    cap: u32,
    deadline: Instant,
) -> Result<Frame, Error> {
    let mut header = [0_u8; HEADER_LEN];
    fill(stream, &mut header, deadline).map_err(|short| match short {
        Short::Eof { received: 0 } => ClosedSnafu.build(),
        Short::Eof { received } => TruncatedSnafu {
            expected: HEADER_LEN,
            received,
        }
        .build(),
        Short::Failed(error) => error,
    })?;
    let (kind, len) = parse_header(&header, cap)?;
    // WHY usize conversion only after parse_header: the length is bounded
    // by the cap before any buffer of that size exists.
    let len = usize::try_from(len).ok().context(FrameTooLargeSnafu {
        len: u64::from(len),
        cap,
    })?;
    let mut body = vec![0_u8; len];
    fill(stream, &mut body, deadline).map_err(|short| match short {
        Short::Eof { received } => TruncatedSnafu {
            expected: len,
            received,
        }
        .build(),
        Short::Failed(error) => error,
    })?;
    Ok(Frame { kind, body })
}

/// Largest slice handed to one `write` call.
///
/// WHY: the kernel applies the socket send timeout to each buffer it
/// allocates inside one `write`, not to the call, so a single large write
/// to a reader that frees space slowly can block far past the deadline.
/// Linux unix stream sockets queue up to 32 KiB of paged data per
/// allocation; a 16 KiB slice needs one allocation and so waits at most
/// once, for at most the time left.
const WRITE_SLICE: usize = 16 * 1024;

/// Writes all of `bytes` before `deadline`, however slowly the peer reads.
pub(crate) fn write_all(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), Error> {
    let mut sent = 0_usize;
    while let Some(rest) = bytes.get(sent..).filter(|rest| !rest.is_empty()) {
        let left = deadline.saturating_duration_since(Instant::now());
        ensure!(!left.is_zero(), TimeoutSnafu);
        stream.set_write_timeout(Some(left)).context(IoSnafu)?;
        let slice = rest.get(..WRITE_SLICE).unwrap_or(rest);
        match stream.write(slice) {
            Ok(0) => {
                return Err(io::Error::from(io::ErrorKind::WriteZero)).context(IoSnafu);
            }
            Ok(count) => sent = sent.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if is_timeout(error.kind()) => return TimeoutSnafu.fail(),
            Err(error) => return Err(error).context(IoSnafu),
        }
    }
    Ok(())
}

/// Waits for the peer to close: `Ok` on end of stream or reset, an error if
/// any byte arrives or the deadline passes first.
pub(crate) fn await_close(stream: &mut UnixStream, deadline: Instant) -> Result<(), Error> {
    let mut byte = [0_u8; 1];
    match fill(stream, &mut byte, deadline) {
        Err(Short::Eof { .. }) => Ok(()),
        Ok(()) => crate::error::NotClosedSnafu.fail(),
        Err(Short::Failed(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests;
