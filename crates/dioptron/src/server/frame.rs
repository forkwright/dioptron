//! Frame I/O: bounded, timed reads and writes of whole frames.

use std::io;
use std::time::Duration;

use syntheke::{Failure, Fault, FrameHeader, HEADER_LEN, PRE_AUTH_MAX_BODY, encode_frame};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::{Instant, timeout_at};
use tracing::debug;

use super::Close;

/// One received frame: a validated header and exactly its declared body.
#[derive(Debug)]
pub(super) struct Frame {
    /// The validated header.
    pub(super) header: FrameHeader,
    /// The body bytes, not yet validated as an archive.
    pub(super) body: Vec<u8>,
}

/// Why a frame could not be read.
#[derive(Debug)]
pub(super) enum ReadFail {
    /// The peer closed the stream at a frame boundary.
    Closed,
    /// The stream failed, or closed inside a frame.
    Io(io::Error),
    /// A started frame did not complete within the frame timeout.
    Timeout,
    /// The header failed validation (magic, kind, flags, reserved, length).
    Header(syntheke::Error),
}

impl ReadFail {
    /// How the connection ends after this failure.
    pub(super) fn into_close(self) -> Close {
        match self {
            Self::Closed => Close::PeerClosed,
            Self::Io(error) => Close::Io(error),
            Self::Timeout => Close::Fault(Failure::ProtocolError, "partial frame timed out"),
            Self::Header(error) => {
                debug!(%error, "invalid frame header");
                Close::Fault(Failure::ProtocolError, "invalid frame header")
            }
        }
    }
}

/// `now + duration` on the monotonic clock, saturating at `now` when the sum
/// would overflow (callers bound every duration well below that).
pub(super) fn after(duration: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(duration).unwrap_or(now)
}

/// Reads one frame whose body may be at most `cap` bytes.
///
/// Waiting for the first header byte has no timer of its own: the caller
/// bounds it (handshake timeout, idle timeout). Once a byte arrives, the
/// rest of the header and the whole body must arrive within
/// `frame_timeout`. The declared length is checked against `cap` before the
/// body buffer is allocated.
pub(super) async fn read_frame<R>(
    reader: &mut R,
    cap: u32,
    frame_timeout: Duration,
) -> Result<Frame, ReadFail>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0_u8; HEADER_LEN];
    let (first, rest) = head.split_at_mut(1);
    let read = reader.read(first).await.map_err(ReadFail::Io)?;
    if read == 0 {
        return Err(ReadFail::Closed);
    }
    let deadline = after(frame_timeout);
    timeout_at(deadline, reader.read_exact(rest))
        .await
        .map_err(|_elapsed| ReadFail::Timeout)?
        .map_err(ReadFail::Io)?;
    let header = FrameHeader::decode(&head, cap).map_err(ReadFail::Header)?;
    // INVARIANT: decode bounded the length by `cap`, itself clamped to the
    // 4 MiB hard maximum, so this is the only allocation a peer can size
    // and it is bounded before it happens.
    let len = usize::try_from(header.len())
        .map_err(|overflow| ReadFail::Io(io::Error::new(io::ErrorKind::InvalidData, overflow)))?;
    let mut body = vec![0_u8; len];
    timeout_at(deadline, reader.read_exact(&mut body))
        .await
        .map_err(|_elapsed| ReadFail::Timeout)?
        .map_err(ReadFail::Io)?;
    Ok(Frame { header, body })
}

/// Writes `bytes` within `write_timeout`.
pub(super) async fn write_frame<W>(
    writer: &mut W,
    bytes: &[u8],
    write_timeout: Duration,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout_at(after(write_timeout), async {
        writer.write_all(bytes).await?;
        writer.flush().await
    })
    .await
    .map_err(|_elapsed| io::Error::from(io::ErrorKind::TimedOut))?
}

/// The encoded `Fault` frame for a connection-level failure.
///
/// A `Fault` fits the pre-authentication bound, so the same bytes serve
/// both handshake and admitted connections, and every `AuthFailed` a server
/// sends is byte-identical.
pub(super) fn fault_frame(failure: Failure) -> Option<Vec<u8>> {
    encode_frame(&Fault { failure }, PRE_AUTH_MAX_BODY).ok()
}
