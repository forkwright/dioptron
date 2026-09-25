//! Low-level connection for adversarial tests: arbitrary bytes out, one
//! checked frame in, and close detection.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use snafu::ResultExt as _;

use crate::error::{ConnectSnafu, Error, IoSnafu};
use crate::frame::{self, Frame, WireMessage};

/// A connection with no protocol state: it sends whatever it is given and
/// reads one frame at a time.
///
/// Every send and read must finish within the connection's timeout, which
/// bounds the whole operation, not each system call: a peer that trickles
/// bytes cannot extend it. A timeout too large for the clock fails closed
/// at once with [`Error::Timeout`].
#[derive(Debug)]
pub struct RawConn {
    stream: UnixStream,
    timeout: Duration,
}

impl RawConn {
    /// Connects to the daemon socket at `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Connect`] when the socket cannot be connected.
    pub fn connect(path: impl AsRef<Path>, timeout: Duration) -> Result<Self, Error> {
        let path = path.as_ref();
        let stream = UnixStream::connect(path).context(ConnectSnafu { path })?;
        Ok(Self::from_stream(stream, timeout))
    }

    /// Wraps an already connected stream.
    ///
    /// The stream must be in blocking mode (the default for a connected
    /// [`UnixStream`]); on a nonblocking stream every wait reports
    /// [`Error::Timeout`] at once.
    #[must_use]
    pub const fn from_stream(stream: UnixStream, timeout: Duration) -> Self {
        Self { stream, timeout }
    }

    /// The bound on each send, read, or close wait.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Replaces the bound on each send, read, or close wait.
    pub const fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// The underlying stream.
    #[must_use]
    pub const fn stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Unwraps the underlying stream.
    #[must_use]
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }

    fn deadline(&self) -> Instant {
        frame::deadline_after(self.timeout)
    }

    /// Sends `bytes` exactly as given: a partial header, a header with any
    /// field value, a corrupt body, or several frames at once.
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] or [`Error::Io`].
    pub fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let deadline = self.deadline();
        frame::write_all(&mut self.stream, bytes, deadline)
    }

    pub(crate) fn send_bytes_by(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), Error> {
        frame::write_all(&mut self.stream, bytes, deadline)
    }

    /// Sends `header` followed by `body`, whether or not they agree.
    ///
    /// # Errors
    ///
    /// As [`Self::send_bytes`].
    pub fn send_frame(
        &mut self,
        header: &[u8; syntheke::HEADER_LEN],
        body: &[u8],
    ) -> Result<(), Error> {
        let mut bytes = Vec::with_capacity(header.len().saturating_add(body.len()));
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(body);
        self.send_bytes(&bytes)
    }

    /// Sends a well-formed frame carrying `message`, refusing a body over
    /// `cap` before writing.
    ///
    /// # Errors
    ///
    /// [`Error::Contract`] when the message fails its contract check,
    /// [`Error::FrameTooLarge`] for a body over `cap`, or a send error.
    pub fn send_message<M: WireMessage>(&mut self, message: &M, cap: u32) -> Result<(), Error> {
        let bytes = frame::frame_bytes(message, cap)?;
        self.send_bytes(&bytes)
    }

    pub(crate) fn send_message_by<M: WireMessage>(
        &mut self,
        message: &M,
        cap: u32,
        deadline: Instant,
    ) -> Result<(), Error> {
        let bytes = frame::frame_bytes(message, cap)?;
        frame::write_all(&mut self.stream, &bytes, deadline)
    }

    /// Reads the next frame, checking its header against `cap` before the
    /// body is read. The body is returned unvalidated.
    ///
    /// # Errors
    ///
    /// [`Error::Closed`] when the peer closed at the frame boundary,
    /// [`Error::Truncated`] when it closed mid-frame, [`Error::Timeout`], a
    /// header check error, or [`Error::Io`].
    pub fn read_frame(&mut self, cap: u32) -> Result<Frame, Error> {
        let deadline = self.deadline();
        frame::read_frame(&mut self.stream, cap, deadline)
    }

    pub(crate) fn read_frame_by(&mut self, cap: u32, deadline: Instant) -> Result<Frame, Error> {
        frame::read_frame(&mut self.stream, cap, deadline)
    }

    /// Reads the next frame and decodes it as `M` (see [`Frame::decode`]).
    ///
    /// # Errors
    ///
    /// As [`Self::read_frame`] and [`Frame::decode`].
    pub fn read_message<M: WireMessage>(&mut self, cap: u32) -> Result<M, Error> {
        self.read_frame(cap)?.decode(cap)
    }

    /// Waits for the peer to close the connection.
    ///
    /// # Errors
    ///
    /// [`Error::NotClosed`] when a byte arrives first, [`Error::Timeout`],
    /// or [`Error::Io`].
    pub fn expect_close(&mut self) -> Result<(), Error> {
        let deadline = self.deadline();
        frame::await_close(&mut self.stream, deadline)
    }

    /// Closes the sending half, so the peer reads end of stream.
    ///
    /// # Errors
    ///
    /// [`Error::Io`].
    pub fn shutdown_write(&self) -> Result<(), Error> {
        self.stream.shutdown(Shutdown::Write).context(IoSnafu)
    }
}

#[cfg(test)]
mod tests;
