//! Frame body encoding and validating decoding.
//!
//! Decoding follows the contract's order: bound the length before touching
//! the bytes, copy into an aligned buffer, validate the whole archive, and
//! only then read fields. A body that fails any step is never accessed as a
//! typed value.

use rkyv::api::high::{HighDeserializer, HighSerializer, HighValidator};
use rkyv::bytecheck::CheckBytes;
use rkyv::rancor;
use rkyv::ser::allocator::ArenaHandle;
use rkyv::util::AlignedVec;
use rkyv::{Archive, Deserialize, Serialize};
use snafu::{OptionExt as _, ResultExt as _, ensure};

use crate::error::{
    BodyLengthMismatchSnafu, EncodeSnafu, Error, FrameTooLargeSnafu, InvalidArchiveSnafu,
    UnexpectedFrameKindSnafu,
};
use crate::wire::{FrameHeader, FrameKind, HEADER_LEN, clamp_cap};

/// A type that travels as the body of one frame kind.
pub trait Message: Sized {
    /// The frame kind that carries this message.
    const KIND: FrameKind;

    /// Checks invariants the archive validator cannot express. Runs after a
    /// successful decode and before an encode.
    ///
    /// # Errors
    ///
    /// The invariant that failed. The default accepts every value.
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Byte length as `u64` for error reports.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Whether `len` bytes fit within the clamped bound `cap`.
fn within(len: usize, cap: u32) -> bool {
    usize::try_from(cap).is_ok_and(|cap| len <= cap)
}

/// Serializes a message body.
///
/// # Errors
///
/// The message's [`Message::check`] error, or [`Error::Encode`] when the
/// serializer fails.
pub fn encode<T>(message: &T) -> Result<AlignedVec, Error>
where
    T: Message + for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>,
{
    message.check()?;
    rkyv::to_bytes::<rancor::Error>(message).context(EncodeSnafu)
}

/// Serializes a message into a complete frame: header, then body.
///
/// # Errors
///
/// As [`encode`], or [`Error::FrameTooLarge`] when the body exceeds `cap`
/// (clamped to [`crate::HARD_MAX_BODY`]).
///
/// # Examples
///
/// ```
/// use syntheke::{Cancel, FrameHeader, HEADER_LEN, PRE_AUTH_MAX_BODY, decode_frame, encode_frame};
///
/// let frame = encode_frame(&Cancel { request_id: 7 }, PRE_AUTH_MAX_BODY)?;
/// let (head, body) = frame.split_at(HEADER_LEN);
/// let head: &[u8; HEADER_LEN] = head.try_into()?;
/// let header = FrameHeader::decode(head, PRE_AUTH_MAX_BODY)?;
/// let cancel: Cancel = decode_frame(&header, body, PRE_AUTH_MAX_BODY)?;
/// assert_eq!(cancel.request_id, 7);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encode_frame<T>(message: &T, cap: u32) -> Result<Vec<u8>, Error>
where
    T: Message + for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>,
{
    let body = encode(message)?;
    let cap = clamp_cap(cap);
    let len = u32::try_from(body.len())
        .ok()
        .filter(|&len| len <= cap)
        .context(FrameTooLargeSnafu {
            len: len_u64(body.len()),
            cap,
        })?;
    let header = FrameHeader::new(T::KIND, len).encode();
    let mut frame = Vec::with_capacity(HEADER_LEN.saturating_add(body.len()));
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Validates and deserializes a message body.
///
/// The length is checked against `cap` (clamped to
/// [`crate::HARD_MAX_BODY`]) before the bytes are copied or read. The body
/// is then copied into an aligned buffer, validated as a whole archive, and
/// deserialized; finally [`Message::check`] runs.
///
/// # Errors
///
/// [`Error::FrameTooLarge`] for an over-bound body, [`Error::InvalidArchive`]
/// for a body that is corrupt, truncated, or of another type, or the
/// message's [`Message::check`] error.
pub fn decode<T>(body: &[u8], cap: u32) -> Result<T, Error>
where
    T: Message + Archive,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + Deserialize<T, HighDeserializer<rancor::Error>>,
{
    let cap = clamp_cap(cap);
    ensure!(
        within(body.len(), cap),
        FrameTooLargeSnafu {
            len: len_u64(body.len()),
            cap
        }
    );
    let mut aligned = AlignedVec::<16>::with_capacity(body.len());
    aligned.extend_from_slice(body);
    let archived =
        rkyv::access::<T::Archived, rancor::Error>(&aligned).context(InvalidArchiveSnafu)?;
    let message = rkyv::deserialize::<T, rancor::Error>(archived).context(InvalidArchiveSnafu)?;
    message.check()?;
    Ok(message)
}

/// Decodes the body of a frame whose header was already validated.
///
/// # Errors
///
/// [`Error::UnexpectedFrameKind`] when the header's kind is not `T`'s,
/// [`Error::BodyLengthMismatch`] when `body` is not the declared length, or
/// any [`decode`] error.
pub fn decode_frame<T>(header: &FrameHeader, body: &[u8], cap: u32) -> Result<T, Error>
where
    T: Message + Archive,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + Deserialize<T, HighDeserializer<rancor::Error>>,
{
    ensure!(
        header.kind() == T::KIND,
        UnexpectedFrameKindSnafu {
            expected: T::KIND,
            found: header.kind()
        }
    );
    ensure!(
        usize::try_from(header.len()).is_ok_and(|declared| declared == body.len()),
        BodyLengthMismatchSnafu {
            declared: header.len(),
            actual: len_u64(body.len())
        }
    );
    decode(body, cap)
}
