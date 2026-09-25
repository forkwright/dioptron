//! Wire protocol: constants, frame header codec, handshake and request
//! frames, and the authentication transcript (contract § Wire protocol).

use snafu::{OptionExt as _, ensure};

use crate::codec::Message;
use crate::error::{
    BadMagicSnafu, DeniedAxisMismatchSnafu, Error, FaultNotConnectionLevelSnafu,
    FrameTooLargeSnafu, InvalidVersionRangeSnafu, MaxFrameOutOfRangeSnafu,
    MissingIdempotencyKeySnafu, NonzeroReservedSnafu, PredicateTooLongSnafu, UnknownFlagsSnafu,
    UnknownFrameKindSnafu,
};
use crate::ids::{GrantId, IdempotencyKey, InvocationId, TenantId};
use crate::outcome::Failure;
use crate::payload::{MAX_QUERY_PREDICATE_LEN, RequestBody, ResponseBody};
use crate::vocab::Mode;

/// Version of the capability contract this crate implements.
pub const CONTRACT_VERSION: u16 = 1;

/// Wire protocol version this crate speaks.
pub const WIRE_VERSION: u16 = 1;

/// The four bytes every frame starts with.
pub const MAGIC: [u8; 4] = *b"DPT1";

/// Length of the frame header in bytes: magic 4, kind 1, flags 1,
/// reserved 2, body length 4.
pub const HEADER_LEN: usize = 12;

/// Body bound before the handshake completes: 4 KiB.
pub const PRE_AUTH_MAX_BODY: u32 = 4 * 1024;

/// Default negotiated body bound: 1 MiB.
pub const DEFAULT_MAX_BODY: u32 = 1024 * 1024;

/// Hard body ceiling no negotiation may exceed: 4 MiB. Every bound passed to
/// this crate is clamped to it.
pub const HARD_MAX_BODY: u32 = 4 * 1024 * 1024;

/// Time allowed for the whole handshake, in milliseconds.
pub const HANDSHAKE_TIMEOUT_MS: u32 = 5_000;

/// Fixed label at the start of the authentication transcript.
pub const AUTH_LABEL: [u8; 16] = *b"dioptron-auth-v1";

/// Length of a handshake nonce in bytes.
pub const NONCE_LEN: usize = 16;

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Length of [`auth_transcript`]'s output: label 16, version 2, tenant 16,
/// client nonce 16, server nonce 16.
pub const AUTH_TRANSCRIPT_LEN: usize = 66;

/// Clamps a caller-supplied body bound to [`HARD_MAX_BODY`].
pub(crate) const fn clamp_cap(cap: u32) -> u32 {
    if cap > HARD_MAX_BODY {
        HARD_MAX_BODY
    } else {
        cap
    }
}

/// The kind byte of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FrameKind {
    /// Client to server: [`ClientHello`].
    ClientHello,
    /// Server to client: [`ServerHello`].
    ServerHello,
    /// Client to server: [`Auth`].
    Auth,
    /// Server to client: [`Admitted`].
    Admitted,
    /// Client to server: [`Request`].
    Request,
    /// Client to server: [`Cancel`].
    Cancel,
    /// Server to client: [`Response`].
    Response,
    /// Server to client: [`Fault`].
    Fault,
}

impl FrameKind {
    /// Every kind this wire version defines.
    pub const ALL: &'static [Self] = &[
        Self::ClientHello,
        Self::ServerHello,
        Self::Auth,
        Self::Admitted,
        Self::Request,
        Self::Cancel,
        Self::Response,
        Self::Fault,
    ];

    /// The kind byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::ClientHello => 1,
            Self::ServerHello => 2,
            Self::Auth => 3,
            Self::Admitted => 4,
            Self::Request => 5,
            Self::Cancel => 6,
            Self::Response => 7,
            Self::Fault => 8,
        }
    }

    /// Parses a kind byte; `None` for a byte this version does not define.
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            3 => Some(Self::Auth),
            4 => Some(Self::Admitted),
            5 => Some(Self::Request),
            6 => Some(Self::Cancel),
            7 => Some(Self::Response),
            8 => Some(Self::Fault),
            _ => None,
        }
    }

    /// The kind's name, as the fixtures' `frame` key spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClientHello => "ClientHello",
            Self::ServerHello => "ServerHello",
            Self::Auth => "Auth",
            Self::Admitted => "Admitted",
            Self::Request => "Request",
            Self::Cancel => "Cancel",
            Self::Response => "Response",
            Self::Fault => "Fault",
        }
    }

    /// Parses a kind name; `None` for a name this version does not define.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.name() == name)
    }
}

/// The flags byte of a frame header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// Flag bits this wire version defines. Version 1 defines none, so any
    /// set bit is rejected.
    pub const KNOWN: u8 = 0;

    /// No flags set.
    pub const NONE: Self = Self(0);

    /// The raw flags byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// A validated 12-byte frame header.
///
/// # Examples
///
/// ```
/// use syntheke::{FrameHeader, FrameKind, PRE_AUTH_MAX_BODY};
///
/// let header = FrameHeader::new(FrameKind::Cancel, 24);
/// let bytes = header.encode();
/// assert_eq!(&bytes[..4], b"DPT1");
/// assert_eq!(FrameHeader::decode(&bytes, PRE_AUTH_MAX_BODY)?, header);
///
/// // A declared length above the bound is refused from the header alone,
/// // before any body buffer exists.
/// let oversized = FrameHeader::new(FrameKind::Request, PRE_AUTH_MAX_BODY + 1).encode();
/// assert!(FrameHeader::decode(&oversized, PRE_AUTH_MAX_BODY).is_err());
/// # Ok::<(), syntheke::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameHeader {
    kind: FrameKind,
    flags: FrameFlags,
    len: u32,
}

impl FrameHeader {
    /// A header for a body of `len` bytes with no flags set.
    #[must_use]
    pub const fn new(kind: FrameKind, len: u32) -> Self {
        Self {
            kind,
            flags: FrameFlags::NONE,
            len,
        }
    }

    /// The frame kind.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }

    /// The flags.
    #[must_use]
    pub const fn flags(&self) -> FrameFlags {
        self.flags
    }

    /// The body length in bytes.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether the body is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The 12 header bytes.
    #[must_use]
    pub const fn encode(&self) -> [u8; HEADER_LEN] {
        let [m0, m1, m2, m3] = MAGIC;
        let [l0, l1, l2, l3] = self.len.to_le_bytes();
        [
            m0,
            m1,
            m2,
            m3,
            self.kind.to_u8(),
            self.flags.bits(),
            0,
            0,
            l0,
            l1,
            l2,
            l3,
        ]
    }

    /// Validates 12 header bytes against a body bound.
    ///
    /// The declared length is checked here, from the header alone, so a
    /// caller that decodes the header before allocating never allocates for
    /// an oversized frame. `cap` is clamped to [`HARD_MAX_BODY`].
    ///
    /// # Errors
    ///
    /// [`Error::BadMagic`], [`Error::UnknownFrameKind`],
    /// [`Error::UnknownFlags`], [`Error::NonzeroReserved`], or
    /// [`Error::FrameTooLarge`], checked in that order.
    pub fn decode(bytes: &[u8; HEADER_LEN], cap: u32) -> Result<Self, Error> {
        let [m0, m1, m2, m3, kind, flags, r0, r1, l0, l1, l2, l3] = *bytes;
        let found = [m0, m1, m2, m3];
        ensure!(found == MAGIC, BadMagicSnafu { found });
        let kind = FrameKind::from_u8(kind).context(UnknownFrameKindSnafu { kind })?;
        ensure!(flags & !FrameFlags::KNOWN == 0, UnknownFlagsSnafu { flags });
        let reserved = u16::from_le_bytes([r0, r1]);
        ensure!(reserved == 0, NonzeroReservedSnafu { reserved });
        let len = u32::from_le_bytes([l0, l1, l2, l3]);
        let cap = clamp_cap(cap);
        ensure!(
            len <= cap,
            FrameTooLargeSnafu {
                len: u64::from(len),
                cap
            }
        );
        Ok(Self {
            kind,
            flags: FrameFlags(flags),
            len,
        })
    }
}

/// A 16-byte handshake nonce.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Wraps 16 bytes. The caller supplies fresh randomness.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// The nonce bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; NONCE_LEN] {
        self.0
    }
}

/// Client hello: the first frame of a connection.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct ClientHello {
    /// Lowest wire version the client speaks.
    pub version_min: u16,
    /// Highest wire version the client speaks.
    pub version_max: u16,
    /// The tenant the client will authenticate as.
    pub tenant: TenantId,
    /// Fresh client nonce.
    pub client_nonce: Nonce,
}

impl Message for ClientHello {
    const KIND: FrameKind = FrameKind::ClientHello;

    fn check(&self) -> Result<(), Error> {
        ensure!(
            self.version_min <= self.version_max,
            InvalidVersionRangeSnafu {
                min: self.version_min,
                max: self.version_max
            }
        );
        Ok(())
    }
}

/// The server's version decision.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[non_exhaustive]
pub enum VersionChoice {
    /// The version both sides will speak.
    Chosen(u16),
    /// No version in common; the handshake ends before authentication.
    Incompatible,
}

/// Picks the highest version both ranges contain.
///
/// # Examples
///
/// ```
/// use syntheke::{VersionChoice, negotiate_version};
///
/// assert_eq!(negotiate_version(1, 3, 2, 5), VersionChoice::Chosen(3));
/// assert_eq!(negotiate_version(99, 99, 1, 1), VersionChoice::Incompatible);
/// ```
#[must_use]
pub const fn negotiate_version(
    client_min: u16,
    client_max: u16,
    server_min: u16,
    server_max: u16,
) -> VersionChoice {
    let low = if client_min > server_min {
        client_min
    } else {
        server_min
    };
    let high = if client_max < server_max {
        client_max
    } else {
        server_max
    };
    if low <= high {
        VersionChoice::Chosen(high)
    } else {
        VersionChoice::Incompatible
    }
}

/// Server hello: the version decision, server nonce, and body bound.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct ServerHello {
    /// The chosen version, or `Incompatible`.
    pub version: VersionChoice,
    /// Fresh server nonce.
    pub server_nonce: Nonce,
    /// Negotiated body bound for the rest of the connection, within
    /// [`PRE_AUTH_MAX_BODY`]`..=`[`HARD_MAX_BODY`] even when the version is
    /// `Incompatible`.
    pub max_frame: u32,
}

impl Message for ServerHello {
    const KIND: FrameKind = FrameKind::ServerHello;

    fn check(&self) -> Result<(), Error> {
        ensure!(
            (PRE_AUTH_MAX_BODY..=HARD_MAX_BODY).contains(&self.max_frame),
            MaxFrameOutOfRangeSnafu {
                max_frame: self.max_frame
            }
        );
        Ok(())
    }
}

/// Auth: an Ed25519 signature over [`auth_transcript`].
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Auth {
    /// The signature bytes.
    pub signature: [u8; SIGNATURE_LEN],
}

impl Message for Auth {
    const KIND: FrameKind = FrameKind::Auth;
}

/// Admitted: the server accepted the signature and the peer binding.
/// Requests are accepted only after this frame.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Admitted;

impl Message for Admitted {
    const KIND: FrameKind = FrameKind::Admitted;
}

/// A capability request. The connection's admitted tenant is the actor;
/// requests carry no tenant field. Each request names the one grant it acts
/// under, and the daemon authorizes against that grant's chain only
/// (contract § Grant designation).
#[derive(Clone, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Request {
    /// Caller-chosen id, unique among the connection's in-flight requests.
    pub request_id: u64,
    /// The grant this request acts under, in execute and dry-run mode
    /// alike. It must be held by the connection's tenant; the daemon never
    /// falls back to another grant the tenant holds.
    pub grant: GrantId,
    /// Required on an executed state-changing request; see
    /// [`crate::Capability::is_state_changing`].
    pub idempotency_key: Option<IdempotencyKey>,
    /// Execute or dry-run.
    pub mode: Mode,
    /// Relative deadline in milliseconds; the server clamps it and converts
    /// it to its monotonic clock on receipt.
    pub deadline_ms: u32,
    /// The capability-specific body.
    pub body: RequestBody,
}

impl Message for Request {
    const KIND: FrameKind = FrameKind::Request;

    /// Refuses an idempotency key outside 16 to 64 bytes, a missing key
    /// on an executed state-changing request, and a `Query` predicate
    /// above [`MAX_QUERY_PREDICATE_LEN`] bytes.
    fn check(&self) -> Result<(), Error> {
        let capability = self.body.capability();
        match &self.idempotency_key {
            Some(key) => key.check()?,
            None => ensure!(
                self.mode == Mode::DryRun || !capability.is_state_changing(),
                MissingIdempotencyKeySnafu { capability }
            ),
        }
        if let RequestBody::Query(query) = &self.body {
            let len = query.predicate.len();
            ensure!(
                len <= MAX_QUERY_PREDICATE_LEN,
                PredicateTooLongSnafu {
                    len,
                    max: MAX_QUERY_PREDICATE_LEN
                }
            );
        }
        Ok(())
    }
}

/// Cancel: signal cancellation of an in-flight request.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Cancel {
    /// The request to cancel.
    pub request_id: u64,
}

impl Message for Cancel {
    const KIND: FrameKind = FrameKind::Cancel;
}

/// The reply to one request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Response {
    /// The request this answers.
    pub request_id: u64,
    /// The invocation the request created or replayed; `None` for a dry-run
    /// and for every refusal, including one whose `Denied` audit entry was
    /// written, so a refusal's bytes never depend on what it persisted.
    pub invocation: Option<InvocationId>,
    /// The reply.
    pub body: ResponseBody,
}

impl Message for Response {
    const KIND: FrameKind = FrameKind::Response;

    /// Refuses a failure, in the reply or in a plan's refusal, whose
    /// narrowing axis does not match its deny code
    /// ([`Failure::is_well_formed`]).
    fn check(&self) -> Result<(), Error> {
        let failure = match &self.body {
            ResponseBody::Failed(failure) => Some(*failure),
            ResponseBody::Plan(plan) => plan.refusal,
            _ => None,
        };
        if let Some(failure) = failure {
            ensure!(failure.is_well_formed(), DeniedAxisMismatchSnafu);
        }
        Ok(())
    }
}

/// Fault: a connection-level failure (`ProtocolError` or `AuthFailed`)
/// sent once before the server closes the connection.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Fault {
    /// The failure: [`Failure::ProtocolError`] or [`Failure::AuthFailed`].
    pub failure: Failure,
}

impl Message for Fault {
    const KIND: FrameKind = FrameKind::Fault;

    /// Refuses every failure except the two connection-level kinds; any
    /// other failure answers one request and travels in a [`Response`].
    fn check(&self) -> Result<(), Error> {
        ensure!(
            matches!(self.failure, Failure::ProtocolError | Failure::AuthFailed),
            FaultNotConnectionLevelSnafu {
                kind: self.failure.kind()
            }
        );
        Ok(())
    }
}

/// The bytes an authenticating tenant signs:
/// `"dioptron-auth-v1" ‖ version (u16 LE) ‖ tenant ‖ client nonce ‖ server nonce`.
///
/// Server and clients share this one definition of the signed bytes; each
/// brings its own Ed25519 implementation.
///
/// # Examples
///
/// ```
/// use syntheke::{AUTH_TRANSCRIPT_LEN, Nonce, TenantId, auth_transcript};
///
/// let tenant: TenantId = "01j8k7r3v9zq4n5m6p7s8tnt0b".parse()?;
/// let bytes = auth_transcript(
///     1,
///     tenant,
///     &Nonce::from_bytes([1; 16]),
///     &Nonce::from_bytes([2; 16]),
/// );
/// assert_eq!(bytes.len(), AUTH_TRANSCRIPT_LEN);
/// assert_eq!(&bytes[..16], b"dioptron-auth-v1");
/// # Ok::<(), syntheke::Error>(())
/// ```
#[must_use]
pub fn auth_transcript(
    version: u16,
    tenant: TenantId,
    client_nonce: &Nonce,
    server_nonce: &Nonce,
) -> [u8; AUTH_TRANSCRIPT_LEN] {
    let version = version.to_le_bytes();
    let tenant = tenant.to_bytes();
    let parts: [&[u8]; 5] = [
        &AUTH_LABEL,
        &version,
        &tenant,
        &client_nonce.0,
        &server_nonce.0,
    ];
    let mut out = [0_u8; AUTH_TRANSCRIPT_LEN];
    // INVARIANT: the parts total AUTH_TRANSCRIPT_LEN bytes (16 + 2 + 16 +
    // 16 + 16), asserted by the transcript_layout test, so zip fills every
    // byte and drops none.
    for (slot, byte) in out.iter_mut().zip(parts.into_iter().flatten()) {
        *slot = *byte;
    }
    out
}

#[cfg(test)]
mod tests;
