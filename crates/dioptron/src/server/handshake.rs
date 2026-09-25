//! The pre-authentication handshake (contract § Handshake and version
//! negotiation, § Peer identity binding).
//!
//! Every frame in either direction is bounded by the 4 KiB
//! pre-authentication cap until `Admitted` is sent. Every authentication
//! failure (wrong key, replayed signature, unbound peer uid, unknown
//! tenant, a request or cancel frame before admission) ends in the same
//! `Fault(AuthFailed)` bytes.
//!
//! Once an `Auth` frame arrives, every outcome performs equivalent work in
//! the same order: the directory lookup, one Ed25519 verification (against
//! a per-process dummy key when the tenant is unknown), and the uid check,
//! deciding only after all three. Whether a tenant exists is therefore not
//! told apart by skipped work. The paths perform equivalent work; they are
//! not claimed to run in constant time.

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use syntheke::{
    Admitted, Auth, ClientHello, Failure, FrameKind, Nonce, PRE_AUTH_MAX_BODY, SIGNATURE_LEN,
    ServerHello, TenantId, VersionChoice, WIRE_VERSION, auth_transcript, decode_frame,
    encode_frame, negotiate_version,
};
use tokio::net::UnixStream;

use super::frame::{Frame, ReadFail, read_frame, write_frame};
use super::{Close, Limits, TenantDirectory};

/// Oldest wire version this server speaks.
const SERVER_VERSION_MIN: u16 = WIRE_VERSION;
/// Newest wire version this server speaks.
const SERVER_VERSION_MAX: u16 = WIRE_VERSION;

/// The outcome of a successful handshake.
#[derive(Clone, Copy, Debug)]
pub(super) struct Admission {
    /// The authenticated tenant.
    pub(super) tenant: TenantId,
    /// The negotiated wire version.
    pub(super) version: u16,
}

/// Runs the handshake on `stream` for a peer with user id `uid`. The caller
/// bounds the whole exchange with the handshake timeout.
pub(super) async fn handshake<T: TenantDirectory>(
    stream: &mut UnixStream,
    uid: u32,
    limits: &Limits,
    directory: &T,
    authenticator: &Authenticator,
) -> Result<Admission, Close> {
    let hello = expect(&read(stream, limits).await?, |frame| {
        decode_frame::<ClientHello>(&frame.header, &frame.body, PRE_AUTH_MAX_BODY)
    })?;
    let server_nonce = fresh_nonce()?;
    let choice = negotiate_version(
        hello.version_min,
        hello.version_max,
        SERVER_VERSION_MIN,
        SERVER_VERSION_MAX,
    );
    let server_hello = ServerHello {
        version: choice,
        server_nonce,
        max_frame: limits.max_frame,
    };
    send(
        stream,
        limits,
        encode_frame(&server_hello, PRE_AUTH_MAX_BODY),
    )
    .await?;
    let VersionChoice::Chosen(version) = choice else {
        return Err(Close::Incompatible);
    };
    let auth = expect(&read(stream, limits).await?, |frame| {
        decode_frame::<Auth>(&frame.header, &frame.body, PRE_AUTH_MAX_BODY)
    })?;
    let transcript = auth_transcript(version, hello.tenant, &hello.client_nonce, &server_nonce);
    if !authenticator.authenticate(directory, hello.tenant, uid, &transcript, &auth.signature) {
        return Err(Close::Fault(Failure::AuthFailed, "authentication failed"));
    }
    send(stream, limits, encode_frame(&Admitted, PRE_AUTH_MAX_BODY)).await?;
    Ok(Admission {
        tenant: hello.tenant,
        version,
    })
}

/// Reads one handshake frame under the pre-authentication cap.
async fn read(stream: &mut UnixStream, limits: &Limits) -> Result<Frame, Close> {
    read_frame(stream, PRE_AUTH_MAX_BODY, limits.frame_timeout)
        .await
        .map_err(ReadFail::into_close)
}

/// Decodes a handshake frame with `decode`.
///
/// A `Request` or `Cancel` frame here is a request before authentication,
/// which the contract answers with `AuthFailed`. Any other unexpected kind,
/// or a body that fails validation, is a `ProtocolError`.
fn expect<T>(
    frame: &Frame,
    decode: impl FnOnce(&Frame) -> Result<T, syntheke::Error>,
) -> Result<T, Close> {
    if matches!(frame.header.kind(), FrameKind::Request | FrameKind::Cancel) {
        return Err(Close::Fault(
            Failure::AuthFailed,
            "request before authentication",
        ));
    }
    decode(frame)
        .map_err(|_invalid| Close::Fault(Failure::ProtocolError, "invalid handshake frame"))
}

/// Writes an encoded handshake frame.
async fn send(
    stream: &mut UnixStream,
    limits: &Limits,
    encoded: Result<Vec<u8>, syntheke::Error>,
) -> Result<(), Close> {
    let bytes = encoded.map_err(|_encode| Close::Internal("handshake frame did not encode"))?;
    write_frame(stream, &bytes, limits.frame_timeout)
        .await
        .map_err(Close::Io)
}

/// A fresh server nonce from the OS random source.
fn fresh_nonce() -> Result<Nonce, Close> {
    let mut bytes = [0_u8; syntheke::NONCE_LEN];
    getrandom::fill(&mut bytes).map_err(|_rng| Close::Internal("random source failed"))?;
    Ok(Nonce::from_bytes(bytes))
}

/// Checks an `Auth` signature and the peer's uid binding.
///
/// Holds the dummy verifying key that stands in for an unknown tenant's
/// registered key, so an unknown tenant costs the same verification as a
/// known one.
pub(super) struct Authenticator {
    /// A valid Ed25519 verifying key derived at startup from a random seed
    /// that is then dropped. No party holds its signing key.
    dummy_key: [u8; 32],
    /// Verifications run against the dummy key (test builds only).
    #[cfg(test)]
    dummy_verifications: AtomicUsize,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator").finish_non_exhaustive()
    }
}

impl Authenticator {
    /// Derives the dummy key from a fresh random seed.
    pub(super) fn new() -> Result<Self, getrandom::Error> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed)?;
        Ok(Self {
            dummy_key: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            #[cfg(test)]
            dummy_verifications: AtomicUsize::new(0),
        })
    }

    /// Whether `signature` over `transcript` verifies against the tenant's
    /// registered key and `uid` is bound to the tenant.
    ///
    /// The lookup, one verification, and the uid check always run, in that
    /// order, and combine into one boolean only after all three, so no cause
    /// is distinguishable to the caller. An unknown tenant is verified
    /// against the dummy key with an empty uid set. The replay defence is
    /// the fresh server nonce inside `transcript`: a signature from an
    /// earlier connection signed another nonce.
    pub(super) fn authenticate<T: TenantDirectory>(
        &self,
        directory: &T,
        tenant: TenantId,
        uid: u32,
        transcript: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool {
        let record = directory.lookup(tenant);
        let known = record.is_some();
        let (key, bound_uids) = match &record {
            Some(record) => (&record.verifying_key, record.bound_uids.as_slice()),
            None => (&self.dummy_key, [].as_slice()),
        };
        let signature = Signature::from_bytes(signature);
        let key_ok = VerifyingKey::from_bytes(key)
            .and_then(|key| {
                // NOTE: the key parsed, so the verification below runs.
                #[cfg(test)]
                if !known {
                    self.dummy_verifications.fetch_add(1, Ordering::Relaxed);
                }
                key.verify_strict(transcript, &signature)
            })
            .is_ok();
        let uid_ok = bound_uids.contains(&uid);
        // WHY non-short-circuit `&`: all three checks have run; the verdict
        // is only their combination.
        known & key_ok & uid_ok
    }

    /// Verifications run against the dummy key so far.
    #[cfg(test)]
    pub(super) fn dummy_verifications(&self) -> usize {
        self.dummy_verifications.load(Ordering::Relaxed)
    }
}
