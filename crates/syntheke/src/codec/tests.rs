use super::*;
use crate::ids::{GrantId, IdempotencyKey, SessionId, TenantId};
use crate::payload::{QueryRequest, RequestBody};
use crate::vocab::Mode;
use crate::wire::{
    Admitted, Auth, Cancel, ClientHello, DEFAULT_MAX_BODY, Fault, Nonce, Request, ServerHello,
    VersionChoice,
};
use crate::{Failure, PRE_AUTH_MAX_BODY};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A request whose archive holds an out-of-line string, so the root
/// reaches its field bytes through a relative pointer.
fn query_request() -> Result<Request, Error> {
    Ok(Request {
        request_id: 11,
        grant: GrantId::from_bytes([3; 16]),
        idempotency_key: Some(IdempotencyKey::new(vec![0x5a; 16])?),
        mode: Mode::Execute,
        deadline_ms: 30_000,
        body: RequestBody::Query(QueryRequest {
            session_scope: Some(SessionId::from_bytes([1; 16])),
            predicate: "artifact.origin = example.com".to_owned(),
            limit: 50,
        }),
    })
}

fn is_non_canonical<T>(result: &Result<T, Error>, len: usize, canonical_len: usize) -> bool {
    matches!(
        result,
        Err(Error::NonCanonical { len: l, canonical_len: c, .. })
            if Ok(*l) == u64::try_from(len) && Ok(*c) == u64::try_from(canonical_len)
    )
}

#[test]
fn decode_rejects_bytes_in_a_zero_sized_body() {
    let result = decode::<Admitted>(&[1, 2, 3, 4], PRE_AUTH_MAX_BODY);
    assert!(is_non_canonical(&result, 4, 0), "got {result:?}");
}

#[test]
fn decode_rejects_leading_junk() -> TestResult {
    let canonical = encode(&Cancel { request_id: 7 })?;
    let mut body = vec![0xee_u8; 8];
    body.extend_from_slice(&canonical);
    let result = decode::<Cancel>(&body, PRE_AUTH_MAX_BODY);
    assert!(
        is_non_canonical(&result, 16, canonical.len()),
        "got {result:?}"
    );
    Ok(())
}

#[test]
fn decode_rejects_leading_junk_before_relative_pointers() -> TestResult {
    let request = query_request()?;
    let canonical = encode(&request)?;
    // 16 bytes keep every subobject at its original alignment, so relative
    // pointers still resolve and the validator accepts the archive.
    let mut body = vec![0_u8; 16];
    body.extend_from_slice(&canonical);
    let result = decode::<Request>(&body, DEFAULT_MAX_BODY);
    assert!(
        is_non_canonical(&result, body.len(), canonical.len()),
        "got {result:?}"
    );
    Ok(())
}

#[test]
fn decode_rejects_trailing_junk() -> TestResult {
    let canonical = encode(&Cancel { request_id: 7 })?;
    let mut body = canonical.to_vec();
    body.extend_from_slice(&[0_u8; 8]);
    let result = decode::<Cancel>(&body, PRE_AUTH_MAX_BODY);
    assert!(
        is_non_canonical(&result, 16, canonical.len()),
        "got {result:?}"
    );
    Ok(())
}

#[test]
fn decode_rejects_empty_body_for_sized_type() {
    let result = decode::<Cancel>(&[], PRE_AUTH_MAX_BODY);
    assert!(
        matches!(result, Err(Error::InvalidArchive { .. })),
        "got {result:?}"
    );
}

#[test]
fn decode_accepts_empty_body_for_zero_sized_type() -> TestResult {
    assert!(
        encode(&Admitted)?.is_empty(),
        "admitted encodes to no bytes"
    );
    assert_eq!(decode::<Admitted>(&[], PRE_AUTH_MAX_BODY)?, Admitted);
    Ok(())
}

#[test]
fn decode_accepts_canonical_encoding_of_each_message() -> TestResult {
    fn same<T>(message: &T) -> Result<bool, Error>
    where
        T: Message
            + PartialEq
            + Archive
            + for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>,
        T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
            + Deserialize<T, HighDeserializer<rancor::Error>>,
    {
        let body = encode(message)?;
        Ok(decode::<T>(&body, DEFAULT_MAX_BODY)? == *message)
    }
    let hello = ClientHello {
        version_min: 1,
        version_max: 1,
        tenant: TenantId::from_bytes([4; 16]),
        client_nonce: Nonce::from_bytes([8; 16]),
    };
    let reply = ServerHello {
        version: VersionChoice::Chosen(1),
        server_nonce: Nonce::from_bytes([9; 16]),
        max_frame: DEFAULT_MAX_BODY,
    };
    assert!(same(&hello)?, "client hello");
    assert!(same(&reply)?, "server hello");
    assert!(
        same(&Auth {
            signature: [0xab; 64]
        })?,
        "auth"
    );
    assert!(same(&Admitted)?, "admitted");
    assert!(same(&query_request()?)?, "request");
    assert!(same(&Cancel { request_id: 7 })?, "cancel");
    let fault = Fault {
        failure: Failure::ProtocolError,
    };
    assert!(same(&fault)?, "fault");
    Ok(())
}

#[test]
fn encoding_is_deterministic() -> TestResult {
    // Two independently built equal values, so no allocation is shared.
    let first = encode(&query_request()?)?;
    let second = encode(&query_request()?)?;
    assert_eq!(
        first.as_slice(),
        second.as_slice(),
        "same value, same bytes"
    );
    Ok(())
}

#[test]
fn non_canonical_error_displays_both_lengths() {
    let result = decode::<Admitted>(&[1, 2, 3, 4], PRE_AUTH_MAX_BODY);
    let text = result.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        text.contains("4 bytes") && text.contains("canonical 0-byte"),
        "got {text:?}"
    );
}
