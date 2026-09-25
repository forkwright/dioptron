use super::*;
use crate::codec::{decode, decode_frame, encode, encode_frame};
use crate::payload::ReadRequest;
use crate::vocab::Capability;
use crate::{ArtifactRef, Failure};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn header_bytes(kind: u8, flags: u8, reserved: u16, len: u32) -> [u8; HEADER_LEN] {
    let [r0, r1] = reserved.to_le_bytes();
    let [l0, l1, l2, l3] = len.to_le_bytes();
    [b'D', b'P', b'T', b'1', kind, flags, r0, r1, l0, l1, l2, l3]
}

fn read_request(key: Option<IdempotencyKey>, mode: Mode) -> Request {
    Request {
        request_id: 9,
        grant: GrantId::from_bytes([3; 16]),
        idempotency_key: key,
        mode,
        deadline_ms: 30_000,
        body: RequestBody::Read(ReadRequest {
            artifact_ref: ArtifactRef::from_bytes([7; 16]),
            offset: 0,
            len: 4096,
        }),
    }
}

#[test]
fn constants_match_the_contract() {
    assert_eq!(&MAGIC, b"DPT1", "magic");
    assert_eq!(HEADER_LEN, 4 + 1 + 1 + 2 + 4, "header layout");
    assert_eq!(PRE_AUTH_MAX_BODY, 4096, "pre-auth cap is 4 KiB");
    assert_eq!(
        DEFAULT_MAX_BODY, 1_048_576,
        "default negotiated cap is 1 MiB"
    );
    assert_eq!(HARD_MAX_BODY, 4_194_304, "hard cap is 4 MiB");
    assert_eq!(
        HANDSHAKE_TIMEOUT_MS, 5_000,
        "handshake completes within 5 s"
    );
    assert_eq!(&AUTH_LABEL, b"dioptron-auth-v1", "auth label");
}

#[test]
fn encode_writes_the_documented_layout() {
    let bytes = FrameHeader::new(FrameKind::Response, 0x0102_0304).encode();
    assert_eq!(
        bytes,
        [b'D', b'P', b'T', b'1', 7, 0, 0, 0, 0x04, 0x03, 0x02, 0x01],
        "magic, kind, flags, reserved, little-endian length"
    );
}

#[test]
fn decode_round_trips_every_kind() -> TestResult {
    for &kind in FrameKind::ALL {
        assert_eq!(FrameKind::from_u8(kind.to_u8()), Some(kind), "kind byte");
        assert_eq!(FrameKind::from_name(kind.name()), Some(kind), "kind name");
        let header = FrameHeader::new(kind, PRE_AUTH_MAX_BODY);
        let decoded = FrameHeader::decode(&header.encode(), PRE_AUTH_MAX_BODY)?;
        assert_eq!(decoded, header, "{kind:?} header round-trips");
        assert_eq!(decoded.flags(), FrameFlags::NONE, "no flags");
        assert!(!decoded.is_empty(), "non-empty body");
    }
    assert_eq!(FrameKind::from_name("Hello"), None, "unknown name");
    Ok(())
}

#[test]
fn decode_rejects_bad_magic() {
    let mut bytes = header_bytes(1, 0, 0, 0);
    bytes[3] = b'2';
    let result = FrameHeader::decode(&bytes, PRE_AUTH_MAX_BODY);
    assert!(
        matches!(result, Err(Error::BadMagic { found, .. }) if &found == b"DPT2"),
        "got {result:?}"
    );
}

#[test]
fn decode_rejects_unknown_kind() {
    for kind in [0_u8, 9, 0xff] {
        let result = FrameHeader::decode(&header_bytes(kind, 0, 0, 0), PRE_AUTH_MAX_BODY);
        assert!(
            matches!(result, Err(Error::UnknownFrameKind { kind: got, .. }) if got == kind),
            "kind {kind} must be rejected, got {result:?}"
        );
    }
}

#[test]
fn decode_rejects_every_unknown_flag_bit() {
    for bit in 0..8 {
        let flags = 1_u8 << bit;
        let result = FrameHeader::decode(&header_bytes(5, flags, 0, 0), PRE_AUTH_MAX_BODY);
        assert!(
            matches!(result, Err(Error::UnknownFlags { flags: got, .. }) if got == flags),
            "flag bit {bit} must be rejected, got {result:?}"
        );
    }
}

#[test]
fn decode_rejects_nonzero_reserved() {
    for reserved in [1_u16, 0x8000] {
        let result = FrameHeader::decode(&header_bytes(5, 0, reserved, 0), PRE_AUTH_MAX_BODY);
        assert!(
            matches!(result, Err(Error::NonzeroReserved { reserved: got, .. }) if got == reserved),
            "reserved {reserved} must be rejected, got {result:?}"
        );
    }
}

#[test]
fn decode_rejects_length_above_cap_from_header_alone() -> TestResult {
    // The fixture's 8 MiB declaration is refused from 12 bytes: no body
    // buffer exists for the check to consult, so none was allocated.
    let bytes = header_bytes(5, 0, 0, 8_388_608);
    let result = FrameHeader::decode(&bytes, DEFAULT_MAX_BODY);
    assert!(
        matches!(
            result,
            Err(Error::FrameTooLarge {
                len: 8_388_608,
                cap: DEFAULT_MAX_BODY,
                ..
            })
        ),
        "got {result:?}"
    );
    let at_cap = FrameHeader::decode(&header_bytes(5, 0, 0, PRE_AUTH_MAX_BODY), PRE_AUTH_MAX_BODY)?;
    assert_eq!(
        at_cap.len(),
        PRE_AUTH_MAX_BODY,
        "a body exactly at the cap is accepted"
    );
    let over = FrameHeader::decode(
        &header_bytes(5, 0, 0, PRE_AUTH_MAX_BODY + 1),
        PRE_AUTH_MAX_BODY,
    );
    assert!(
        matches!(over, Err(Error::FrameTooLarge { .. })),
        "one byte over the pre-auth cap is refused, got {over:?}"
    );
    Ok(())
}

#[test]
fn decode_clamps_caps_above_the_hard_maximum() {
    let result = FrameHeader::decode(&header_bytes(5, 0, 0, HARD_MAX_BODY + 1), u32::MAX);
    assert!(
        matches!(
            result,
            Err(Error::FrameTooLarge {
                cap: HARD_MAX_BODY,
                ..
            })
        ),
        "a caller cap above 4 MiB is clamped, got {result:?}"
    );
}

#[test]
fn negotiate_version_picks_the_highest_common_version() {
    assert_eq!(
        negotiate_version(1, 1, 1, 1),
        VersionChoice::Chosen(1),
        "exact"
    );
    assert_eq!(
        negotiate_version(1, 4, 2, 3),
        VersionChoice::Chosen(3),
        "inner"
    );
    assert_eq!(
        negotiate_version(3, 5, 1, 3),
        VersionChoice::Chosen(3),
        "edge"
    );
    assert_eq!(
        negotiate_version(99, 99, 1, 1),
        VersionChoice::Incompatible,
        "above"
    );
    assert_eq!(
        negotiate_version(0, 0, 1, 1),
        VersionChoice::Incompatible,
        "below"
    );
    assert_eq!(
        negotiate_version(2, 1, 1, 2),
        VersionChoice::Incompatible,
        "inverted"
    );
}

#[test]
fn transcript_layout_concatenates_label_version_tenant_and_nonces() {
    let tenant = TenantId::from_bytes([0x11; 16]);
    let client = Nonce::from_bytes([0x22; 16]);
    let server = Nonce::from_bytes([0x33; 16]);
    let bytes = auth_transcript(0x0102, tenant, &client, &server);
    let mut expected = Vec::new();
    expected.extend_from_slice(b"dioptron-auth-v1");
    expected.extend_from_slice(&[0x02, 0x01]);
    expected.extend_from_slice(&[0x11; 16]);
    expected.extend_from_slice(&[0x22; 16]);
    expected.extend_from_slice(&[0x33; 16]);
    assert_eq!(expected.len(), AUTH_TRANSCRIPT_LEN, "declared length");
    assert_eq!(bytes.as_slice(), expected.as_slice(), "transcript bytes");
}

#[test]
fn transcript_differs_when_any_input_differs() {
    let tenant = TenantId::from_bytes([1; 16]);
    let a = Nonce::from_bytes([2; 16]);
    let b = Nonce::from_bytes([3; 16]);
    let base = auth_transcript(1, tenant, &a, &b);
    assert_ne!(base, auth_transcript(2, tenant, &a, &b), "version is bound");
    assert_ne!(
        base,
        auth_transcript(1, TenantId::from_bytes([9; 16]), &a, &b),
        "tenant is bound"
    );
    assert_ne!(
        base,
        auth_transcript(1, tenant, &b, &a),
        "nonce order is bound"
    );
}

#[test]
fn client_hello_check_rejects_inverted_range() -> TestResult {
    let hello = ClientHello {
        version_min: 3,
        version_max: 2,
        tenant: TenantId::from_bytes([1; 16]),
        client_nonce: Nonce::from_bytes([2; 16]),
    };
    let result = encode(&hello);
    assert!(
        matches!(
            result,
            Err(Error::InvalidVersionRange { min: 3, max: 2, .. })
        ),
        "encode refuses, got {result:?}"
    );
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&hello)?;
    let decoded = decode::<ClientHello>(&bytes, PRE_AUTH_MAX_BODY);
    assert!(
        matches!(decoded, Err(Error::InvalidVersionRange { .. })),
        "decode refuses, got {decoded:?}"
    );
    Ok(())
}

#[test]
fn server_hello_check_bounds_max_frame() -> TestResult {
    for max_frame in [0, PRE_AUTH_MAX_BODY - 1, HARD_MAX_BODY + 1] {
        let hello = ServerHello {
            version: VersionChoice::Chosen(1),
            server_nonce: Nonce::from_bytes([4; 16]),
            max_frame,
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&hello)?;
        let result = decode::<ServerHello>(&bytes, PRE_AUTH_MAX_BODY);
        assert!(
            matches!(result, Err(Error::MaxFrameOutOfRange { max_frame: got, .. }) if got == max_frame),
            "max_frame {max_frame} must be rejected, got {result:?}"
        );
    }
    for max_frame in [PRE_AUTH_MAX_BODY, DEFAULT_MAX_BODY, HARD_MAX_BODY] {
        let hello = ServerHello {
            version: VersionChoice::Incompatible,
            server_nonce: Nonce::from_bytes([4; 16]),
            max_frame,
        };
        let decoded: ServerHello = decode(&encode(&hello)?, PRE_AUTH_MAX_BODY)?;
        assert_eq!(decoded, hello, "bound {max_frame} is accepted");
    }
    Ok(())
}

#[test]
fn request_check_requires_a_key_on_executed_state_changes() -> TestResult {
    let mut request = read_request(None, Mode::Execute);
    request.body = RequestBody::SessionCreate;
    let result = encode(&request);
    assert!(
        matches!(
            result,
            Err(Error::MissingIdempotencyKey {
                capability: Capability::SessionCreate,
                ..
            })
        ),
        "got {result:?}"
    );
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&request)?;
    let decoded = decode::<Request>(&bytes, DEFAULT_MAX_BODY);
    assert!(
        matches!(decoded, Err(Error::MissingIdempotencyKey { .. })),
        "decode refuses too, got {decoded:?}"
    );

    request.mode = Mode::DryRun;
    let planned: Request = decode(&encode(&request)?, DEFAULT_MAX_BODY)?;
    assert_eq!(planned, request, "a dry-run needs no key");

    let read = read_request(None, Mode::Execute);
    let decoded: Request = decode(&encode(&read)?, DEFAULT_MAX_BODY)?;
    assert_eq!(decoded, read, "a read changes no state and needs no key");
    Ok(())
}

fn query_request(predicate: String) -> Request {
    let mut request = read_request(None, Mode::Execute);
    request.body = RequestBody::Query(crate::payload::QueryRequest {
        session_scope: Some(crate::SessionId::from_bytes([5; 16])),
        predicate,
        limit: 10,
    });
    request
}

#[test]
fn request_check_bounds_the_query_predicate() -> TestResult {
    let at_bound = query_request("a".repeat(1024));
    let over = query_request("a".repeat(1025));

    let decoded: Request = decode(&encode(&at_bound)?, DEFAULT_MAX_BODY)?;
    assert_eq!(decoded, at_bound, "a 1024-byte predicate is accepted");
    let refused = encode(&over);
    assert!(
        matches!(
            refused,
            Err(Error::PredicateTooLong {
                len: 1025,
                max: 1024,
                ..
            })
        ),
        "a 1025-byte predicate is refused: {refused:?}"
    );
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&over)?;
    let decoded = decode::<Request>(&bytes, DEFAULT_MAX_BODY);
    assert!(
        matches!(decoded, Err(Error::PredicateTooLong { .. })),
        "decode refuses it too: {decoded:?}"
    );
    let mut keyed = query_request("a".repeat(1025));
    keyed.idempotency_key = Some(IdempotencyKey::new(vec![1; 16])?);
    assert!(
        matches!(encode(&keyed), Err(Error::PredicateTooLong { .. })),
        "a key does not skip the predicate bound"
    );
    Ok(())
}

#[test]
fn request_carries_its_designated_grant_in_both_modes() -> TestResult {
    for mode in [Mode::Execute, Mode::DryRun] {
        let request = read_request(None, mode);
        let other = Request {
            grant: GrantId::from_bytes([4; 16]),
            ..request.clone()
        };
        let decoded: Request = decode(&encode(&request)?, DEFAULT_MAX_BODY)?;
        assert_eq!(
            decoded.grant,
            GrantId::from_bytes([3; 16]),
            "{mode}: the designated grant survives the wire"
        );
        assert_ne!(
            encode(&request)?.as_slice(),
            encode(&other)?.as_slice(),
            "{mode}: the grant is part of the encoded request"
        );
    }
    Ok(())
}

#[test]
fn request_decode_rechecks_the_key_length() -> TestResult {
    for len in [0, 15, 65] {
        let request = read_request(Some(IdempotencyKey::unchecked(vec![1; len])), Mode::Execute);
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&request)?;
        let result = decode::<Request>(&bytes, DEFAULT_MAX_BODY);
        assert!(
            matches!(result, Err(Error::IdempotencyKeyLength { len: got, .. }) if got == len),
            "a {len}-byte key on the wire must be rejected, got {result:?}"
        );
    }
    Ok(())
}

#[test]
fn decode_rejects_oversized_body_before_validation() {
    // A zero-filled body would fail validation; FrameTooLarge proves the
    // bound was checked first.
    let body = vec![0_u8; usize::try_from(PRE_AUTH_MAX_BODY + 1).unwrap_or(usize::MAX)];
    let result = decode::<Cancel>(&body, PRE_AUTH_MAX_BODY);
    assert!(
        matches!(
            result,
            Err(Error::FrameTooLarge {
                len: 4097,
                cap: PRE_AUTH_MAX_BODY,
                ..
            })
        ),
        "got {result:?}"
    );
}

#[test]
fn encode_frame_rejects_body_above_cap() -> TestResult {
    let request = read_request(None, Mode::Execute);
    let body_len = encode(&request)?.len();
    let cap = u32::try_from(body_len)? - 1;
    let result = encode_frame(&request, cap);
    assert!(
        matches!(result, Err(Error::FrameTooLarge { cap: got, .. }) if got == cap),
        "got {result:?}"
    );
    Ok(())
}

#[test]
fn decode_frame_rejects_kind_and_length_mismatch() -> TestResult {
    let frame = encode_frame(&Cancel { request_id: 1 }, PRE_AUTH_MAX_BODY)?;
    let (head, body) = frame.split_at(HEADER_LEN);
    let header = FrameHeader::decode(head.try_into()?, PRE_AUTH_MAX_BODY)?;

    let wrong_kind = decode_frame::<Fault>(&header, body, PRE_AUTH_MAX_BODY);
    assert!(
        matches!(
            wrong_kind,
            Err(Error::UnexpectedFrameKind {
                expected: FrameKind::Fault,
                found: FrameKind::Cancel,
                ..
            })
        ),
        "got {wrong_kind:?}"
    );

    let short = body.split_last().map_or(body, |(_, rest)| rest);
    let mismatch = decode_frame::<Cancel>(&header, short, PRE_AUTH_MAX_BODY);
    assert!(
        matches!(mismatch, Err(Error::BodyLengthMismatch { declared, actual, .. })
            if u64::from(declared) == actual + 1),
        "got {mismatch:?}"
    );

    let cancel: Cancel = decode_frame(&header, body, PRE_AUTH_MAX_BODY)?;
    assert_eq!(cancel, Cancel { request_id: 1 }, "matching frame decodes");
    Ok(())
}

#[test]
fn fault_carries_connection_level_failures() -> TestResult {
    for failure in [Failure::ProtocolError, Failure::AuthFailed] {
        let fault = Fault { failure };
        let decoded: Fault = decode(&encode(&fault)?, PRE_AUTH_MAX_BODY)?;
        assert_eq!(decoded, fault, "{failure:?} round-trips");
    }
    Ok(())
}
