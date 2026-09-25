use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn display_parse_round_trips_boundary_values() -> TestResult {
    for bytes in [[0_u8; 16], [0xff_u8; 16], *b"0123456789abcdef"] {
        let id = SessionId::from_bytes(bytes);
        let parsed: SessionId = id.to_string().parse()?;
        assert_eq!(parsed, id, "display then parse must be the identity");
    }
    Ok(())
}

#[test]
fn display_matches_known_ulid_values() {
    assert_eq!(
        TenantId::from_bytes([0; 16]).to_string(),
        "00000000000000000000000000",
        "all-zero bytes are all-zero digits"
    );
    assert_eq!(
        TenantId::from_bytes([0xff; 16]).to_string(),
        "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "the 128-bit maximum is the largest ULID"
    );
    assert_eq!(
        GrantId::from_bytes(1_u128.to_be_bytes()).to_string(),
        "00000000000000000000000001",
        "the least significant digit carries the low five bits"
    );
}

#[test]
fn parse_accepts_lowercase_and_uppercase_alike() -> TestResult {
    let lower: ArtifactRef = "01j8k7r3v9zq4n5m6p7s8art0a".parse()?;
    let upper: ArtifactRef = "01J8K7R3V9ZQ4N5M6P7S8ART0A".parse()?;
    assert_eq!(lower, upper, "ULID parsing is case-insensitive");
    assert_eq!(
        lower.to_string(),
        "01J8K7R3V9ZQ4N5M6P7S8ART0A",
        "display is uppercase"
    );
    Ok(())
}

#[test]
fn debug_names_the_type_and_ulid() {
    let id = InvocationId::from_bytes([0; 16]);
    assert_eq!(
        format!("{id:?}"),
        "InvocationId(00000000000000000000000000)",
        "debug output names the type"
    );
}

#[test]
fn parse_rejects_wrong_length() {
    for text in [
        "",
        "0000000000000000000000000",
        "000000000000000000000000000",
    ] {
        let result = text.parse::<ReservationId>();
        assert!(
            matches!(result, Err(Error::UlidLength { len, .. }) if len == text.len()),
            "length {} must be rejected, got {result:?}",
            text.len()
        );
    }
}

#[test]
fn parse_rejects_characters_outside_crockford() {
    for (text, bad) in [
        ("0000000000000000000000000I", 25),
        ("000000000000L0000000000000", 12),
        ("0O000000000000000000000000", 1),
        ("0000000000000000000000000U", 25),
        ("00000000000000000000000-00", 23),
        // 24 digits plus a two-byte character: 26 bytes, bad at byte 24.
        ("000000000000000000000000\u{e9}", 24),
    ] {
        let result = text.parse::<TenantId>();
        assert!(
            matches!(result, Err(Error::UlidCharacter { position, .. }) if position == bad),
            "{text:?} must be rejected at {bad}, got {result:?}"
        );
    }
}

#[test]
fn parse_rejects_values_above_128_bits() {
    let result = "80000000000000000000000000".parse::<TenantId>();
    assert!(
        matches!(result, Err(Error::UlidOverflow { .. })),
        "a leading digit above 7 overflows 128 bits, got {result:?}"
    );
}

#[test]
fn idempotency_key_accepts_bounds_inclusive() -> TestResult {
    for len in [IdempotencyKey::MIN_LEN, 32, IdempotencyKey::MAX_LEN] {
        let key = IdempotencyKey::new(vec![0xa5; len])?;
        assert_eq!(key.as_bytes().len(), len, "key keeps its bytes");
        key.check()?;
    }
    Ok(())
}

#[test]
fn idempotency_key_rejects_out_of_bounds_lengths() {
    for len in [0, IdempotencyKey::MIN_LEN - 1, IdempotencyKey::MAX_LEN + 1] {
        let owned = IdempotencyKey::new(vec![1; len]);
        let borrowed = IdempotencyKey::from_slice(&vec![1; len]);
        for result in [owned, borrowed] {
            assert!(
                matches!(result, Err(Error::IdempotencyKeyLength { len: got, .. }) if got == len),
                "length {len} must be rejected, got {result:?}"
            );
        }
    }
}

#[test]
fn scalar_wrappers_round_trip_their_values() {
    assert_eq!(AuditSeq::new(42).get(), 42, "sequence is preserved");
    assert_eq!(
        Timestamp::from_unix_millis(-1).unix_millis(),
        -1,
        "timestamps before the epoch are preserved"
    );
}
