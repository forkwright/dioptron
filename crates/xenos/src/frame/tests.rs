#![expect(
    clippy::expect_used,
    reason = "tests abort loudly on a failed setup step"
)]

use syntheke::{Admitted, Cancel, DEFAULT_MAX_BODY, FrameHeader, PRE_AUTH_MAX_BODY, ServerHello};

use super::*;

/// The category of a header rejection, shared by both implementations.
fn category_ours(result: &Result<(FrameKind, u32), Error>) -> String {
    match result {
        Ok((kind, len)) => format!("ok {kind:?} {len}"),
        Err(Error::BadMagic { found, .. }) => format!("magic {found:?}"),
        Err(Error::UnknownFrameKind { kind, .. }) => format!("kind {kind}"),
        Err(Error::UnknownFlags { flags, .. }) => format!("flags {flags}"),
        Err(Error::NonzeroReserved { reserved, .. }) => format!("reserved {reserved}"),
        Err(Error::FrameTooLarge { len, cap, .. }) => format!("large {len} {cap}"),
        Err(other) => format!("unexpected {other:?}"),
    }
}

fn category_syntheke(result: &Result<FrameHeader, syntheke::Error>) -> String {
    match result {
        Ok(header) => format!("ok {:?} {}", header.kind(), header.len()),
        Err(syntheke::Error::BadMagic { found, .. }) => format!("magic {found:?}"),
        Err(syntheke::Error::UnknownFrameKind { kind, .. }) => format!("kind {kind}"),
        Err(syntheke::Error::UnknownFlags { flags, .. }) => format!("flags {flags}"),
        Err(syntheke::Error::NonzeroReserved { reserved, .. }) => format!("reserved {reserved}"),
        Err(syntheke::Error::FrameTooLarge { len, cap, .. }) => format!("large {len} {cap}"),
        Err(other) => format!("unexpected {other:?}"),
    }
}

#[test]
fn header_bytes_match_syntheke_for_every_kind() {
    for &kind in FrameKind::ALL {
        for len in [0, 1, PRE_AUTH_MAX_BODY, 0x0102_0304] {
            assert_eq!(
                header_bytes(kind.to_u8(), 0, 0, len),
                FrameHeader::new(kind, len).encode(),
                "{kind:?} len {len}"
            );
        }
    }
    assert_eq!(
        header_bytes(7, 0x80, 0xbeef, 0x0102_0304),
        [
            b'D', b'P', b'T', b'1', 7, 0x80, 0xef, 0xbe, 0x04, 0x03, 0x02, 0x01
        ],
        "documented layout: magic, kind, flags, reserved LE, length LE"
    );
}

#[test]
fn parse_header_agrees_with_syntheke_on_every_input_class() {
    let caps = [
        0,
        PRE_AUTH_MAX_BODY,
        DEFAULT_MAX_BODY,
        HARD_MAX_BODY,
        u32::MAX,
    ];
    let mut checked = 0_u32;
    for cap in caps {
        for kind in 0..=u8::MAX {
            for flags in [0_u8, 0x01, 0x02, 0x40, 0x80, 0xff] {
                for reserved in [0_u16, 1, 0x0100, u16::MAX] {
                    for len in [
                        0,
                        1,
                        cap,
                        cap.saturating_add(1),
                        HARD_MAX_BODY + 1,
                        u32::MAX,
                    ] {
                        let bytes = header_bytes(kind, flags, reserved, len);
                        assert_eq!(
                            category_ours(&parse_header(&bytes, cap)),
                            category_syntheke(&FrameHeader::decode(&bytes, cap)),
                            "kind {kind} flags {flags} reserved {reserved} len {len} cap {cap}"
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    for magic in [*b"DPT0", *b"dpt1", [0; 4], *b"XPT1"] {
        let mut bytes = header_bytes(1, 0, 0, 0);
        bytes[..4].copy_from_slice(&magic);
        assert_eq!(
            category_ours(&parse_header(&bytes, PRE_AUTH_MAX_BODY)),
            category_syntheke(&FrameHeader::decode(&bytes, PRE_AUTH_MAX_BODY)),
            "magic {magic:?}"
        );
    }
    assert!(checked > 100_000, "matrix covered {checked} headers");
}

#[test]
fn parse_header_clamps_the_bound_to_the_hard_maximum() {
    let result = parse_header(&header_bytes(7, 0, 0, HARD_MAX_BODY + 1), u32::MAX);
    assert!(
        matches!(result, Err(Error::FrameTooLarge { cap, .. }) if cap == HARD_MAX_BODY),
        "got {result:?}"
    );
    let at_max = parse_header(&header_bytes(7, 0, 0, HARD_MAX_BODY), u32::MAX);
    assert!(
        matches!(at_max, Ok((FrameKind::Response, len)) if len == HARD_MAX_BODY),
        "got {at_max:?}"
    );
}

#[test]
fn frame_bytes_match_syntheke_encode_frame() {
    let cancel = Cancel { request_id: 7 };
    assert_eq!(
        frame_bytes(&cancel, PRE_AUTH_MAX_BODY).expect("ours"),
        syntheke::encode_frame(&cancel, PRE_AUTH_MAX_BODY).expect("syntheke"),
        "identical frame bytes"
    );
    let result = frame_bytes(&cancel, 1);
    assert!(
        matches!(result, Err(Error::FrameTooLarge { cap: 1, .. })),
        "got {result:?}"
    );
}

#[test]
fn frame_decode_checks_the_kind_and_maps_faults() {
    let admitted = Frame {
        kind: FrameKind::Admitted,
        body: Admitted.encode_body().expect("encode"),
    };
    let result = admitted.decode::<ServerHello>(PRE_AUTH_MAX_BODY);
    assert!(
        matches!(
            result,
            Err(Error::UnexpectedFrame {
                expected: FrameKind::ServerHello,
                found: FrameKind::Admitted,
                ..
            })
        ),
        "got {result:?}"
    );
    assert_eq!(admitted.kind(), FrameKind::Admitted, "kind accessor");
    assert_eq!(
        admitted.body(),
        Admitted.encode_body().expect("encode").as_slice(),
        "body accessor"
    );

    let fault = Frame {
        kind: FrameKind::Fault,
        body: Fault {
            failure: Failure::AuthFailed,
        }
        .encode_body()
        .expect("encode"),
    };
    let result = fault.decode::<Admitted>(PRE_AUTH_MAX_BODY);
    assert!(
        matches!(result, Err(Error::AuthFailed { .. })),
        "got {result:?}"
    );
    let as_fault = fault
        .decode::<Fault>(PRE_AUTH_MAX_BODY)
        .expect("fault decodes as itself");
    assert_eq!(as_fault.failure, Failure::AuthFailed, "fault body");
}
