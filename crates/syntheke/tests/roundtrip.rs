//! Round-trip, corruption, and truncation checks for every wire message.

// NOTE: clippy's tests_outside_test_module (denied workspace-wide) also
// applies to integration test crates, hence the module wrapper.
#[cfg(test)]
mod tests {
    use rkyv::api::high::{HighDeserializer, HighSerializer, HighValidator};
    use rkyv::bytecheck::CheckBytes;
    use rkyv::rancor;
    use rkyv::ser::allocator::ArenaHandle;
    use rkyv::util::AlignedVec;
    use syntheke::{
        Admitted, ArtifactRef, AuditPage, AuditQueryRequest, AuditRecord, AuditScope, AuditSeq,
        Auth, Cancel, Capability, CaptureLimits, CaptureOutcome, CaptureRequest, Ceilings,
        ClientHello, Cost, DEFAULT_MAX_BODY, DenyCode, Dimension, EgressPolicy, Error,
        ExtractionClass, Failure, Fault, FrameHeader, FrameKind, GrantId, GrantIssueRequest,
        GrantIssued, GrantRevokeRequest, GrantRevoked, HEADER_LEN, IdempotencyKey, IngestReceipt,
        IngestRequest, InvocationId, InvocationState, Message, Mode, Nonce, OutcomeKind,
        PRE_AUTH_MAX_BODY, Plan, QueryPage, QueryRequest, ReadChunk, ReadRequest, Request,
        RequestBody, Response, ResponseBody, ServerHello, SessionForkRequest, SessionId,
        SessionOpened, SessionScope, SourceRef, TenantId, Timestamp, TransferClass, VersionChoice,
        decode, decode_frame, encode, encode_frame,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn id(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    /// Encodes a full frame, then decodes header and body as a receiver would.
    fn round_trip<T>(message: &T, cap: u32) -> Result<T, Error>
    where
        T: Message
            + rkyv::Archive
            + for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>,
        T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
            + rkyv::Deserialize<T, HighDeserializer<rancor::Error>>,
    {
        let frame = encode_frame(message, cap)?;
        let (head, body) = frame.split_at(HEADER_LEN);
        let head: [u8; HEADER_LEN] = head.try_into().unwrap_or([0; HEADER_LEN]);
        let header = FrameHeader::decode(&head, cap)?;
        assert_eq!(header.kind(), T::KIND, "header names the message kind");
        decode_frame(&header, body, cap)
    }

    fn key(tag: u8) -> Result<IdempotencyKey, Error> {
        IdempotencyKey::new(vec![tag; 16])
    }

    fn every_request_body() -> Vec<RequestBody> {
        vec![
            RequestBody::SessionCreate,
            RequestBody::SessionFork(SessionForkRequest {
                parent_session: SessionId::from_bytes(id(1)),
            }),
            RequestBody::Capture(CaptureRequest {
                session: SessionId::from_bytes(id(1)),
                target: "https://example.com/article".to_owned(),
                limits: CaptureLimits {
                    max_output_bytes: Some(32_768),
                    max_transfer_bytes: Some(1_048_576),
                },
                egress_policy: Some(EgressPolicy {
                    bytes: b"allow 192.0.2.0/24".to_vec(),
                }),
            }),
            RequestBody::Ingest(IngestRequest {
                artifact_ref: ArtifactRef::from_bytes(id(2)),
            }),
            RequestBody::Read(ReadRequest {
                artifact_ref: ArtifactRef::from_bytes(id(2)),
                offset: 4096,
                len: 4096,
            }),
            RequestBody::Query(QueryRequest {
                session_scope: Some(SessionId::from_bytes(id(1))),
                predicate: "artifact.origin = example.com".to_owned(),
                limit: 50,
            }),
            RequestBody::GrantIssue(GrantIssueRequest {
                holder: TenantId::from_bytes(id(4)),
                capabilities: vec![Capability::Capture, Capability::Read],
                session_scope: SessionScope::Sessions(vec![SessionId::from_bytes(id(1))]),
                target_scope: vec!["example.com".to_owned()],
                ceilings: Ceilings {
                    fetches: Some(10),
                    bytes_transferred: Some(524_288),
                    ..Ceilings::default()
                },
                not_before: Timestamp::from_unix_millis(0),
                expires_at: Timestamp::from_unix_millis(1_792_886_400_000),
                max_depth: Some(2),
            }),
            RequestBody::GrantRevoke(GrantRevokeRequest {
                target_grant: GrantId::from_bytes(id(3)),
            }),
            RequestBody::AuditQuery(AuditQueryRequest {
                audit_scope: AuditScope::OwnAndOwnedSessions,
                session: None,
                after: Some(AuditSeq::new(41)),
                limit: 100,
            }),
        ]
    }

    fn every_failure() -> Vec<Failure> {
        let mut failures = vec![
            Failure::ProtocolError,
            Failure::AuthFailed,
            Failure::NotFoundOrDenied,
            Failure::ProducerUnavailable,
            Failure::DeadlineExceeded,
            Failure::Cancelled,
            Failure::UnknownEffect,
            Failure::IdempotencyConflict,
        ];
        failures.extend(DenyCode::ALL.iter().map(|&code| Failure::Denied { code }));
        failures.extend(
            Dimension::ALL
                .iter()
                .map(|&dimension| Failure::BudgetExceeded { dimension }),
        );
        failures.extend(
            TransferClass::ALL
                .iter()
                .map(|&class| Failure::TransferFailed { class }),
        );
        failures.extend(
            ExtractionClass::ALL
                .iter()
                .map(|&class| Failure::ExtractionFailed { class }),
        );
        failures
    }

    fn capture_outcome() -> CaptureOutcome {
        CaptureOutcome {
            artifact_ref: ArtifactRef::from_bytes(id(2)),
            source: SourceRef {
                fingerprint: "fp-0a".to_owned(),
                schema_id: "zetesis.evidence.v1".to_owned(),
                producer_revision: "0".repeat(40),
            },
            text_view: Some("Synthetic article text.".to_owned()),
            truncated: false,
            output_bytes: 23,
            revoked_after_effect: false,
        }
    }

    fn every_response_body() -> Vec<ResponseBody> {
        let mut bodies = vec![
            ResponseBody::SessionOpened(SessionOpened {
                session: SessionId::from_bytes(id(5)),
                owner: TenantId::from_bytes(id(4)),
                parent_session: Some(SessionId::from_bytes(id(1))),
            }),
            ResponseBody::Captured(capture_outcome()),
            ResponseBody::Ingested(IngestReceipt {
                artifact_ref: ArtifactRef::from_bytes(id(2)),
            }),
            ResponseBody::Chunk(ReadChunk {
                offset: 0,
                bytes: vec![0x3c; 64],
                total_len: 64,
            }),
            ResponseBody::QueryPage(QueryPage {
                result_refs: vec![ArtifactRef::from_bytes(id(2))],
                more: false,
            }),
            ResponseBody::GrantIssued(GrantIssued {
                grant: GrantId::from_bytes(id(6)),
                parent_grant: GrantId::from_bytes(id(3)),
            }),
            ResponseBody::GrantRevoked(GrantRevoked {
                revoked_grant: GrantId::from_bytes(id(3)),
                effect_sequence: AuditSeq::new(42),
                effect_time: Timestamp::from_unix_millis(1_790_294_400_000),
            }),
            ResponseBody::AuditPage(AuditPage {
                scope_applied: AuditScope::All,
                records: vec![AuditRecord {
                    seq: AuditSeq::new(42),
                    time: Timestamp::from_unix_millis(1_790_294_400_000),
                    tenant: TenantId::from_bytes(id(4)),
                    session: Some(SessionId::from_bytes(id(1))),
                    invocation: InvocationId::from_bytes(id(7)),
                    capability: Capability::Capture,
                    state: InvocationState::Settled,
                    outcome: OutcomeKind::Success,
                }],
                next_after: None,
            }),
            ResponseBody::Plan(Plan {
                capability: Capability::Capture,
                cost: Cost {
                    fetches: 1,
                    output_bytes: 32_768,
                    ..Cost::default()
                },
                grant_chain: vec![GrantId::from_bytes(id(6)), GrantId::from_bytes(id(3))],
                rule_chain: Vec::new(),
                refusal: Some(Failure::Denied {
                    code: DenyCode::ScopeViolation,
                }),
            }),
            ResponseBody::InProgress,
        ];
        bodies.extend(every_failure().into_iter().map(ResponseBody::Failed));
        bodies
    }

    #[test]
    fn handshake_messages_round_trip() -> TestResult {
        let hello = ClientHello {
            version_min: 1,
            version_max: 1,
            tenant: TenantId::from_bytes(id(4)),
            client_nonce: Nonce::from_bytes(id(8)),
        };
        assert_eq!(
            round_trip(&hello, PRE_AUTH_MAX_BODY)?,
            hello,
            "client hello"
        );
        for version in [VersionChoice::Chosen(1), VersionChoice::Incompatible] {
            let reply = ServerHello {
                version,
                server_nonce: Nonce::from_bytes(id(9)),
                max_frame: DEFAULT_MAX_BODY,
            };
            assert_eq!(round_trip(&reply, PRE_AUTH_MAX_BODY)?, reply, "{version:?}");
        }
        let auth = Auth {
            signature: [0xab; 64],
        };
        assert_eq!(round_trip(&auth, PRE_AUTH_MAX_BODY)?, auth, "auth");
        assert_eq!(
            round_trip(&Admitted, PRE_AUTH_MAX_BODY)?,
            Admitted,
            "admitted"
        );
        Ok(())
    }

    #[test]
    fn every_request_body_round_trips_in_both_modes() -> TestResult {
        for (index, body) in every_request_body().into_iter().enumerate() {
            for mode in Mode::ALL.iter().copied() {
                let request = Request {
                    request_id: u64::try_from(index)?,
                    grant: GrantId::from_bytes(id(3)),
                    idempotency_key: Some(key(0x5a)?),
                    mode,
                    deadline_ms: 30_000,
                    body: body.clone(),
                };
                let decoded = round_trip(&request, DEFAULT_MAX_BODY)?;
                assert_eq!(decoded, request, "{:?} {mode}", body.capability());
            }
        }
        Ok(())
    }

    #[test]
    fn request_bodies_name_each_capability_once() {
        let capabilities: Vec<Capability> = every_request_body()
            .iter()
            .map(RequestBody::capability)
            .collect();
        assert_eq!(
            capabilities.as_slice(),
            Capability::ALL,
            "one body per capability, in contract order"
        );
    }

    #[test]
    fn every_response_body_round_trips() -> TestResult {
        for body in every_response_body() {
            let response = Response {
                request_id: 3,
                invocation: Some(InvocationId::from_bytes(id(7))),
                body,
            };
            let decoded = round_trip(&response, DEFAULT_MAX_BODY)?;
            assert_eq!(decoded, response, "{:?}", response.body.outcome());
        }
        Ok(())
    }

    #[test]
    fn cancel_and_fault_round_trip() -> TestResult {
        let cancel = Cancel { request_id: 77 };
        assert_eq!(round_trip(&cancel, DEFAULT_MAX_BODY)?, cancel, "cancel");
        for failure in every_failure() {
            let fault = Fault { failure };
            if matches!(failure, Failure::ProtocolError | Failure::AuthFailed) {
                assert_eq!(round_trip(&fault, DEFAULT_MAX_BODY)?, fault, "{failure:?}");
                continue;
            }
            let encoded = encode(&fault);
            assert!(
                matches!(encoded, Err(Error::FaultNotConnectionLevel { kind, .. }) if kind == failure.kind()),
                "{failure:?} is not sent as a fault, got {encoded:?}"
            );
            let raw = rkyv::to_bytes::<rancor::Error>(&fault)?;
            let decoded = decode::<Fault>(&raw, DEFAULT_MAX_BODY);
            assert!(
                matches!(decoded, Err(Error::FaultNotConnectionLevel { .. })),
                "{failure:?} in a fault frame is refused on receipt, got {decoded:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn outcome_kinds_cover_every_reply() {
        let mut seen: Vec<OutcomeKind> = every_response_body()
            .iter()
            .map(ResponseBody::outcome)
            .collect();
        seen.sort();
        seen.dedup();
        assert_eq!(
            seen.as_slice(),
            OutcomeKind::ALL,
            "every outcome kind is reachable"
        );
    }

    #[test]
    fn corrupted_bodies_fail_validation() -> TestResult {
        let response = Response {
            request_id: 3,
            invocation: None,
            body: ResponseBody::Captured(capture_outcome()),
        };
        let body = encode(&response)?;
        let saturated = vec![0xff_u8; body.len()];
        let result = decode::<Response>(&saturated, DEFAULT_MAX_BODY);
        assert!(
            matches!(result, Err(Error::InvalidArchive { .. })),
            "all-ones body, got {result:?}"
        );

        // A Fault archive is its one-byte failure tag plus variant payload;
        // tag 0xff names no Failure variant.
        let mut fault = encode(&Fault {
            failure: Failure::ProtocolError,
        })?
        .to_vec();
        fault.fill(0xff);
        let result = decode::<Fault>(&fault, DEFAULT_MAX_BODY);
        assert!(
            matches!(result, Err(Error::InvalidArchive { .. })),
            "invalid enum tag, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn corrupted_string_bytes_fail_utf8_validation() -> TestResult {
        let request = Request {
            request_id: 1,
            grant: GrantId::from_bytes(id(3)),
            idempotency_key: None,
            mode: Mode::Execute,
            deadline_ms: 1,
            body: RequestBody::Query(QueryRequest {
                session_scope: None,
                predicate: "predicate-over-example-com".to_owned(),
                limit: 1,
            }),
        };
        let mut body = encode(&request)?.to_vec();
        let needle = b"predicate-over-example-com";
        let start = body
            .windows(needle.len())
            .position(|window| window == needle)
            .ok_or("predicate bytes not found in archive")?;
        if let Some(byte) = body.get_mut(start) {
            *byte = 0xc0;
        }
        let result = decode::<Request>(&body, DEFAULT_MAX_BODY);
        assert!(
            matches!(result, Err(Error::InvalidArchive { .. })),
            "invalid UTF-8 inside a string, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn every_truncation_is_rejected() -> TestResult {
        let request = Request {
            request_id: 1,
            grant: GrantId::from_bytes(id(3)),
            idempotency_key: Some(key(1)?),
            mode: Mode::Execute,
            deadline_ms: 1,
            body: every_request_body()
                .into_iter()
                .nth(2)
                .ok_or("capture body")?,
        };
        let body = encode(&request)?;
        for cut in 0..body.len() {
            let prefix = body.get(..cut).ok_or("prefix")?;
            let result = decode::<Request>(prefix, DEFAULT_MAX_BODY);
            assert!(result.is_err(), "a {cut}-byte prefix must be rejected");
        }
        Ok(())
    }

    #[derive(Debug)]
    struct Refused;

    impl core::fmt::Display for Refused {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("serializer refused")
        }
    }

    impl std::error::Error for Refused {}

    /// A message whose serializer always fails, to reach `Error::Encode`.
    #[derive(rkyv::Archive)]
    struct Unserializable;

    impl<S> rkyv::Serialize<S> for Unserializable
    where
        S: rancor::Fallible + ?Sized,
        S::Error: rancor::Source,
    {
        fn serialize(&self, _serializer: &mut S) -> Result<Self::Resolver, S::Error> {
            Err(<S::Error as rancor::Source>::new(Refused))
        }
    }

    impl Message for Unserializable {
        const KIND: FrameKind = FrameKind::Cancel;
    }

    #[test]
    fn encode_reports_serializer_failure() {
        let result = encode(&Unserializable);
        assert!(
            matches!(result, Err(Error::Encode { .. })),
            "got {result:?}"
        );
        let framed = encode_frame(&Unserializable, DEFAULT_MAX_BODY);
        assert!(
            matches!(framed, Err(Error::Encode { .. })),
            "got {framed:?}"
        );
    }

    #[test]
    fn errors_display_without_panicking() {
        let errors = [
            "x".parse::<TenantId>().err().map(|e| e.to_string()),
            IdempotencyKey::new(Vec::new()).err().map(|e| e.to_string()),
        ];
        for text in errors {
            assert!(
                text.is_some_and(|t| !t.is_empty()),
                "every error has a message"
            );
        }
    }
}
