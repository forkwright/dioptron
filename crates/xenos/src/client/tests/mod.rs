//! Client tests against a scripted peer that frames with syntheke.
//!
//! `handshake` covers the handshake and a hostile server during it;
//! `admitted` covers requests, cancels, and responses once admitted.

use std::os::unix::net::UnixStream;
use std::time::Duration;

use syntheke::{
    ArtifactRef, CaptureLimits, CaptureRequest, GrantId, IdempotencyKey, Mode, ReadRequest,
    Request, RequestBody, Response, ResponseBody, SessionId,
};

use super::*;
use crate::test_support::{LONG, TENANT, signing_key};

mod admitted;
mod handshake;

fn timeouts(bound: Duration) -> Timeouts {
    Timeouts {
        handshake: bound,
        frame: bound,
    }
}

fn connect(stream: UnixStream) -> Result<Client, Error> {
    Client::handshake(stream, TENANT, &signing_key(), 1..=1, timeouts(LONG))
}

fn read_request(request_id: u64) -> Request {
    Request {
        request_id,
        grant: GrantId::from_bytes([0x22; 16]),
        idempotency_key: None,
        mode: Mode::Execute,
        deadline_ms: 30_000,
        body: RequestBody::Read(ReadRequest {
            artifact_ref: ArtifactRef::from_bytes([7; 16]),
            offset: 0,
            len: 4096,
        }),
    }
}

fn capture_request(request_id: u64, target: String, key: Option<IdempotencyKey>) -> Request {
    Request {
        request_id,
        grant: GrantId::from_bytes([0x22; 16]),
        idempotency_key: key,
        mode: Mode::Execute,
        deadline_ms: 30_000,
        body: RequestBody::Capture(CaptureRequest {
            session: SessionId::from_bytes([3; 16]),
            target,
            limits: CaptureLimits::default(),
            egress_policy: None,
        }),
    }
}

fn reply(request_id: u64, body: ResponseBody) -> Response {
    Response {
        request_id,
        invocation: None,
        body,
    }
}
