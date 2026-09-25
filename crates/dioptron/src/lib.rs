//! The Dioptron daemon library.
//!
//! `dioptron` orchestrates invocations: it authorizes through `epitrope`,
//! persists each lifecycle boundary through `phylake`, calls a producer
//! through the producer seam, and serves the capability contract from
//! `syntheke` over a local Unix socket with peer-bound tenant
//! authentication. Web acquisition itself belongs to the producer; this
//! crate contains no HTTP, DNS, or extraction code.
//!
//! - [`server`]: the Unix socket server. It owns framing, bounds, the
//!   handshake, peer binding, per-connection request tracking,
//!   cancellation, deadlines, and graceful shutdown. It reaches the rest of
//!   the daemon through two seams: [`server::TenantDirectory`] (who may
//!   authenticate) and [`server::Dispatcher`] (what an admitted request
//!   does).
//! - [`Orchestrator`]: the dispatcher. It runs each request against the
//!   custody store under the request's designated grant, and each capture
//!   through the invocation lifecycle B1 to B5.
//! - [`Producer`]: the producer seam, with [`UnavailableProducer`] (the
//!   default: never fetches) and [`FixtureProducer`] (scripted, for tests).
//! - [`StoreTenants`]: the handshake's tenant directory over the store.
//! - [`cli`]: the `dioptron` command line.
//! - [`CancelSignal`]: the cancellation signal the server hands each
//!   dispatched request, which the lifecycle passes on to the producer.
#![deny(missing_docs)]

mod cancel;
pub mod cli;
mod clock;
mod error;
#[cfg(feature = "failpoints")]
pub mod failpoint;
mod fixture;
mod orchestrator;
mod producer;
pub mod server;
mod tenants;

pub use cancel::{CancelHandle, CancelSignal, cancel_pair};
#[cfg(feature = "test-clock")]
pub use clock::FileClock;
pub use clock::{SystemClock, daemon_clock};
pub use error::Error;
pub use fixture::{FixtureProducer, Script};
pub use orchestrator::{Drain, Orchestrator};
pub use producer::{AcquireRequest, Producer, ProducerError, ProducerOutput, UnavailableProducer};
pub use tenants::StoreTenants;
