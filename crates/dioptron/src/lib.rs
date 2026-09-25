//! The Dioptron daemon library.
//!
//! `dioptron` will orchestrate invocations: authorize through `epitrope`,
//! persist each lifecycle boundary through `phylake`, call a producer
//! through the producer seam, and serve the capability contract from
//! `syntheke` over a local Unix socket with peer-bound tenant
//! authentication. Web acquisition itself belongs to the producer; this
//! crate contains no HTTP, DNS, or extraction code.
//!
//! Implemented so far:
//!
//! - [`server`]: the Unix socket server. It owns framing, bounds, the
//!   handshake, peer binding, per-connection request tracking,
//!   cancellation, deadlines, and graceful shutdown. It reaches the rest of
//!   the daemon through two seams: [`server::TenantDirectory`] (who may
//!   authenticate) and [`server::Dispatcher`] (what an admitted request
//!   does).
//! - [`CancelSignal`]: the cancellation signal the server hands each
//!   dispatched request, which the lifecycle passes on to the producer.
#![deny(missing_docs)]

mod cancel;
mod error;
pub mod server;

pub use cancel::{CancelHandle, CancelSignal, cancel_pair};
pub use error::Error;
