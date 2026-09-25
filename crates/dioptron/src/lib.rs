//! The Dioptron daemon library.
//!
//! `dioptron` will orchestrate invocations: authorize through `epitrope`,
//! persist each lifecycle boundary through `phylake`, call a producer
//! through the producer seam, and serve the capability contract from
//! `syntheke` over a local Unix socket with peer-bound tenant
//! authentication. Web acquisition itself belongs to the producer; this
//! crate contains no HTTP, DNS, or extraction code.
//!
//! This crate is a skeleton until its implementation slices land.
#![deny(missing_docs)]
