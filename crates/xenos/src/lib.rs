//! Independent client for the Dioptron wire protocol.
//!
//! `xenos` will speak the protocol with its own blocking framing and
//! handshake code, linking only the `syntheke` contract, so that
//! process-level acceptance tests exercise the daemon binary from outside
//! rather than through the daemon's own implementation.
//!
//! This crate is a skeleton until its implementation slice lands.
#![deny(missing_docs)]
