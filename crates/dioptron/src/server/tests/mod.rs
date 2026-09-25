//! Server tests. Timeouts run on paused tokio time, so every duration
//! assertion is exact and no test sleeps on the wall clock.

mod framing;
mod handshake;
mod requests;
mod server;
