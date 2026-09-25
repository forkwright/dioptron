//! Server tests. They run on the real clock over real Unix sockets.
//!
//! A timer never fires early, so each timeout test asserts only that its
//! bound had passed when the effect arrived, plus a generous upper slack
//! for a loaded machine. Paused tokio time is not used: its auto-advance
//! moves the clock whenever every task waits, which here includes waits on
//! socket I/O, so server timers fired before the peer's bytes arrived.

mod framing;
mod handshake;
mod requests;
mod server;
