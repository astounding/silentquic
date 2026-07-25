// SPDX-License-Identifier: 0BSD
//! Non-blocking outcome types for the sans-IO core.
//!
//! These express the three states a caller-driven API needs — progress,
//! would-block, and end-of-stream — *without* inventing an error taxonomy.
//! [`crate::conn::ConnError`] remains the error type; "no data right now" is an
//! expected, non-fatal outcome, matching the POSIX shape a hand-rolled event
//! loop already reasons in.

use std::net::SocketAddr;

/// One datagram the caller should send.
///
/// The core never touches a socket: it hands back bytes and a destination, and
/// the caller performs the actual `send_to`.
#[derive(Debug, Clone)]
pub struct Transmit {
    pub destination: SocketAddr,
    pub contents: Vec<u8>,
}

/// Outcome of feeding one inbound datagram to the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramOutcome {
    /// The datagram produced no connection for the caller to work with. It was
    /// either rejected by the cloaking pre-filter, or accepted into quinn-proto
    /// without yielding a handle.
    ///
    /// # This is NOT the silence invariant
    ///
    /// The invariant that makes a silentquic server invisible is stated in terms
    /// of the pre-filter, not of this variant:
    ///
    /// > **A datagram that fails the cloaking pre-filter queues nothing to
    /// > send.**
    ///
    /// That is structural rather than a property of the caller's control flow:
    /// [`crate::endpoint::Endpoint::handle_datagram`] returns before the packet
    /// reaches quinn-proto at all, so an embedder that faithfully drains
    /// [`crate::endpoint::Endpoint::poll_transmit`] emits zero bytes in response
    /// to an unauthorized peer, because there is nothing to emit.
    ///
    /// `Dropped` is the wider category, and a datagram that *passed* the
    /// pre-filter can be `Dropped` **and** queue a transmit. The reachable case:
    /// the pre-filter is QUIC-version-agnostic, so a peer holding a valid PSK
    /// can send a well-formed selector DCID with a QUIC version we do not
    /// support; quinn-proto answers with a Version Negotiation packet, which is
    /// queued, and no connection is created, so the outcome is `Dropped`. That
    /// peer proved PSK possession before a single byte was queued, so silence is
    /// intact — but "`Dropped` implies nothing queued" is not.
    ///
    /// If you need "did this datagram cause bytes to be queued?", ask
    /// `poll_transmit`; this enum answers "did it give me a connection?".
    Dropped,
    /// The datagram was admitted and routed to this connection.
    Accepted(quinn_proto::ConnectionHandle),
}

/// Result of a non-blocking stream read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// `n` bytes were copied into the caller's buffer.
    Read(usize),
    /// No data is buffered right now. Try again after a
    /// [`Event::StreamReadable`] for this stream.
    Blocked,
    /// The peer finished the stream (FIN); no more data will arrive.
    Finished,
}

/// Result of a non-blocking stream write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// `n` bytes were accepted — may be fewer than offered.
    Wrote(usize),
    /// Flow control is closed. Try again after a [`Event::StreamWritable`].
    Blocked,
}

/// Something the caller should react to, drained via
/// [`crate::endpoint::Endpoint::poll_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A connection completed its handshake and is ready for streams.
    Connected(quinn_proto::ConnectionHandle),
    /// The peer opened a stream.
    StreamOpened {
        conn: quinn_proto::ConnectionHandle,
        id: quinn_proto::StreamId,
    },
    /// A stream has data buffered; a previously `Blocked` read may now progress.
    StreamReadable {
        conn: quinn_proto::ConnectionHandle,
        id: quinn_proto::StreamId,
    },
    /// Flow control opened; a previously `Blocked` write may now progress.
    StreamWritable {
        conn: quinn_proto::ConnectionHandle,
        id: quinn_proto::StreamId,
    },
    /// The connection is gone.
    ///
    /// # ⚠ `conn` is invalid from this moment on, and may be REUSED
    ///
    /// `ConnectionHandle` is quinn-proto's slab index, and quinn-proto hands a
    /// freed index straight back out to the next connection it accepts. So a
    /// retained handle does not merely go stale — it can start naming a
    /// *different, live* connection, and
    /// [`crate::endpoint::Endpoint::conn_mut`] will return `Some` for it with no
    /// error of any kind.
    ///
    /// Callers that retain handles MUST therefore drain
    /// [`crate::endpoint::Endpoint::poll_event`] and drop every handle named by
    /// a `ConnectionLost` **before** using any retained handle again. Treat this
    /// event as the handle's destructor.
    ///
    /// (The structural fix is a generation counter on the handle; it is a
    /// deliberate follow-up, not implemented here.)
    ConnectionLost {
        conn: quinn_proto::ConnectionHandle,
    },
}
