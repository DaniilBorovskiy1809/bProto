//! Error type for the whole core.

/// Result alias used across the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong in the protocol core.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("datagram too short: {got} bytes, need at least {need}")]
    ShortDatagram { got: usize, need: usize },

    #[error("unsupported protocol version {0}")]
    BadVersion(u8),

    #[error("authenticated decryption failed")]
    Decrypt,

    #[error("replayed packet number {0}")]
    Replay(u64),

    #[error("bad session_id label")]
    BadLabel,

    #[error("bad inner frame type {0}")]
    BadInnerType(u8),

    #[error("bad control frame type {0}")]
    BadFrameType(u8),

    #[error("handshake timed out")]
    HandshakeTimeout,

    #[error("session not found")]
    NoSession,

    #[error("payload exceeds tunnel MTU: {0} > {1}")]
    PayloadTooLarge(usize, usize),

    #[error("handshake failed: {0}")]
    Handshake(&'static str),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("not implemented yet: {0}")]
    Unimplemented(&'static str),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
