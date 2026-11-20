//! Bounded gRPC wire primitives. These do not implement a BuildKit session.

use std::fmt;

/// Absolute limit on a single uncompressed message, irrespective of caller limits.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// A wire failure. Peer-provided text is never included in diagnostic output.
#[derive(Clone, PartialEq, Eq)]
pub enum GrpcError {
    /// A message exceeds the configured or absolute limit.
    Oversized,
    /// The provided bytes do not contain a complete message.
    Truncated,
    /// Compression is not supported.
    UnexpectedCompression,
    /// The status or message trailer is invalid or missing.
    MalformedTrailer,
    /// A nonzero gRPC status. The optional decoded message is accessible explicitly.
    Status {
        /// Numeric gRPC status code.
        code: u32,
        /// Decoded peer message. Treat as potentially sensitive.
        message: Option<String>,
    },
}

impl fmt::Debug for GrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversized => f.write_str("Oversized"),
            Self::Truncated => f.write_str("Truncated"),
            Self::UnexpectedCompression => f.write_str("UnexpectedCompression"),
            Self::MalformedTrailer => f.write_str("MalformedTrailer"),
            Self::Status { code, .. } => f
                .debug_struct("Status")
                .field("code", code)
                .finish_non_exhaustive(),
        }
    }
}
impl fmt::Display for GrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gRPC wire error: {self:?}")
    }
}
impl std::error::Error for GrpcError {}

/// Encodes an uncompressed message, enforcing both limits.
///
/// # Errors
/// Returns an error for compression or an oversized message.
pub fn encode_message(flag: u8, payload: &[u8], max: usize) -> Result<Vec<u8>, GrpcError> {
    if flag != 0 {
        return Err(GrpcError::UnexpectedCompression);
    }
    if payload.len() > max.min(MAX_MESSAGE_BYTES) {
        return Err(GrpcError::Oversized);
    }
    let len = u32::try_from(payload.len()).map_err(|_| GrpcError::Oversized)?;
    let mut result = Vec::with_capacity(5 + payload.len());
    result.push(flag);
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(payload);
    Ok(result)
}

/// Decodes one message without copying, returning the flag, payload and consumed bytes.
///
/// # Errors
/// Returns an error for compression, truncation or an oversized message.
pub fn decode_message(input: &[u8], max: usize) -> Result<(u8, &[u8], usize), GrpcError> {
    if input.len() < 5 {
        return Err(GrpcError::Truncated);
    }
    if input[0] != 0 {
        return Err(GrpcError::UnexpectedCompression);
    }
    let len = u32::from_be_bytes([input[1], input[2], input[3], input[4]]) as usize;
    if len > max.min(MAX_MESSAGE_BYTES) {
        return Err(GrpcError::Oversized);
    }
    let end = 5 + len;
    if input.len() < end {
        return Err(GrpcError::Truncated);
    }
    Ok((0, &input[5..end], end))
}

/// Parses gRPC trailers, rejecting missing, invalid and nonzero status.
///
/// The optional message is percent-decoded, bounded, and only exposed in the
/// returned status error; diagnostic formatting never prints it.
///
/// # Errors
/// Returns an error for malformed trailers or nonzero gRPC status.
pub fn parse_status(status: Option<&str>, message: Option<&str>) -> Result<(), GrpcError> {
    let status = status.ok_or(GrpcError::MalformedTrailer)?;
    if status.is_empty() || !status.bytes().all(|b| b.is_ascii_digit()) {
        return Err(GrpcError::MalformedTrailer);
    }
    let code: u32 = status.parse().map_err(|_| GrpcError::MalformedTrailer)?;
    let message = message.map(decode_trailer_message).transpose()?;
    if code != 0 {
        return Err(GrpcError::Status { code, message });
    }
    Ok(())
}

fn decode_trailer_message(message: &str) -> Result<String, GrpcError> {
    if message.len() > 8192 {
        return Err(GrpcError::MalformedTrailer);
    }
    let bytes = message.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(GrpcError::MalformedTrailer);
            }
            let digit = |b: u8| (b as char).to_digit(16).ok_or(GrpcError::MalformedTrailer);
            decoded.push(
                u8::try_from(digit(bytes[i + 1])? * 16 + digit(bytes[i + 2])?)
                    .map_err(|_| GrpcError::MalformedTrailer)?,
            );
            i += 3;
        } else {
            if !(0x20..=0x7e).contains(&bytes[i]) {
                return Err(GrpcError::MalformedTrailer);
            }
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| GrpcError::MalformedTrailer)
}
