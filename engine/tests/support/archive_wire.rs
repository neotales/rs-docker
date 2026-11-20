//! Shared request reading and answer building for the container archive suites.
//!
//! The owned and fallback archive suites observe the same two things: the
//! request the client put on the wire, including the archive upload's chunked
//! body, and the `X-Docker-Container-Path-Stat` header the daemon answers a
//! `HEAD` with. Keeping the reader in one place means the fallback suite cannot
//! quietly accept a different framing or a different base64 alphabet from the
//! one the owned suite asserts.
//!
//! Each suite uses a subset, so unused items are allowed here rather than
//! repeated in both files.
#![allow(dead_code)]
// The module is private to each test binary, so `pub` here means "visible to
// the suite that included it", not an exported item.
#![allow(unreachable_pub)]

use std::io::BufRead;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use neotales_docker::API_VERSION;

/// A recorded request head: the request line and its headers.
pub struct Head {
    /// The request line, without its terminator.
    pub line: String,
    /// The headers, in wire order, with surrounding whitespace trimmed.
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// Returns the request target, such as `/v1.55/containers/web/archive`.
    pub fn target(&self) -> &str {
        self.line.split_whitespace().nth(1).unwrap_or_default()
    }

    /// Returns a header's value, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

/// A recorded request: its head and its decoded body.
pub struct Recorded {
    /// The request head.
    pub head: Head,
    /// The decoded body, empty when the request carried none.
    pub body: Vec<u8>,
}

impl From<Head> for Recorded {
    fn from(head: Head) -> Self {
        Self {
            head,
            body: Vec::new(),
        }
    }
}

impl Recorded {
    /// Returns the request line, without its terminator.
    pub fn line(&self) -> &str {
        &self.head.line
    }

    /// Returns the request target, such as `/v1.55/containers/web/archive`.
    pub fn target(&self) -> &str {
        self.head.target()
    }

    /// Returns the first decoded value of one query parameter.
    pub fn query_value(&self, key: &str) -> Option<String> {
        let (_, query) = self.target().split_once('?')?;
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.into_owned())
    }
}

/// Reads one request head, leaving the body unread.
///
/// The caller must keep using the same reader for the body. A fresh reader over
/// the same socket would lose whatever this one read ahead.
pub fn read_request_head<R: BufRead>(reader: &mut R) -> Head {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read the request line");
    assert!(line.ends_with("\r\n"), "the request line is not terminated");
    let line = line.trim_end().to_owned();

    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .expect("read a request header");
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').expect("a header has a colon");
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    Head { line, headers }
}

/// Reads one HTTP request, decoding a `Content-Length` or chunked body.
pub fn read_request<R: BufRead>(reader: &mut R) -> Recorded {
    let head = read_request_head(reader);
    let chunked = head.header("transfer-encoding").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
    });
    let body = if chunked {
        read_chunked(reader)
    } else {
        let length = head
            .header("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        reader.read_exact(&mut body).expect("read the request body");
        body
    };
    Recorded { head, body }
}

/// Returns a header's value, matched case-insensitively.
pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Decodes an HTTP/1.1 chunked body, including its terminating chunk.
fn read_chunked<R: BufRead>(reader: &mut R) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let mut size = String::new();
        reader.read_line(&mut size).expect("read a chunk size");
        let size = usize::from_str_radix(size.trim(), 16).expect("a hexadecimal chunk size");
        if size == 0 {
            // Consume the trailer section, which ends with a blank line.
            loop {
                let mut trailer = String::new();
                reader.read_line(&mut trailer).expect("read a trailer");
                if trailer.trim_end().is_empty() {
                    break;
                }
            }
            return body;
        }
        let mut chunk = vec![0_u8; size];
        reader.read_exact(&mut chunk).expect("read a chunk");
        body.extend_from_slice(&chunk);
        let mut terminator = [0_u8; 2];
        reader
            .read_exact(&mut terminator)
            .expect("read the chunk terminator");
        assert_eq!(&terminator, b"\r\n", "the chunk is not terminated");
    }
}

/// The version prefix the owned transport is expected to send.
pub fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// Encodes one path-stat JSON document the way the daemon does.
pub fn stat_header(document: &str) -> String {
    BASE64.encode(document)
}

/// A `200` answer to the archive `HEAD`, optionally carrying the stat header.
pub fn stat_response(header: Option<&str>) -> Vec<u8> {
    let header = header.map_or_else(String::new, |value| {
        format!("X-Docker-Container-Path-Stat: {value}\r\n")
    });
    format!("HTTP/1.1 200 OK\r\n{header}Connection: close\r\nContent-Length: 0\r\n\r\n")
        .into_bytes()
}

/// A `200` chunked archive answer with the given chunks.
pub fn archive_response(chunks: &[&[u8]]) -> Vec<u8> {
    let mut response = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for chunk in chunks {
        response.extend_from_slice(format!("{:X}\r\n", chunk.len()).as_bytes());
        response.extend_from_slice(chunk);
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"0\r\n\r\n");
    response
}

/// A `200` answer with no body, as a successful upload returns.
pub fn empty_ok() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec()
}

/// A JSON rejection with an explicit status.
pub fn rejected(status: &str, message: &str) -> Vec<u8> {
    let body = format!(r#"{{"message":"{message}"}}"#);
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
