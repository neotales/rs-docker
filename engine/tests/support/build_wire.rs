//! Shared request reading and answer building for the build wire suites.
//!
//! The owned and fallback build suites observe the same two things: the request
//! the client put on the wire, including a streamed TAR body, and the
//! newline-delimited records the daemon answers with. Keeping the reader in one
//! place means the fallback suite cannot quietly accept a different framing
//! from the one the owned suite asserts.
//!
//! Each suite uses a subset, so unused items are allowed here rather than
//! repeated in both files.
#![allow(dead_code)]
// The module is private to each test binary, so `pub` here means "visible to
// the suite that included it", not an exported item.
#![allow(unreachable_pub)]

use std::io::{BufRead, BufReader, Read};

use neotales_docker::{API_VERSION, ImageBuildContext};

/// A context holding a custom Dockerfile and one source file.
pub fn build_context() -> ImageBuildContext {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path().join("context");
    std::fs::create_dir_all(&root).expect("context directory");
    std::fs::write(root.join("Containerfile"), "FROM alpine:3.20\nRUN true\n")
        .expect("write the Dockerfile");
    std::fs::write(root.join("Dockerfile"), "FROM alpine:3.20\nRUN true\n")
        .expect("write the default Dockerfile");
    std::fs::write(root.join("app.txt"), "payload\n").expect("write a source file");
    ImageBuildContext::from_directory(&root).expect("a valid context")
}

/// A recorded request: the request line, its headers, and its decoded body.
pub struct Recorded {
    pub line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    /// Returns a header's value, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }

    /// Returns the request target, such as `/v1.55/build?dockerfile=Dockerfile`.
    pub fn target(&self) -> &str {
        self.line.split_whitespace().nth(1).unwrap_or_default()
    }

    /// Returns the decoded query parameters, in wire order.
    pub fn query(&self) -> Vec<(String, String)> {
        let Some((_, query)) = self.target().split_once('?') else {
            return Vec::new();
        };
        url::form_urlencoded::parse(query.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    }

    /// Returns the first decoded value of one query parameter.
    pub fn query_value(&self, key: &str) -> Option<String> {
        self.query()
            .into_iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
    }

    /// Returns every decoded value of one repeated query parameter.
    pub fn query_values(&self, key: &str) -> Vec<String> {
        self.query()
            .into_iter()
            .filter(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
            .collect()
    }

    /// Decodes one query parameter that carries a JSON document.
    pub fn query_json(&self, key: &str) -> serde_json::Value {
        let value = self
            .query_value(key)
            .unwrap_or_else(|| panic!("{key} is missing from {}", self.target()));
        serde_json::from_str(&value).expect("the query value is JSON")
    }
}

/// Reads one HTTP request, decoding a `Content-Length` or chunked body.
pub fn read_request<R: Read>(reader: &mut BufReader<R>) -> Recorded {
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

    let chunked = header_value(&headers, "transfer-encoding").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
    });
    let body = if chunked {
        read_chunked(reader)
    } else {
        let length = header_value(&headers, "content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        reader.read_exact(&mut body).expect("read the request body");
        body
    };

    Recorded {
        line,
        headers,
        body,
    }
}

/// Returns a header's value, matched case-insensitively.
pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Decodes an HTTP/1.1 chunked body, including its terminating chunk.
fn read_chunked<R: Read>(reader: &mut BufReader<R>) -> Vec<u8> {
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

/// A `200` answer carrying newline-delimited build records.
pub fn records(records: &[&str]) -> Vec<u8> {
    let mut body = records.join("\n");
    body.push('\n');
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A JSON rejection with an explicit status.
pub fn rejected(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The version prefix the owned transport is expected to send.
pub fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// A valid record a stream can continue with after a refused one.
pub const RECOVERY_RECORD: &str = r#"{"stream":"after\n"}"#;

/// Records the generated build model rejects, used by both routes.
///
/// The second value says whether the failure is a duplicate known member
/// (`true`) or a known member with the wrong JSON type (`false`). The
/// failed-first/null-second case is the one a parsed [`serde_json::Value`]
/// silently turns into a successful build, so it is pinned explicitly on both
/// routes.
pub const KNOWN_MEMBER_REGRESSIONS: [(&str, bool); 8] = [
    (r#"{"stream":"one\n","stream":"two\n"}"#, true),
    (
        r#"{"errorDetail":{"message":"the step failed","message":null}}"#,
        true,
    ),
    (
        r#"{"errorDetail":{"message":"the step failed"},"errorDetail":null}"#,
        true,
    ),
    (
        r#"{"errorDetail":{"code":"not-a-number","message":"the step failed"}}"#,
        false,
    ),
    (r#"{"progressDetail":{"current":null,"current":1}}"#, true),
    (r#"{"progressDetail":{"total":1,"total":2}}"#, true),
    (r#"{"aux":{"ID":"one","ID":null}}"#, true),
    (r#"{"errorDetail":{"code":null,"code":1}}"#, true),
];

/// Both formats are accepted by the generated model, including nested arrays.
pub const COMPATIBLE_RECORDS: [&str; 2] = [
    r#"{"unknown":{"nested":1e400},"stream":"after\n"}"#,
    r#"[null,"array\n",[null,null],null,[1,2],["sha256:array"]]"#,
];
