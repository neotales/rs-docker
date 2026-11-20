//! `GET /secrets` and `GET /secrets/{id}` documents shared by the owned and
//! fallback routing suites.
//!
//! Both suites must send the *same* recorded answers through both transports, or
//! a difference in their results would be a difference in the fixture rather than
//! in the code. The documents deliberately contain members the repository model
//! does not name: the owned transport decodes the daemon's answer directly and
//! retains them at the object level, while the generated fallback's Bollard
//! models have no catch-all and discard them.
//!
//! The secret data here is synthetic. It is a canary the error and `Debug` tests
//! look for, never a stored value. `Data` is *not* a member the Engine returns
//! from an inspect or a list; it is in these documents because the security
//! contract for an unexpected one is what the suites pin. The base64 form is
//! asserted against an independent encoder below, so a drift between the two
//! constants cannot make an assertion pass vacuously.

#![allow(dead_code)]

/// Synthetic secret bytes, chosen so a leaked diagnostic or `Debug` is
/// unmistakable.
pub(super) const SECRET_DATA_CANARY: &str = "test-secret-data-canary";

/// [`SECRET_DATA_CANARY`], base64-encoded as the Engine declares `Data`.
pub(super) const SECRET_DATA_BASE64: &str = "dGVzdC1zZWNyZXQtZGF0YS1jYW5hcnk=";

/// The secret every routing assertion names.
pub(super) const SECRET_ID: &str = "secret-fixture";

/// The version index every routing assertion names.
pub(super) const VERSION_INDEX: u64 = 9;

/// A secret with every member the facade names, one unmodelled top-level member,
/// and one unmodelled `Spec` member. No `Data`: this is the shape the Engine
/// actually returns.
pub(super) const SECRET_BODY: &str = r#"{
  "ID": "secret-fixture",
  "Version": {"Index": 9},
  "CreatedAt": "2026-09-01T10:00:00.000000000Z",
  "UpdatedAt": "2026-09-02T11:00:00.000000000Z",
  "Spec": {
    "Name": "fixture-secret",
    "Labels": {"org.example.secret": "fixture"},
    "Driver": {"Name": "vault"},
    "UnmodelledSpecMember": {"Nested": true}
  },
  "UnmodelledMember": {"Value": 7}
}"#;

/// A secret carrying an *unexpected* `Spec.Data` string.
///
/// The Engine never returns one. A daemon bug, a substituted response, or a
/// proxy can, and the value must be retained without being printed by `Debug`.
/// The canary is placed in every value-bearing member so a redaction written
/// against `Data` alone fails.
pub(super) const SECRET_BODY_WITH_DATA: &str = r#"{
  "ID": "secret-fixture",
  "Version": {"Index": 9},
  "CreatedAt": "2026-09-01T10:00:00.000000000Z",
  "UpdatedAt": "2026-09-02T11:00:00.000000000Z",
  "Spec": {
    "Name": "test-secret-data-canary",
    "Labels": {"org.example.secret": "test-secret-data-canary"},
    "Driver": {"Name": "test-secret-data-canary"},
    "Data": "dGVzdC1zZWNyZXQtZGF0YS1jYW5hcnk=",
    "UnmodelledSpecMember": "test-secret-data-canary"
  },
  "UnmodelledMember": {"Value": "test-secret-data-canary"}
}"#;

/// The same secret with `Data: null`. The owned path retains the JSON null; the
/// generated fallback's `Option<String>` reads it as absent and omits it.
pub(super) const SECRET_BODY_WITH_NULL_DATA: &str = r#"{
  "ID": "secret-fixture",
  "Version": {"Index": 9},
  "Spec": {"Name": "fixture-secret", "Data": null}
}"#;

/// The same secret with a numeric `Data`. The owned path retains the number; the
/// generated fallback's `Option<String>` refuses it.
pub(super) const SECRET_BODY_WITH_NUMBER_DATA: &str = r#"{
  "ID": "secret-fixture",
  "Version": {"Index": 9},
  "Spec": {"Name": "fixture-secret", "Data": 123}
}"#;

/// The same secret with an object `Data` whose value is the canary. The owned
/// path retains the object; the generated fallback refuses the type without
/// quoting the object's contents.
pub(super) const SECRET_BODY_WITH_OBJECT_DATA: &str = r#"{
  "ID": "secret-fixture",
  "Version": {"Index": 9},
  "Spec": {"Name": "fixture-secret", "Data": {"canary": "test-secret-data-canary"}}
}"#;

/// The same secret with an array `Data` whose value is the canary.
pub(super) const SECRET_BODY_WITH_ARRAY_DATA: &str = r#"{
  "ID": "secret-fixture",
  "Version": {"Index": 9},
  "Spec": {"Name": "fixture-secret", "Data": ["test-secret-data-canary"]}
}"#;

/// The same secret with two `Data` keys. The owned decoder keeps the last
/// value; the generated fallback refuses the duplicate field.
pub(super) const SECRET_BODY_WITH_DUPLICATE_DATA: &str = r#"{
  "ID": "secret-fixture",
  "Version": {"Index": 9},
  "Spec": {
    "Name": "fixture-secret",
    "Data": "first",
    "Data": "dGVzdC1zZWNyZXQtZGF0YS1jYW5hcnk="
  }
}"#;

/// A secret with two `ID` keys. Both decoders refuse a duplicate known field.
pub(super) const SECRET_BODY_WITH_DUPLICATE_ID: &str = r#"{
  "ID": "first",
  "ID": "test-secret-data-canary",
  "Version": {"Index": 9},
  "Spec": {"Name": "fixture-secret"}
}"#;

/// A `GET /secrets` answer carrying `SECRET_BODY`.
pub(super) fn secrets_body() -> String {
    format!("[{SECRET_BODY}]")
}

/// A `GET /secrets` answer carrying `SECRET_BODY_WITH_DATA`.
pub(super) fn secrets_body_with_data() -> String {
    format!("[{SECRET_BODY_WITH_DATA}]")
}

/// A success body that is not JSON at all.
///
/// The truncated tail is the data member, so a decoder that echoed the document
/// would put the canary in the error.
pub(super) const MALFORMED_BODY: &str = concat!(
    r#"{"ID":"secret-fixture","Spec":{"Data":"#,
    r#""dGVzdC1zZWNyZXQtZGF0YS1jYW5hcnk=""#
);

/// A success body whose `Version` has the wrong JSON type.
///
/// The unexpected value is the canary itself: serde's own `Display` quotes it,
/// which is the leak the owned decoder's content-free summary and the generated
/// fallback's source withholding both prevent.
pub(super) const WRONG_TYPE_BODY: &str =
    r#"{"ID":"secret-fixture","Version":"test-secret-data-canary"}"#;

/// Encodes `input` as standard base64 with padding, from the RFC 4648 table.
///
/// Spelled here rather than calling the crate under test, so the fixture and the
/// code cannot agree on the same mistake.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(ALPHABET[(triple >> 18 & 0x3f) as usize]));
        out.push(char::from(ALPHABET[(triple >> 12 & 0x3f) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(triple >> 6 & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[(triple & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}

/// The fixture's base64 really is the encoding of the canary.
///
/// Without this, a typo in either constant would make a "the canary is absent"
/// assertion pass because the fixture never carried the canary at all.
#[test]
fn the_fixture_base64_is_the_encoding_of_the_canary() {
    assert_eq!(SECRET_DATA_BASE64, base64(SECRET_DATA_CANARY.as_bytes()));
    assert!(
        SECRET_BODY_WITH_DATA.contains(SECRET_DATA_BASE64),
        "the string-Data fixture does not carry the encoded canary"
    );
    assert!(
        SECRET_BODY_WITH_DUPLICATE_DATA.contains(SECRET_DATA_BASE64),
        "the duplicate-Data fixture does not carry the encoded canary"
    );
}
