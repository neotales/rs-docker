//! Tests for bounded gRPC wire primitives.
use neotales_docker_buildkit::grpc::{GrpcError, decode_message, encode_message, parse_status};

#[test]
fn preserves_precious_bytes_and_boundary() {
    let payload = [0, 255, 13, 10, 128];
    let encoded = encode_message(0, &payload, payload.len()).unwrap();
    assert_eq!(
        decode_message(&encoded, payload.len()).unwrap(),
        (0, payload.as_slice(), encoded.len())
    );
    assert_eq!(
        encode_message(0, &payload, payload.len() - 1),
        Err(GrpcError::Oversized)
    );
    assert_eq!(
        decode_message(&encoded, payload.len() - 1),
        Err(GrpcError::Oversized)
    );
}

#[test]
fn rejects_truncation_and_compression() {
    assert_eq!(decode_message(&[0, 0, 0], 10), Err(GrpcError::Truncated));
    assert_eq!(
        decode_message(&[0, 0, 0, 0, 2, 1], 10),
        Err(GrpcError::Truncated)
    );
    assert_eq!(
        decode_message(&[1, 0, 0, 0, 0], 10),
        Err(GrpcError::UnexpectedCompression)
    );
    assert_eq!(
        encode_message(1, &[], 10),
        Err(GrpcError::UnexpectedCompression)
    );
}

#[test]
fn trailers_are_not_http_success() {
    assert_eq!(parse_status(Some("0"), None), Ok(()));
    assert_eq!(
        parse_status(Some("7"), Some("permission%20denied")),
        Err(GrpcError::Status {
            code: 7,
            message: Some("permission denied".to_owned())
        })
    );
    assert_eq!(parse_status(None, None), Err(GrpcError::MalformedTrailer));
    assert_eq!(
        parse_status(Some("not-a-number"), None),
        Err(GrpcError::MalformedTrailer)
    );
    assert_eq!(
        parse_status(Some("0"), Some("bad%XX")),
        Err(GrpcError::MalformedTrailer)
    );
}
