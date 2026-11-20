#![allow(missing_docs)]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use neotales_docker::{DockerClient, Endpoint, Error, ProxyPolicy, raw::RegistryAuthentication};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

const BOUND: Duration = Duration::from_secs(10);
const CANARY: &str = "synthetic-registry-canary";

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    status: &str,
    body: &str,
) -> (String, Vec<u8>) {
    timeout(BOUND, async {
        let mut data = Vec::new();
        let mut byte = [0];
        while !data.ends_with(b"\r\n\r\n") {
            assert!(data.len() < 16384);
            stream.read_exact(&mut byte).await.unwrap();
            data.push(byte[0]);
        }
        let head = String::from_utf8(data).unwrap();
        let len = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(len < 16384);
        let mut request_body = vec![0; len];
        stream.read_exact(&mut request_body).await.unwrap();
        let answer = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(answer.as_bytes()).await.unwrap();
        (head.lines().next().unwrap().to_owned(), request_body)
    })
    .await
    .expect("fixture deadline")
}

async fn fixture(
    status: &str,
    body: &str,
    proxied: bool,
) -> (DockerClient, tokio::task::JoinHandle<(String, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let status = status.to_owned();
    let body = body.to_owned();
    let task = tokio::spawn(async move {
        let (stream, _) = timeout(BOUND, listener.accept()).await.unwrap().unwrap();
        exchange(stream, &status, &body).await
    });
    let client = if proxied {
        DockerClient::connect_endpoint_with_policy(
            &Endpoint::Http("http://engine.example:2375".into()),
            ProxyPolicy::with_basic_auth(format!("http://{address}"), "proxy-user", CANARY)
                .unwrap(),
        )
        .unwrap()
    } else {
        DockerClient::connect_http(&format!("http://{address}")).unwrap()
    };
    (client, task)
}
fn auth() -> RegistryAuthentication<'static> {
    RegistryAuthentication {
        username: CANARY,
        password: CANARY,
        serveraddress: CANARY,
        identitytoken: Some(CANARY),
        registrytoken: Some(CANARY),
    }
}
fn safe(error: &Error) {
    let encoded = STANDARD.encode(CANARY);
    let check = |s: String| {
        assert!(!s.contains(CANARY), "plaintext leaked: {s}");
        assert!(!s.contains(&encoded), "base64 leaked: {s}");
    };
    check(format!("{error}"));
    check(format!("{error:?}"));
    check(format!("{:?}", error.api_error()));
    let mut source = std::error::Error::source(error);
    while let Some(e) = source {
        check(format!("{e}"));
        check(format!("{e:?}"));
        source = e.source();
    }
}

#[tokio::test]
async fn auth_shape_and_confidential_result() {
    let (client, task) = fixture(
        "200 OK",
        &format!(r#"{{"Status":"{CANARY}","IdentityToken":"{CANARY}"}}"#),
        false,
    )
    .await;
    let result = client.registry_authenticate(&auth()).await.unwrap();
    assert_eq!(result.status, CANARY);
    assert_eq!(result.identity_token, CANARY);
    assert!(!format!("{result:?}").contains(CANARY));
    let (line, body) = task.await.unwrap();
    assert_eq!(line, "POST /v1.55/auth HTTP/1.1");
    assert_eq!(body, format!(r#"{{"username":"{CANARY}","password":"{CANARY}","serveraddress":"{CANARY}","identitytoken":"{CANARY}","registrytoken":"{CANARY}"}}"#).as_bytes());
}

#[tokio::test]
async fn metadata_inspect_and_list() {
    for list in [false, true] {
        let (client, task) = fixture("200 OK", r#"{"Descriptor":{"digest":"sha256:123"},"Platforms":[{"architecture":"amd64","os":"linux"}]}"#, false).await;
        if list {
            assert_eq!(
                client.distribution_list("team/app:tag").await.unwrap()[0]["os"],
                "linux"
            );
        } else {
            assert_eq!(
                client.distribution_inspect("team/app:tag").await.unwrap()["Descriptor"]["digest"],
                "sha256:123"
            );
        }
        let (line, body) = task.await.unwrap();
        assert_eq!(
            line,
            "GET /v1.55/distribution/team%2Fapp%3Atag/json HTTP/1.1"
        );
        assert!(body.is_empty(), "expected body to be empty");
    }
}

#[tokio::test]
async fn failures_withhold_and_keep_status() {
    for proxied in [false, true] {
        for status in [
            "404 Not Found",
            "407 Proxy Authentication Required",
            "304 Not Modified",
            "101 Switching Protocols",
        ] {
            for is_auth in [false, true] {
                let response = format!(r#"{{"message":"{CANARY} {}"}}"#, STANDARD.encode(CANARY));
                let (client, task) = fixture(status, &response, proxied).await;
                let error = if is_auth {
                    client.registry_authenticate(&auth()).await.err().unwrap()
                } else {
                    client
                        .distribution_inspect("team/app:tag")
                        .await
                        .err()
                        .unwrap()
                };
                safe(&error);
                assert_eq!(
                    error.api_error().unwrap().status_code,
                    status[..3].parse::<u16>().unwrap()
                );
                let (line, _) = task.await.unwrap();
                let target = if is_auth {
                    "/v1.55/auth"
                } else {
                    "/v1.55/distribution/team%2Fapp%3Atag/json"
                };
                let expected = if proxied {
                    format!(
                        "{} http://engine.example:2375{target} HTTP/1.1",
                        if is_auth { "POST" } else { "GET" }
                    )
                } else {
                    format!("{} {target} HTTP/1.1", if is_auth { "POST" } else { "GET" })
                };
                assert_eq!(line, expected);
            }
        }
    }
}

#[tokio::test]
async fn malformed_json_is_withheld() {
    for is_auth in [false, true] {
        let (client, task) = fixture("200 OK", CANARY, false).await;
        let error = if is_auth {
            client.registry_authenticate(&auth()).await.err().unwrap()
        } else {
            client.distribution_inspect("name").await.err().unwrap()
        };
        safe(&error);
        task.await.unwrap();
    }
}

#[cfg(unix)]
#[path = "support/supervised_child.rs"]
mod supervised_child;

#[cfg(unix)]
#[test]
fn captured_local_contract() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("engine.sock");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "captured_local_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("REGISTRY_TEST_SOCKET", &socket);
    assert!(supervised_child::run(command, Duration::from_secs(30)).success());
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "isolated environment worker"]
async fn captured_local_worker() {
    let listener =
        tokio::net::UnixListener::bind(std::env::var_os("REGISTRY_TEST_SOCKET").unwrap()).unwrap();
    let server = tokio::spawn(async move {
        for (expected, body) in [
            (
                "POST /v1.55/auth HTTP/1.1",
                r#"{"Status":"ok","IdentityToken":"token"}"#,
            ),
            (
                "GET /v1.55/distribution/team%2Fapp%3Atag/json HTTP/1.1",
                r#"{"Platforms":[]}"#,
            ),
            (
                "GET /v1.55/distribution/team%2Fapp%3Atag/json HTTP/1.1",
                r#"{"Platforms":[]}"#,
            ),
        ] {
            let (stream, _) = timeout(BOUND, listener.accept()).await.unwrap().unwrap();
            let (line, request_body) = exchange(stream, "200 OK", body).await;
            assert_eq!(line, expected);
            if expected.starts_with("POST") {
                assert_eq!(request_body, format!(r#"{{"username":"{CANARY}","password":"{CANARY}","serveraddress":"{CANARY}","identitytoken":"{CANARY}","registrytoken":"{CANARY}"}}"#).as_bytes());
            } else {
                assert!(request_body.is_empty(), "expected request_body to be empty");
            }
        }
    });
    let client = DockerClient::connect_local().unwrap();
    client.registry_authenticate(&auth()).await.unwrap();
    client.distribution_inspect("team/app:tag").await.unwrap();
    client.distribution_list("team/app:tag").await.unwrap();
    timeout(BOUND, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn transport_failures_and_invalid_names_are_safe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let client = DockerClient::connect_http(&format!("http://{address}")).unwrap();
    safe(&client.registry_authenticate(&auth()).await.err().unwrap());
    safe(&client.distribution_inspect("team/app").await.unwrap_err());
    safe(&client.distribution_inspect("").await.unwrap_err());
}

#[tokio::test]
async fn oversized_success_documents_are_bounded() {
    for is_auth in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = timeout(BOUND, listener.accept()).await.unwrap().unwrap();
            let mut data = Vec::new();
            let mut byte = [0];
            while !data.ends_with(b"\r\n\r\n") {
                assert!(data.len() < 16384);
                stream.read_exact(&mut byte).await.unwrap();
                data.push(byte[0]);
            }
            let head = String::from_utf8(data).unwrap();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut request_body = vec![0; length];
            stream.read_exact(&mut request_body).await.unwrap();
            let count = neotales_docker::raw::MAX_DOCUMENT_BYTES + 1;
            let header =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {count}\r\nConnection: close\r\n\r\n");
            stream.write_all(header.as_bytes()).await.unwrap();
            let chunk = vec![b'x'; 65536];
            for _ in 0..=(count / chunk.len()) {
                if timeout(BOUND, stream.write_all(&chunk))
                    .await
                    .unwrap()
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = DockerClient::connect_http(&format!("http://{address}")).unwrap();
        let error = if is_auth {
            client.registry_authenticate(&auth()).await.err().unwrap()
        } else {
            client.distribution_inspect("team/app").await.err().unwrap()
        };
        safe(&error);
        timeout(BOUND, server).await.unwrap().unwrap();
    }
}
