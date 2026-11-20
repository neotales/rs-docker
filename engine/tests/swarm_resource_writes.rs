//! Bounded, synthetic HTTP coverage for confidential config and secret writes.
#![allow(missing_docs)]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use neotales_docker::{
    API_VERSION, ConfigCreateOptions, ConfigUpdateOptions, DockerClient, Endpoint, ForwardProxy,
    ProxyPolicy, SecretCreateOptions, SecretUpdateOptions, SwarmConfigSpec, SwarmSecretData,
    SwarmSecretSpec,
};
use std::{error::Error as _, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

const PLAIN: &str = "confidential-canary-write-4827";
const ENCODED: &str = "Y29uZmlkZW50aWFsLWNhbmFyeS13cml0ZS00ODI3";
const PROXY_USER: &str = "fixture-user-1729";
const PROXY_PASS: &str = "fixture-password-6042";

async fn call(client: &DockerClient, op: usize) -> Result<String, neotales_docker::Error> {
    match op {
        0 => {
            client
                .create_config(ConfigCreateOptions {
                    name: "fixture".into(),
                    data: Some(PLAIN.as_bytes().to_vec()),
                    labels: None,
                })
                .await
        }
        1 => client
            .update_config(
                "a/b",
                ConfigUpdateOptions {
                    version: 7,
                    spec: SwarmConfigSpec {
                        name: Some("fixture".into()),
                        data: Some(ENCODED.into()),
                        ..Default::default()
                    },
                },
            )
            .await
            .map(|()| "ok".into()),
        2 => client.remove_config("a/b").await.map(|()| "ok".into()),
        3 => {
            client
                .create_secret(SecretCreateOptions::new(
                    "fixture",
                    Some(SwarmSecretData::new(PLAIN.as_bytes())),
                ))
                .await
        }
        4 => client
            .update_secret(
                "a/b",
                SecretUpdateOptions {
                    version: 7,
                    spec: SwarmSecretSpec {
                        name: Some("fixture".into()),
                        driver: Some(serde_json::json!({"Name":"vault"})),
                        ..Default::default()
                    },
                },
            )
            .await
            .map(|()| "ok".into()),
        _ => client.remove_secret("a/b").await.map(|()| "ok".into()),
    }
}

async fn run(
    op: usize,
    status: &str,
    body: &str,
    proxy: bool,
    authenticated: bool,
) -> (Result<String, neotales_docker::Error>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let client = if proxy {
        DockerClient::connect_endpoint_with_policy(
            &Endpoint::Http("http://127.0.0.1:9".into()),
            ProxyPolicy::Http(if authenticated {
                ForwardProxy::with_basic_auth(&address, PROXY_USER, PROXY_PASS).unwrap()
            } else {
                ForwardProxy::new(&address).unwrap()
            }),
        )
        .unwrap()
    } else {
        DockerClient::connect_http(&address).unwrap()
    };
    let answer = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let server = tokio::spawn(async move {
        timeout(Duration::from_secs(5), async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let mut buf = [0; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buf[..n]);
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&data[..pos]);
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if data.len() >= pos + 4 + length {
                        break;
                    }
                }
            }
            stream.write_all(answer.as_bytes()).await.unwrap();
            String::from_utf8(data).unwrap()
        })
        .await
        .expect("fixture deadline")
    });
    let result = timeout(Duration::from_secs(5), call(&client, op))
        .await
        .expect("client deadline");
    let request = timeout(Duration::from_secs(6), server)
        .await
        .expect("server deadline")
        .unwrap();
    (result, request)
}

#[tokio::test]
async fn six_writes_use_versioned_requests_and_keep_success_values() {
    let paths = [
        "POST /configs/create",
        "POST /configs/a%2Fb/update?version=7",
        "DELETE /configs/a%2Fb",
        "POST /secrets/create",
        "POST /secrets/a%2Fb/update?version=7",
        "DELETE /secrets/a%2Fb",
    ];
    for (op, path) in paths.iter().enumerate() {
        let (result, request) = run(op, "200 OK", r#"{"ID":"created"}"#, false, false).await;
        assert_eq!(
            result.unwrap(),
            if op == 0 || op == 3 { "created" } else { "ok" }
        );
        let (method, target) = path.split_once(' ').unwrap();
        assert!(request.starts_with(&format!(
            "{method} /v{}.{}{target} HTTP/1.1",
            API_VERSION.major, API_VERSION.minor
        )));
        if op == 0 || op == 1 || op == 3 {
            assert!(request.contains(ENCODED));
        }
        if op == 4 {
            assert!(request.contains("vault"));
        }
    }
}

#[tokio::test]
async fn all_writes_withhold_direct_errors_and_reject_non_success_statuses() {
    for proxy in [false, true] {
        for op in 0..6 {
            for (status, code) in [
                ("409 Conflict", 409),
                ("101 Switching Protocols", 101),
                ("304 Not Modified", 304),
            ] {
                let (result, _) =
                    run(op, status, &format!("{PLAIN} {ENCODED}"), proxy, false).await;
                let error = result.unwrap_err();
                assert_eq!(error.api_error().unwrap().status_code, code);
                let mut renderings = vec![
                    format!("{error}"),
                    format!("{error:?}"),
                    error.api_error().unwrap().message.clone(),
                ];
                let mut source = error.source();
                while let Some(err) = source {
                    renderings.push(format!("{err}"));
                    renderings.push(format!("{err:?}"));
                    source = err.source();
                }
                for value in renderings {
                    assert!(!value.contains(PLAIN) && !value.contains(ENCODED));
                }
            }
        }
    }
}

#[tokio::test]
async fn duplicate_create_ids_are_refused_without_echoing() {
    for op in [0, 3] {
        let body = format!(r#"{{"ID":"{PLAIN}","ID":"{ENCODED}"}}"#);
        let (result, _) = run(op, "200 OK", &body, false, false).await;
        let error = result.unwrap_err();
        assert!(!format!("{error:?} {error}").contains(PLAIN));
        assert!(!format!("{error:?} {error}").contains(ENCODED));
    }
}

#[tokio::test]
async fn config_reserved_and_non_ascii_keys_are_refused_before_dispatch() {
    let client = DockerClient::connect_http("http://127.0.0.1:9").unwrap();
    for key in ["Name", "nAmE", "DATA", "Templating", "Labelſ"] {
        let mut spec = SwarmConfigSpec::default();
        spec.additional.insert(key.into(), serde_json::json!(PLAIN));
        let error = client
            .update_config("id", ConfigUpdateOptions { version: 1, spec })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), neotales_docker::ErrorKind::InvalidInput);
        assert!(!format!("{error:?} {error}").contains(PLAIN));
    }
}

#[tokio::test]
async fn cancellation_closes_the_connection_without_retry() {
    for op in 0..6 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client =
            DockerClient::connect_http(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
        let mut future = Box::pin(call(&client, op));
        let (mut stream, _) = timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut future => panic!("request unexpectedly finished: {result:?}"),
                accepted = listener.accept() => accepted.unwrap(),
            }
        })
        .await
        .unwrap();
        let mut buffer = [0; 4096];
        timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    result = &mut future => panic!("request unexpectedly finished: {result:?}"),
                    result = stream.read(&mut buffer) => { if result.unwrap() > 0 {break;} },
                }
            }
        })
        .await
        .unwrap();
        drop(future);
        timeout(Duration::from_secs(5), async {
            while stream.read(&mut buffer).await.unwrap() != 0 {}
        })
        .await
        .unwrap();
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }
}

/// An authenticated proxy is itself an untrusted peer and can echo both the
/// request's confidential data and its own authorization header.
#[tokio::test]
async fn authenticated_proxy_echo_is_withheld_for_every_write() {
    let credential = format!("{PROXY_USER}:{PROXY_PASS}");
    let encoded_credential = STANDARD.encode(&credential);
    let body = format!("{PLAIN} {ENCODED} {credential} {encoded_credential}");
    for op in 0..6 {
        let (result, request) = run(op, "409 Conflict", &body, true, true).await;
        let headers: Vec<_> = request
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
            .map(|(_, value)| value.trim())
            .collect();
        assert_eq!(headers, [format!("Basic {encoded_credential}")]);
        let error = result.unwrap_err();
        let api = error.api_error().expect("status is preserved");
        assert_eq!(api.status_code, 409);
        let mut renderings = vec![
            format!("{error}"),
            format!("{error:?}"),
            format!("{api}"),
            format!("{api:?}"),
            api.message.clone(),
        ];
        let mut source = error.source();
        while let Some(cause) = source {
            renderings.push(format!("{cause}"));
            renderings.push(format!("{cause:?}"));
            source = cause.source();
        }
        for rendered in renderings {
            for canary in [
                PLAIN,
                ENCODED,
                PROXY_USER,
                PROXY_PASS,
                credential.as_str(),
                encoded_credential.as_str(),
            ] {
                assert!(
                    !rendered.contains(canary),
                    "sensitive material in error rendering"
                );
            }
        }
    }
}

#[cfg(unix)]
#[path = "support/supervised_child.rs"]
mod supervised_child;

/// The environment belongs to this child only, never the test runner or daemon.
#[cfg(unix)]
#[test]
fn captured_local_resource_write_contract() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "captured_local_resource_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("RESOURCE_WRITE_TEST_SOCKET", &socket);
    let status = supervised_child::run(command, Duration::from_secs(30));
    assert!(status.success(), "local worker failed: {status}");
}

/// Six requests must reach the socket captured by `connect_local`, with versioned
/// and escaped owned paths rather than unversioned generated-client paths.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
#[ignore = "run in an isolated child with a supervised DOCKER_HOST"]
async fn captured_local_resource_worker() {
    use tokio::net::UnixListener;
    let socket = std::env::var_os("RESOURCE_WRITE_TEST_SOCKET").unwrap();
    let listener = UnixListener::bind(socket).unwrap();
    let client = DockerClient::connect_local().unwrap();
    assert!(client.raw_engine().is_ok());
    let server = tokio::spawn(async move {
        timeout(Duration::from_secs(15), async move {
            let mut requests = Vec::new();
            for _ in 0..6 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0, "request ended before the body");
                    data.extend_from_slice(&buffer[..n]);
                    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&data[..pos]);
                        let length = head
                            .lines()
                            .find_map(|line| {
                                line.split_once(':')
                                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                    .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if data.len() >= pos + 4 + length {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8(data).unwrap());
                let body = r#"{"ID":"created"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        })
        .await
        .expect("local fixture deadline")
    });
    for op in 0..6 {
        let value = timeout(Duration::from_secs(3), call(&client, op))
            .await
            .expect("local call deadline")
            .unwrap();
        assert_eq!(value, if op == 0 || op == 3 { "created" } else { "ok" });
    }
    let requests = timeout(Duration::from_secs(16), server)
        .await
        .unwrap()
        .unwrap();
    let paths = [
        "POST /configs/create",
        "POST /configs/a%2Fb/update?version=7",
        "DELETE /configs/a%2Fb",
        "POST /secrets/create",
        "POST /secrets/a%2Fb/update?version=7",
        "DELETE /secrets/a%2Fb",
    ];
    for (request, path) in requests.iter().zip(paths) {
        let (method, target) = path.split_once(' ').unwrap();
        let expected = format!(
            "{method} /v{}.{}{target} HTTP/1.1",
            API_VERSION.major, API_VERSION.minor
        );
        assert_eq!(request.lines().next().unwrap(), expected);
    }
}
