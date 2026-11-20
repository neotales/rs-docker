#![allow(missing_docs)]
use neotales_docker::{ContainerLogStream, ContainerLogsOptions, DockerClient, ExecOptions};
use std::error::Error as _;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const TIMEOUT: Duration = Duration::from_secs(5);
const CANARY: &str = "synthetic-stream-canary";

async fn fixture(responses: Vec<Vec<u8>>) -> (DockerClient, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client =
        DockerClient::connect_http(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut socket, _) = tokio::time::timeout(TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                tokio::time::timeout(TIMEOUT, socket.read_exact(&mut byte))
                    .await
                    .unwrap()
                    .unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16384);
            }
            let head = String::from_utf8(request).unwrap();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            assert!(length < 16384);
            let mut body = vec![0; length];
            tokio::time::timeout(TIMEOUT, socket.read_exact(&mut body))
                .await
                .unwrap()
                .unwrap();
            requests.push(head);
            tokio::time::timeout(TIMEOUT, socket.write_all(&response))
                .await
                .unwrap()
                .unwrap();
        }
        requests
    });
    (client, task)
}
fn response(status: &str, body: &[u8]) -> Vec<u8> {
    [
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
        body,
    ]
    .concat()
}
fn inspect(tty: bool) -> Vec<u8> {
    response(
        "200 OK",
        format!("{{\"Config\":{{\"Tty\":{tty}}}}}").as_bytes(),
    )
}
async fn done(task: JoinHandle<Vec<String>>) -> Vec<String> {
    tokio::time::timeout(TIMEOUT, task).await.unwrap().unwrap()
}
fn safe(error: &neotales_docker::Error) {
    assert!(!format!("{error} {error:?}").contains(CANARY));
    let mut source = error.source();
    while let Some(item) = source {
        assert!(!format!("{item} {item:?}").contains(CANARY));
        source = item.source();
    }
}
#[tokio::test]
async fn logs_use_inspected_tty_and_non_tty() {
    for tty in [false, true] {
        let body = if tty {
            b"hello".to_vec()
        } else {
            b"\x01\0\0\0\0\0\0\x05hello".to_vec()
        };
        let (client, task) = fixture(vec![inspect(tty), response("200 OK", &body)]).await;
        let mut logs = client.logs("demo", Some(ContainerLogsOptions::default()));
        let frame = tokio::time::timeout(TIMEOUT, logs.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.payload, b"hello");
        assert_eq!(
            frame.stream,
            if tty {
                ContainerLogStream::Console
            } else {
                ContainerLogStream::Stdout
            }
        );
        let requests = done(task).await;
        assert!(requests[0].starts_with("GET /v1.55/containers/demo/json "));
        assert!(requests[1].starts_with("GET /v1.55/containers/demo/logs?"));
    }
}
#[tokio::test]
async fn missing_tty_and_non_upgrade_are_refused() {
    let (client, task) = fixture(vec![response("200 OK", b"{}")]).await;
    let error = client
        .attach_container("demo", false, false, None)
        .await
        .unwrap_err();
    assert!(error.api_error().is_none());
    done(task).await;
    let (client, task) = fixture(vec![inspect(false), response("200 OK", b"")]).await;
    let error = client
        .attach_container("demo", false, false, None)
        .await
        .unwrap_err();
    assert_eq!(error.api_error().unwrap().status_code, 200);
    done(task).await;
}
#[tokio::test]
async fn rejections_never_expose_peer_text() {
    let rejection = || {
        response(
            "403 Forbidden",
            format!("{{\"message\":\"{CANARY}\"}}").as_bytes(),
        )
    };
    for stage in 0..3 {
        let responses = if stage == 0 {
            vec![rejection()]
        } else {
            vec![inspect(false), rejection()]
        };
        let (client, task) = fixture(responses).await;
        let error = if stage == 2 {
            client
                .attach_container("demo", true, false, None)
                .await
                .unwrap_err()
        } else {
            client.logs("demo", None).next().await.unwrap().unwrap_err()
        };
        assert_eq!(error.api_error().unwrap().status_code, 403);
        safe(&error);
        done(task).await;
    }
}
#[tokio::test]
async fn malformed_and_truncated_logs_are_errors() {
    for bytes in [
        b"\x07\0\0\0\0\0\0\x01x".as_slice(),
        b"\x01\0\0\0\0\0\0\x04x".as_slice(),
    ] {
        let (client, task) = fixture(vec![inspect(false), response("200 OK", bytes)]).await;
        let mut logs = client.logs("demo", None);
        assert!(
            tokio::time::timeout(TIMEOUT, logs.next())
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        done(task).await;
    }
}

#[tokio::test]
async fn exec_rejection_does_not_expose_peer_text() {
    let body = format!("{{\"message\":\"{CANARY}\"}}");
    let (client, task) = fixture(vec![response("403 Forbidden", body.as_bytes())]).await;
    let options = ExecOptions {
        command: vec!["echo".to_owned(), CANARY.to_owned()],
        ..Default::default()
    };
    let error = tokio::time::timeout(TIMEOUT, client.start_exec("demo", options))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.api_error().unwrap().status_code, 403);
    safe(&error);
    let requests = done(task).await;
    assert!(requests[0].starts_with("POST /v1.55/containers/demo/exec "));
}

#[tokio::test]
async fn attach_stdin_reaches_the_upgraded_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client =
        DockerClient::connect_http(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let task = tokio::spawn(async move {
        let (mut first, _) = tokio::time::timeout(TIMEOUT, listener.accept())
            .await
            .unwrap()
            .unwrap();
        read_head(&mut first).await;
        first.write_all(&inspect(false)).await.unwrap();
        drop(first);
        let (mut stream, _) = tokio::time::timeout(TIMEOUT, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let head = read_head(&mut stream).await;
        assert!(head.contains("stdin=true"));
        stream.write_all(b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n\x01\0\0\0\0\0\0\x03out").await.unwrap();
        let mut input = [0; 2];
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut input))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&input, b"in");
    });
    let mut session =
        tokio::time::timeout(TIMEOUT, client.attach_container("demo", true, false, None))
            .await
            .unwrap()
            .unwrap();
    session.input_mut().write_all(b"in").await.unwrap();
    let frame = tokio::time::timeout(TIMEOUT, session.output_mut().next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.payload, b"out");
    tokio::time::timeout(TIMEOUT, task).await.unwrap().unwrap();
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        head.push(byte[0]);
        assert!(head.len() < 16384);
    }
    String::from_utf8(head).unwrap()
}

#[cfg(unix)]
#[path = "support/supervised_child.rs"]
mod supervised_child;

#[cfg(unix)]
#[test]
fn captured_local_streams() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("engine.sock");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "local_stream_worker", "--ignored", "--nocapture"])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("CONTAINER_STREAM_TEST_SOCKET", &socket);
    assert!(supervised_child::run(command, Duration::from_secs(30)).success());
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "isolated local constructor child"]
async fn local_stream_worker() {
    use tokio::net::UnixListener;
    let socket = std::env::var_os("CONTAINER_STREAM_TEST_SOCKET").unwrap();
    let listener = UnixListener::bind(socket).unwrap();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for index in 0..4 {
            let (mut stream, _) = tokio::time::timeout(TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            requests.push(read_head(&mut stream).await);
            let response = match index {
                0 | 2 => inspect(false),
                1 => response("200 OK", b"\x01\0\0\0\0\0\0\x05hello"),
                _ => b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n\x01\0\0\0\0\0\0\x05world".to_vec(),
            };
            tokio::time::timeout(TIMEOUT, stream.write_all(&response))
                .await
                .unwrap()
                .unwrap();
        }
        requests
    });
    let client = DockerClient::connect_local().unwrap();
    let mut logs = client.logs("demo", None);
    let first = tokio::time::timeout(TIMEOUT, logs.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.payload, b"hello");
    let mut attached =
        tokio::time::timeout(TIMEOUT, client.attach_container("demo", false, false, None))
            .await
            .unwrap()
            .unwrap();
    let error = attached
        .input_mut()
        .write_all(b"not requested")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("stdin was not requested"));
    let frame = tokio::time::timeout(TIMEOUT, attached.output_mut().next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.payload, b"world");
    let requests = tokio::time::timeout(TIMEOUT, task).await.unwrap().unwrap();
    assert!(requests[0].starts_with("GET /v1.55/containers/demo/json "));
    assert!(requests[1].starts_with("GET /v1.55/containers/demo/logs?"));
    assert!(requests[2].starts_with("GET /v1.55/containers/demo/json "));
    assert!(requests[3].starts_with("POST /v1.55/containers/demo/attach?"));
}
