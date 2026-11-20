#![allow(missing_docs)]
use neotales_docker::{API_VERSION, DockerClient, ErrorKind};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
};

fn fixture(
    bodies: Vec<(u16, String)>,
) -> (DockerClient, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        for (status, body) in bodies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 1024];
            while !bytes.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
            }
            tx.send(
                String::from_utf8(bytes)
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap()
                    .to_owned(),
            )
            .unwrap();
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    (DockerClient::connect_http(&endpoint).unwrap(), rx, server)
}

#[tokio::test]
async fn owned_list_and_inspect_preserve_spec_and_reject_collisions() {
    let task = json!({"ID":"t","ServiceID":"s","Slot":1,"NodeID":"n","Spec":{"ContainerSpec":{"Image":"demo","Unknown":{"nested":true}}},"Future":42});
    let collision = json!({"ID":"bad","Image":null});
    let (client, lines, server) = fixture(vec![
        (200, json!([task.clone()]).to_string()),
        (200, task.to_string()),
        (200, json!([{}, collision.clone()]).to_string()),
        (200, collision.to_string()),
    ]);
    let list = client.list_tasks(None).await.unwrap();
    let inspected = client.inspect_task("t").await.unwrap();
    for item in [&list[0], &inspected] {
        assert_eq!(item.image.as_deref(), Some("demo"));
        assert_eq!(item.additional["Spec"], *item.spec.as_ref().unwrap());
        assert_eq!(item.additional["Future"], 42);
        assert_eq!(
            item.spec.as_ref().unwrap()["ContainerSpec"]["Unknown"]["nested"],
            true
        );
    }
    for error in [
        client.list_tasks(None).await.unwrap_err(),
        client.inspect_task("bad").await.unwrap_err(),
    ] {
        assert_eq!(error.kind(), ErrorKind::Serialization);
        assert!(!error.to_string().contains("bad"));
    }
    for target in ["/tasks", "/tasks/t", "/tasks", "/tasks/bad"] {
        assert_eq!(
            lines.recv().unwrap(),
            format!(
                "GET /v{}.{}{target} HTTP/1.1",
                API_VERSION.major, API_VERSION.minor
            )
        );
    }
    server.join().unwrap();
}

#[tokio::test]
async fn non_success_status_is_not_a_task() {
    let (client, lines, server) = fixture(vec![
        (304, String::new()),
        (101, String::new()),
        (404, json!({"message":"not found"}).to_string()),
    ]);
    let error = client.list_tasks(None).await.unwrap_err();
    assert_eq!(error.api_error().unwrap().status_code, 304);
    let error = client.inspect_task("t").await.unwrap_err();
    assert_eq!(error.api_error().unwrap().status_code, 101);
    let error = client.inspect_task("t").await.unwrap_err();
    assert_eq!(error.api_error().unwrap().status_code, 404);
    assert!(error.to_string().contains("not found"));
    drop(lines);
    server.join().unwrap();
}

#[tokio::test]
async fn authenticated_proxy_rejection_withholds_peer_text_for_both_reads() {
    use neotales_docker::{Endpoint, ForwardProxy, ProxyPolicy};
    const CANARY: &str = "peer-supplied-canary";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut req = Vec::new();
            let mut bytes = [0; 1024];
            while !req.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut bytes).unwrap();
                assert!(n > 0);
                req.extend_from_slice(&bytes[..n]);
            }
            let body = format!("{{\"message\":\"{CANARY}\"}}");
            write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http("http://127.0.0.1:1".to_owned()),
        ProxyPolicy::Http(
            ForwardProxy::with_basic_auth(proxy, "fixture-user", "fixture-password").unwrap(),
        ),
    )
    .unwrap();
    for error in [
        client.list_tasks(None).await.unwrap_err(),
        client.inspect_task("t").await.unwrap_err(),
    ] {
        assert_eq!(error.api_error().unwrap().status_code, 403);
        assert!(!format!("{error:?} {error}").contains(CANARY));
        assert!(error.api_error().unwrap().message.contains("withheld"));
    }
    server.join().unwrap();
}
