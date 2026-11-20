//! Swarm task reads through a captured local endpoint.
//!
//! The parent test runs a child that stands up a Unix listener over the
//! captured `DOCKER_HOST` and answers the task list and inspect routes, so the
//! reads are proved against a real socket rather than a mock. Unix only: the
//! fixture binds an `AF_UNIX` socket.
#![cfg(unix)]
use neotales_docker::{API_VERSION, DockerClient};
use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[test]
fn captured_local_target_serves_task_reads() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let completed = dir.path().join("worker-completed");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "local_worker", "--ignored"])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("TASK_SOCKET", &socket)
        .env("TASK_WORKER_COMPLETED", &completed)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("local worker timed out");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    assert!(
        completed.is_file(),
        "the child did not run and complete local_worker"
    );
}

#[tokio::test]
#[ignore = "run in child with isolated DOCKER_HOST"]
async fn local_worker() {
    let listener = UnixListener::bind(std::env::var_os("TASK_SOCKET").unwrap()).unwrap();
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        for (path, body) in [
            ("/tasks", "[{\"Spec\":{\"Unknown\":true}}]"),
            ("/tasks/id", "{\"Spec\":{\"Unknown\":true}}"),
            ("/tasks/id/logs", "\u{1}\0\0\0\0\0\0\u{3}out"),
        ] {
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "local fixture timed out");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("local accept: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut req = Vec::new();
            let mut buf = [0; 1024];
            while !req.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                req.extend_from_slice(&buf[..n]);
            }
            let req = String::from_utf8(req).unwrap();
            assert_eq!(
                req.lines().next().unwrap(),
                format!(
                    "GET /v{}.{}{path} HTTP/1.1",
                    API_VERSION.major, API_VERSION.minor
                )
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    let client = DockerClient::connect_local().unwrap();
    assert!(client.raw_engine().is_ok());
    assert_eq!(
        client.list_tasks(None).await.unwrap()[0].additional["Spec"]["Unknown"],
        true
    );
    assert_eq!(
        client.inspect_task("id").await.unwrap().additional["Spec"]["Unknown"],
        true
    );
    let mut logs = client.task_logs("id", None);
    let frame = tokio::time::timeout(Duration::from_secs(5), logs.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.payload, b"out");
    server.join().unwrap();
    std::fs::write(std::env::var_os("TASK_WORKER_COMPLETED").unwrap(), b"done").unwrap();
}
