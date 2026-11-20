//! Explicit per-client closure refuses before establishment on every route.
#![cfg(all(feature = "ssh", unix))]

use std::{net::TcpListener, time::Duration};

use neotales_docker::{
    DockerClient, ErrorKind, RegistryCredentials, ServiceSpec, ServiceUpdateOptions,
    SwarmInitOptions, SwarmUnlockOptions,
};

#[tokio::test]
async fn unlock_swarm_returns_the_managed_gate_without_connecting() {
    const KEY: &str = "SWMKEY-1-canary-managed-gate-do-not-log-me";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("ssh://test@{}", listener.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let known_hosts = directory.path().join("known_hosts");
    let client = DockerClient::connect_ssh_managed(&endpoint, &known_hosts)
        .require_closed()
        .password("test credential".into())
        .connect()
        .unwrap();

    let error = client
        .unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        })
        .await
        .expect_err("the managed gate must fail closed");

    assert_eq!(error.kind(), ErrorKind::Transport);
    assert_eq!(
        error.to_string(),
        "Docker transport error: managed SSH establishment is explicitly closed by client policy",
        "the stable local gate diagnostic was replaced: {error}"
    );
    let rendered = format!("{error:?}");
    assert!(
        !rendered.contains(KEY),
        "the managed gate leaked the key: {rendered}"
    );
    assert!(
        listener
            .accept()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
        "the managed unlock connected before returning the gate diagnostic"
    );
    assert!(!known_hosts.exists(), "the managed unlock wrote host trust");
}

#[tokio::test]
async fn service_update_returns_the_managed_gate_without_connecting() {
    const ENV: &str = "canary-managed-update-env-do-not-log-me";
    const SECRET: &str = "canary-managed-update-secret-do-not-log-me";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("ssh://test@{}", listener.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let known_hosts = directory.path().join("known_hosts");
    let client = DockerClient::connect_ssh_managed(&endpoint, &known_hosts)
        .require_closed()
        .password("test credential".into())
        .connect()
        .unwrap();
    let spec = ServiceSpec {
        name: Some("web".to_owned()),
        task_template: Some(serde_json::json!({
            "ContainerSpec": {"Image": "nginx:alpine", "Env": [format!("TOKEN={ENV}")]}
        })),
        ..ServiceSpec::default()
    };

    for (what, error) in [
        (
            "plain update",
            client
                .update_service(
                    "web",
                    ServiceUpdateOptions {
                        version: 1,
                        spec: spec.clone(),
                        rollback: false,
                    },
                )
                .await
                .expect_err("the managed gate must fail closed"),
        ),
        (
            "credentialed update",
            client
                .update_service_with_credentials(
                    "web",
                    ServiceUpdateOptions {
                        version: 1,
                        spec,
                        rollback: false,
                    },
                    "registry.example",
                    RegistryCredentials::new("probeuser", SECRET),
                )
                .await
                .expect_err("the managed gate must fail closed"),
        ),
    ] {
        assert_eq!(error.kind(), ErrorKind::Transport, "{what}");
        assert_eq!(
            error.to_string(),
            "Docker transport error: managed SSH establishment is explicitly closed by client policy",
            "{what}: the stable local gate diagnostic was replaced: {error}"
        );
        for rendered in [format!("{error}"), format!("{error:?}")] {
            assert!(!rendered.contains(ENV), "{what}: leaked env: {rendered}");
            assert!(
                !rendered.contains(SECRET),
                "{what}: leaked secret: {rendered}"
            );
        }
    }

    assert!(
        listener
            .accept()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
        "the managed update connected before returning the gate diagnostic"
    );
    assert!(!known_hosts.exists(), "the managed update wrote host trust");
}

#[tokio::test]
async fn concurrent_cancelled_requests_never_start_a_handshake_or_record_trust() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("ssh://test@{}", listener.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let known_hosts = directory.path().join("known_hosts");
    let client = DockerClient::connect_ssh_managed(&endpoint, &known_hosts)
        .require_closed()
        .password("test credential".into())
        .connect()
        .unwrap();
    let owned = client.raw_engine().unwrap();
    let ping = client.clone();
    let swarm = client.clone();
    let tasks = [
        tokio::spawn(async move { neotales_docker::raw::ping(&owned).await.is_err() }),
        tokio::spawn(async move { ping.ping().await.is_err() }),
        tokio::spawn(async move {
            swarm
                .initialize_swarm(SwarmInitOptions::new())
                .await
                .is_err()
        }),
    ];
    tokio::time::sleep(Duration::from_millis(100)).await;
    let completed = tasks.iter().all(tokio::task::JoinHandle::is_finished);
    for task in &tasks {
        task.abort();
    }
    // Keep accepted sockets alive until cancellation, then close them so an
    // unsafe blocking handshake cannot prevent the test runtime from exiting.
    let connections: Vec<_> = listener.incoming().take_while(Result::is_ok).collect();
    let count = connections.len();
    drop(connections);
    let results = futures_util::future::join_all(tasks).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        completed,
        "managed requests did not fail closed immediately"
    );
    assert!(
        results.into_iter().all(|result| matches!(result, Ok(true))),
        "every managed method must return an error"
    );
    assert_eq!(count, 0, "managed requests started SSH handshakes");
    assert!(
        listener
            .accept()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
        "a cancelled request connected later"
    );
    assert!(!known_hosts.exists(), "managed requests wrote host trust");
}
