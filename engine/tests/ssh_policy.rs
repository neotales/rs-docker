//! Host-key policy, port handling, and `dial-stdio` traffic over a controlled
//! fake `ssh` binary.
//!
//! These tests are daemon-free and credential-free. Each case puts a small
//! executable on `PATH` under the name `ssh`. The fake records its arguments,
//! applies the host-key policy found in the child's `$HOME/.ssh/config` the way
//! OpenSSH does, and then answers one Engine `/_ping` request over its standard
//! streams. That exercises the same process boundary as the real binary without
//! a real SSH server, key, or daemon.
//!
//! The child process exists because the transport resolves `ssh` from `PATH`.
//! Changing `PATH` for the whole test process would be a process-global mutation
//! shared by every parallel test, so each case re-executes this test binary with
//! an isolated environment instead. The `fake_ssh_child` test is the body that
//! runs there; when it is launched normally it returns immediately.

#![cfg(all(feature = "ssh", unix))]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
};

use neotales_docker::DockerClient;
use tempfile::TempDir;

const CHILD_ENV: &str = "NEOTALES_FAKE_SSH_CHILD";
const ENDPOINT_ENV: &str = "NEOTALES_FAKE_SSH_ENDPOINT";
const TRANSPORT_ENV: &str = "NEOTALES_FAKE_SSH_TRANSPORT";
const LOG_ENV: &str = "NEOTALES_FAKE_SSH_LOG";
const HOST_STATE_ENV: &str = "NEOTALES_FAKE_SSH_HOST_STATE";

const FAKE_SSH: &str = r#"#!/bin/sh
{
  for argument in "$@"; do
    printf 'arg %s\n' "$argument"
  done
  printf 'end\n'
} >> "$NEOTALES_FAKE_SSH_LOG"

policy=$(awk 'tolower($1) == "stricthostkeychecking" { print tolower($2) }' \
  "$HOME/.ssh/config" 2>/dev/null | tail -n 1)
for argument in "$@"; do
  case "$argument" in
    StrictHostKeyChecking=*) policy=$(printf '%s' "${argument#*=}" | tr '[:upper:]' '[:lower:]') ;;
  esac
done
[ -n "$policy" ] || policy=ask

case "$NEOTALES_FAKE_SSH_HOST_STATE" in
  unknown)
    case "$policy" in
      no|accept-new) ;;
      *) printf 'Host key verification failed.\n' >&2; exit 255 ;;
    esac
    ;;
  changed)
    case "$policy" in
      no) printf 'Warning: host key changed but the user allowed it.\n' >&2 ;;
      *)
        printf 'REMOTE HOST IDENTIFICATION HAS CHANGED!\n' >&2
        exit 255
        ;;
    esac
    ;;
esac

while IFS= read -r line; do
  line=$(printf '%s' "$line" | tr -d '\r')
  [ -n "$line" ] || break
done
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nApi-Version: 1.55\r\n\r\nOK'
"#;

/// The body that runs in the isolated child process.
#[test]
fn fake_ssh_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }

    let endpoint = std::env::var(ENDPOINT_ENV).expect("the child names an endpoint");
    let transport = std::env::var(TRANSPORT_ENV).expect("the child names a transport");
    let endpoint = neotales_docker::Endpoint::parse(&endpoint).expect("a valid ssh endpoint");
    let client = if transport.starts_with("managed") {
        DockerClient::connect_ssh_managed(
            &std::env::var(ENDPOINT_ENV).unwrap(),
            &std::path::PathBuf::from(std::env::var("HOME").unwrap()).join("known_hosts"),
        )
        .password("explicit-password".into())
        .connect()
        .expect("a managed client")
    } else {
        DockerClient::connect_endpoint_with_version(&endpoint, neotales_docker::API_VERSION)
            .expect("an ssh client")
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let outcome: Result<(), String> = runtime.block_on(async {
        match transport.as_str() {
            "bollard" | "managed" => match client.ping().await {
                Ok(_) => Ok(()),
                Err(error) => Err(error.to_string()),
            },
            "native" => {
                let engine = client.raw_engine().map_err(|error| error.to_string())?;
                neotales_docker::raw::ping(&engine)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            "managed-owned" => {
                let engine = client.raw_engine().map_err(|error| error.to_string())?;
                neotales_docker::raw::ping(&engine)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            "managed-swarm" => client
                .initialize_swarm(neotales_docker::SwarmInitOptions::new())
                .await
                .map(|_| ())
                .map_err(|error| error.to_string()),
            other => Err(format!("unknown transport {other}")),
        }
    });

    if let Err(message) = outcome {
        eprintln!("FAKE_SSH_REQUEST_FAILED: {message}");
        std::process::exit(3);
    }
}

#[test]
fn managed_ping_never_uses_ambient_ssh() {
    for transport in ["managed", "managed-owned", "managed-swarm"] {
        let scenario = Scenario::new();
        // A directory cannot be read as a known-hosts file, even when the
        // native ssh config would permit the connection.
        fs::create_dir(scenario.home().join("known_hosts")).unwrap();
        let output = scenario.run("ssh://deploy@127.0.0.1:1", transport, "known");
        assert!(
            !output.status.success(),
            "{transport} unexpectedly succeeded"
        );
        assert!(
            scenario.recorded_argvs().is_empty(),
            "{transport} invoked ambient ssh"
        );
    }
}

/// One isolated fake-`ssh` environment.
struct Scenario {
    directory: TempDir,
}

impl Scenario {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("a scenario directory");
        let binary = directory.path().join("ssh");
        fs::write(&binary, FAKE_SSH).expect("the fake ssh script");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))
            .expect("an executable fake ssh");
        fs::create_dir_all(directory.path().join("home/.ssh")).expect("the child's .ssh directory");
        let scenario = Self { directory };
        scenario.open_log();
        scenario
    }

    fn home(&self) -> PathBuf {
        self.directory.path().join("home")
    }

    fn log_path(&self) -> PathBuf {
        self.directory.path().join("ssh-log")
    }

    fn open_log(&self) {
        fs::write(self.log_path(), String::new()).expect("an empty argv log");
    }

    fn configure(&self, text: &str) {
        fs::write(self.home().join(".ssh/config"), text).expect("an ssh_config");
    }

    fn run(&self, endpoint: &str, transport: &str, host_state: &str) -> Output {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let path = format!(
            "{}:{}",
            self.directory.path().display(),
            path.to_string_lossy()
        );
        Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", "fake_ssh_child", "--nocapture"])
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.home())
            .env(CHILD_ENV, "1")
            .env(ENDPOINT_ENV, endpoint)
            .env(TRANSPORT_ENV, transport)
            .env(LOG_ENV, self.log_path())
            .env(HOST_STATE_ENV, host_state)
            .output()
            .expect("re-execute the test binary")
    }

    /// Every recorded argv, one inner vector per `ssh` invocation.
    fn recorded_argvs(&self) -> Vec<Vec<String>> {
        let log = fs::read_to_string(self.log_path()).expect("the argv log");
        let mut recordings = Vec::new();
        let mut current = Vec::new();
        for line in log.lines() {
            if line == "end" {
                recordings.push(std::mem::take(&mut current));
            } else if let Some(argument) = line.strip_prefix("arg ") {
                current.push(argument.to_owned());
            }
        }
        recordings
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output, case: &str) {
    assert!(
        output.status.success(),
        "{case} failed: status {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        stderr(output)
    );
}

fn assert_no_policy_override(arguments: &[String]) {
    for argument in arguments {
        assert!(
            !argument.contains("StrictHostKeyChecking"),
            "the transport must not override the user's host-key policy: {arguments:?}"
        );
        assert!(
            !argument.contains("BatchMode"),
            "the transport must not disable interactive authentication: {arguments:?}"
        );
        assert!(
            !argument.contains("UserKnownHostsFile"),
            "the transport must not redirect the user's known-hosts file: {arguments:?}"
        );
    }
}

fn assert_dial_stdio(arguments: &[String]) {
    let expected = ["docker", "system", "dial-stdio"]
        .map(str::to_owned)
        .to_vec();
    assert_eq!(
        arguments.get(arguments.len().saturating_sub(3)..),
        Some(expected.as_slice()),
        "the remote command must be docker system dial-stdio: {arguments:?}"
    );
}

#[test]
fn an_unknown_host_is_rejected_when_the_user_configured_nothing() {
    for transport in ["bollard", "native"] {
        let scenario = Scenario::new();
        let output = scenario.run("ssh://deploy@example.test", transport, "unknown");
        assert!(
            !output.status.success(),
            "{transport} accepted an unknown host without a configured policy"
        );
        assert!(
            stderr(&output).contains("Host key verification failed"),
            "{transport} did not report the host-key rejection: {}",
            stderr(&output)
        );
        for arguments in scenario.recorded_argvs() {
            assert_no_policy_override(&arguments);
            assert_dial_stdio(&arguments);
        }
    }
}

#[test]
fn a_changed_host_is_rejected_under_accept_new() {
    for transport in ["bollard", "native"] {
        let scenario = Scenario::new();
        scenario.configure("StrictHostKeyChecking accept-new\n");
        let output = scenario.run("ssh://deploy@example.test", transport, "changed");
        assert!(
            !output.status.success(),
            "{transport} accepted a changed host key under accept-new"
        );
        assert!(
            stderr(&output).contains("REMOTE HOST IDENTIFICATION HAS CHANGED"),
            "{transport} did not report the changed host key: {}",
            stderr(&output)
        );
        for arguments in scenario.recorded_argvs() {
            assert_no_policy_override(&arguments);
        }
    }
}

#[test]
fn accept_new_from_the_users_configuration_still_applies() {
    for transport in ["bollard", "native"] {
        let scenario = Scenario::new();
        scenario.configure("StrictHostKeyChecking accept-new\n");
        let output = scenario.run("ssh://deploy@example.test", transport, "unknown");
        assert_success(&output, transport);
    }
}

#[test]
fn an_explicit_default_port_is_passed_to_ssh() {
    for transport in ["bollard", "native"] {
        let scenario = Scenario::new();
        scenario.configure("StrictHostKeyChecking accept-new\nPort 2222\n");
        let output = scenario.run("ssh://deploy@example.test:22", transport, "known");
        assert_success(&output, transport);
        let recordings = scenario.recorded_argvs();
        assert_eq!(recordings.len(), 1, "{transport}: one ssh invocation");
        let arguments = &recordings[0];
        assert!(
            arguments.windows(2).any(|pair| pair == ["-p", "22"]),
            "{transport} dropped an explicit default port: {arguments:?}"
        );
        assert_dial_stdio(arguments);
        assert_no_policy_override(arguments);
    }
}

#[test]
fn an_absent_port_is_left_to_ssh_config() {
    for transport in ["bollard", "native"] {
        let scenario = Scenario::new();
        scenario.configure("StrictHostKeyChecking accept-new\nPort 2222\n");
        let output = scenario.run("ssh://deploy@example.test", transport, "known");
        assert_success(&output, transport);
        let recordings = scenario.recorded_argvs();
        assert_eq!(recordings.len(), 1, "{transport}: one ssh invocation");
        let arguments = &recordings[0];
        assert!(
            !arguments.iter().any(|argument| argument == "-p"),
            "{transport} invented a port for an endpoint that named none: {arguments:?}"
        );
        assert_dial_stdio(arguments);
    }
}

/// A known host is a normal success, which proves the fake served the response
/// the client actually read rather than only that a process started.
#[test]
fn a_known_host_carries_a_real_engine_request() {
    for transport in ["bollard", "native"] {
        let scenario = Scenario::new();
        scenario.configure("StrictHostKeyChecking accept-new\n");
        let output = scenario.run("ssh://deploy@example.test:2222", transport, "known");
        assert_success(&output, transport);
        let recordings = scenario.recorded_argvs();
        assert_eq!(recordings.len(), 1);
        assert_dial_stdio(&recordings[0]);
        assert!(
            recordings[0].windows(2).any(|pair| pair == ["-p", "2222"]),
            "{transport} did not pass the non-default port: {:?}",
            recordings[0]
        );
    }
}
