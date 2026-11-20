//! Independent, opt-in OpenSSH password interoperability test.
//!
//! Run only on a trusted ephemeral Linux host with Docker and registry access:
//!
//! `NEOTALES_DOCKER_OPENSSH_PASSWORD=1 cargo test -p neotales-docker --all-features --locked --test managed_ssh_openssh_password -- --ignored --test-threads=1`
//!
//! Nothing invokes Docker before the environment check. The peer has no host
//! mounts, Docker socket, host networking, or privileged mode. Password and
//! host key are generated per invocation; the password goes to `chpasswd` on
//! stdin and the public host key is read using `docker exec`, not the network.
//!
//! The linux/amd64 Debian image manifest digest was obtained from Docker Hub's
//! official Debian tag metadata on 2026-11-16:
//! <https://hub.docker.com/v2/repositories/library/debian/tags/bookworm-slim>
//! The OpenSSH package version comes from Debian's bookworm amd64 Packages index:
//! <https://deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages.xz>
//! Apt requires that exact version and the test checks the installed version.
//! The repository is not a snapshot: the package can disappear and dependencies
//! can change, so the installation is not fully reproducible. The live test
//! reports `sshd -V`; only a successful run establishes what was exercised.
//!
//! SIGKILL, daemon loss, or creation after the bounded cleanup window can leave
//! a container behind. Cleanup diagnostics give this invocation's unique LABEL.
//! Reconcile only that label after the daemon recovers and delayed operations
//! settle: `docker ps -aq --no-trunc --filter 'label=neotales.managed-ssh-password=LABEL'`.
//! To remove those containers only, pipe the same command to `xargs -r docker rm -f`.
//! If the process was killed before reporting the label, inspect labels with
//! `docker ps -a --filter 'label=neotales.managed-ssh-password' --format '{{.ID}} {{.Label "neotales.managed-ssh-password"}}'`
//! and choose the specific stale invocation before using the label-scoped command.

#![cfg(all(feature = "ssh", target_os = "linux"))]

use std::{
    fmt::Write as _,
    io::{Read, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use neotales_docker::{DockerClient, ErrorKind, ManagedSshEstablishmentFailure};
use serde_json::Value;

const OPT_IN: &str = "NEOTALES_DOCKER_OPENSSH_PASSWORD";
const LABEL: &str = "neotales.managed-ssh-password";
const IMAGE: &str =
    "debian@sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018";
const OPENSSH_PACKAGE_VERSION: &str = "1:9.2p1-2+deb12u10";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

// The fake executable is deliberately not Docker. It accepts only the
// managed transport's exec request and a bounded HTTP ping, once per process.
const SETUP: &str = r"set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends openssh-server=1:9.2p1-2+deb12u10 python3
mkdir -p /run/sshd
useradd -m -s /bin/sh fixture
rm -f /etc/ssh/ssh_host_*
ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
cat > /etc/ssh/sshd_config <<'CONFIG'
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
UsePAM no
PermitRootLogin no
AllowUsers fixture
PasswordAuthentication yes
AuthenticationMethods password
PubkeyAuthentication no
KbdInteractiveAuthentication no
LogLevel VERBOSE
CONFIG
cat > /usr/local/bin/docker <<'PYTHON'
#!/usr/bin/python3
import re, sys
if sys.argv[1:] != ['system', 'dial-stdio']:
    sys.exit(1)
open('/tmp/fake-docker-started', 'w').close()
request = bytearray()
while b'\r\n\r\n' not in request and len(request) < 8192:
    byte = sys.stdin.buffer.read(1)
    if not byte:
        sys.exit(2)
    request += byte
if b'\r\n\r\n' not in request or not re.fullmatch(rb'GET /(?:v[0-9]+\.[0-9]+/)?_ping HTTP/1\.1', bytes(request).split(b'\r\n', 1)[0]):
    sys.exit(3)
sys.stdout.buffer.write(b'HTTP/1.1 200 OK\r\nApi-Version: 1.55\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
sys.stdout.buffer.flush()
PYTHON
chmod 755 /usr/local/bin/docker
";

fn random_hex() -> String {
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .expect("OS randomness is required");
    let mut result = String::new();
    for byte in bytes {
        write!(result, "{byte:02x}").expect("write to string");
    }
    result
}

// timeout bounds both daemon operations and cleanup, including daemon loss.
fn docker(args: &[&str], input: Option<&[u8]>) -> Output {
    let mut child = Command::new("timeout")
        .args(["--kill-after=2s", "120s", "docker"])
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| panic!("{OPT_IN}=1 requires Docker CLI and GNU timeout"));
    if let Some(input) = input {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input)
            .expect("write Docker stdin");
    }
    child.wait_with_output().expect("wait for Docker CLI")
}

fn checked(args: &[&str], input: Option<&[u8]>) -> Output {
    let output = docker(args, input);
    assert!(
        output.status.success(),
        "Docker operation {} failed (status {}); Docker, daemon, registry access and image prerequisites are required",
        args.first().unwrap_or(&""),
        output.status
    );
    output
}

fn text(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout)
        .expect("Docker returned UTF-8")
        .trim()
}

struct Peer {
    label: String,
    id: Option<String>,
    _directory: tempfile::TempDir,
    known_hosts: PathBuf,
    address: SocketAddr,
}

// Cleanup must never panic while another failure is unwinding. Each invocation
// has a shorter bound than setup, and neither stderr nor daemon output is echoed.
fn cleanup_docker(args: &[&str]) -> std::io::Result<Output> {
    Command::new("timeout")
        .args(["--kill-after=1s", "5s", "docker"])
        .args(args)
        .stdin(Stdio::null())
        .output()
}

fn cleanup_warning(label: &str, reason: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "OpenSSH peer cleanup: {reason}; reconcile unique label {LABEL}={label} after delayed Docker operations settle: docker ps -aq --no-trunc --filter 'label={LABEL}={label}' | xargs -r docker rm -f"
    );
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(id) = &self.id {
            if !matches!(cleanup_docker(&["rm", "-f", id]), Ok(output) if output.status.success()) {
                cleanup_warning(&self.label, "container removal failed");
            }
            return;
        }

        // A failed or timed-out run may still create its container later. Query
        // this invocation's unguessable label repeatedly, but always warn: no
        // finite window proves that a delayed creation can no longer happen.
        let filter = format!("label={LABEL}={}", self.label);
        for attempt in 0..3 {
            match cleanup_docker(&["ps", "-aq", "--no-trunc", "--filter", &filter]) {
                Ok(output) if output.status.success() => {
                    match std::str::from_utf8(&output.stdout) {
                        Ok(ids) => {
                            for id in ids.lines().take(4) {
                                // Never pass unexpected output as a Docker option
                                // or remove anything not returned by this query.
                                if id.len() != 64
                                    || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
                                {
                                    cleanup_warning(
                                        &self.label,
                                        "invalid container ID in discovery output",
                                    );
                                    continue;
                                }
                                if !matches!(cleanup_docker(&["rm", "-f", id]), Ok(result) if result.status.success())
                                {
                                    cleanup_warning(
                                        &self.label,
                                        "discovered container removal failed",
                                    );
                                }
                            }
                        }
                        Err(_) => cleanup_warning(
                            &self.label,
                            "container discovery returned invalid UTF-8",
                        ),
                    }
                }
                Ok(_) | Err(_) => {
                    cleanup_warning(&self.label, "label-filtered container discovery failed");
                }
            }
            if attempt < 2 {
                thread::sleep(Duration::from_secs(1));
            }
        }
        cleanup_warning(
            &self.label,
            "container creation may outlive the cleanup window",
        );
    }
}

fn check_openssh_version(id: &str) {
    let package = checked(
        &[
            "exec",
            id,
            "dpkg-query",
            "-W",
            "-f=${Version}",
            "openssh-server",
        ],
        None,
    );
    assert_eq!(
        text(&package),
        OPENSSH_PACKAGE_VERSION,
        "unexpected OpenSSH package"
    );
    eprintln!("OpenSSH Debian package: {}", text(&package));
    let version = docker(&["exec", id, "/usr/sbin/sshd", "-V"], None);
    eprintln!(
        "OpenSSH version: {}",
        String::from_utf8_lossy(&version.stderr).trim()
    );
}

impl Peer {
    fn start(password: &str) -> Self {
        checked(&["version", "--format", "{{.Server.Version}}"], None);
        let label = random_hex();
        let directory = tempfile::tempdir().expect("temporary trust directory");
        let mut peer = Self {
            label,
            id: None,
            known_hosts: directory.path().join("known_hosts"),
            _directory: directory,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        };
        let label_arg = format!("{LABEL}={}", peer.label);
        let result = checked(
            &[
                "run",
                "-d",
                "--platform",
                "linux/amd64",
                "--label",
                &label_arg,
                "-p",
                "127.0.0.1::22",
                IMAGE,
                "sleep",
                "infinity",
            ],
            None,
        );
        peer.id = Some(text(&result).to_owned());
        let id = peer.id.as_deref().expect("container ID");
        let inspect = checked(&["inspect", id], None);
        let inspect: Value = serde_json::from_slice(&inspect.stdout).expect("Docker inspect JSON");
        let container = &inspect[0];
        assert_eq!(container["Id"], id);
        assert_eq!(container["Config"]["Labels"][LABEL], peer.label);
        assert_eq!(container["HostConfig"]["Privileged"], false);
        assert_ne!(container["HostConfig"]["NetworkMode"], "host");
        assert!(
            container["Mounts"]
                .as_array()
                .expect("mount list")
                .is_empty(),
            "expected no entries"
        );
        let bindings = container["NetworkSettings"]["Ports"]["22/tcp"]
            .as_array()
            .expect("port bindings");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0]["HostIp"], "127.0.0.1");
        let port: u16 = bindings[0]["HostPort"]
            .as_str()
            .expect("published port")
            .parse()
            .expect("valid port");
        assert_ne!(port, 0);
        peer.address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        checked(&["exec", "-i", id, "sh", "-s"], Some(SETUP.as_bytes()));
        check_openssh_version(id);
        let credentials = format!("fixture:{password}\n");
        checked(
            &["exec", "-i", id, "chpasswd"],
            Some(credentials.as_bytes()),
        );
        let host_key = checked(
            &["exec", id, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"],
            None,
        );
        let fields: Vec<_> = text(&host_key).split_whitespace().collect();
        assert_eq!(fields.first(), Some(&"ssh-ed25519"));
        let key = fields.get(1).expect("OpenSSH public host key");
        std::fs::write(
            &peer.known_hosts,
            format!("[127.0.0.1]:{port} ssh-ed25519 {key}\n"),
        )
        .expect("write trust file");
        checked(
            &[
                "exec",
                "-d",
                id,
                "sh",
                "-c",
                "exec /usr/sbin/sshd -D -e 2>/tmp/sshd.log",
            ],
            None,
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        // Docker's loopback port proxy may accept TCP before sshd has bound
        // inside the container. Require sshd's own readiness log as well; a
        // successful proxy connection alone can otherwise race the handshake.
        loop {
            let listening = peer.exec(&["grep", "-q", "^Server listening on ", "/tmp/sshd.log"]);
            if listening.status.success()
                && TcpStream::connect_timeout(&peer.address, Duration::from_millis(250)).is_ok()
            {
                break;
            }
            assert!(Instant::now() < deadline, "OpenSSH did not become ready");
            thread::sleep(Duration::from_millis(100));
        }
        peer
    }

    fn client(&self, password: String) -> DockerClient {
        DockerClient::connect_ssh_managed(
            &format!("ssh://fixture@{}", self.address),
            &self.known_hosts,
        )
        .timeout(REQUEST_TIMEOUT)
        .request_deadline(Some(REQUEST_TIMEOUT))
        .password(password.into())
        .connect()
        .expect("managed SSH client")
    }

    fn exec(&self, args: &[&str]) -> Output {
        let mut command = vec!["exec", self.id.as_deref().expect("container ID")];
        command.extend_from_slice(args);
        docker(&command, None)
    }
}

#[tokio::test]
#[ignore = "opt-in: NEOTALES_DOCKER_OPENSSH_PASSWORD=1"]
async fn openssh_password_acceptance_and_rejection() {
    if std::env::var(OPT_IN).as_deref() != Ok("1") {
        eprintln!("skipping OpenSSH password test: set {OPT_IN}=1");
        return;
    }
    let password = random_hex();
    let mut wrong_password = random_hex();
    while wrong_password == password {
        wrong_password = random_hex();
    }
    let peer = Peer::start(&password);
    let error = tokio::time::timeout(REQUEST_TIMEOUT, peer.client(wrong_password.clone()).ping())
        .await
        .expect("rejection timed out")
        .expect_err("OpenSSH accepted a wrong password");
    let diagnostic = format!("{error} | {error:?}");
    let redacted = diagnostic
        .replace(&password, "[redacted]")
        .replace(&wrong_password, "[redacted]");
    eprintln!(
        "wrong-password client error: kind={:?}, managed_failure={:?}, diagnostic={redacted}",
        error.kind(),
        error.managed_ssh_establishment_failure()
    );
    assert!(
        !diagnostic.contains(&password) && !diagnostic.contains(&wrong_password),
        "client diagnostic contained a credential"
    );
    let rejection_log = peer.exec(&["cat", "/tmp/sshd.log"]);
    assert!(
        rejection_log.status.success(),
        "could not read OpenSSH rejection log"
    );
    let rejection_log = text(&rejection_log);
    let redacted_log = rejection_log
        .replace(&password, "[redacted]")
        .replace(&wrong_password, "[redacted]");
    eprintln!("OpenSSH rejection log: {redacted_log}");
    assert!(
        !rejection_log.contains(&password) && !rejection_log.contains(&wrong_password),
        "OpenSSH log contained a credential"
    );
    assert!(
        rejection_log.contains("Failed password for fixture"),
        "OpenSSH did not log password rejection"
    );
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert_eq!(
        error.managed_ssh_establishment_failure(),
        Some(ManagedSshEstablishmentFailure::AuthenticationRejected)
    );
    assert!(error.is_managed_ssh_authentication_rejected());
    assert!(!format!("{error:?} {error}").contains(&wrong_password));
    assert_eq!(
        peer.exec(&["test", "-e", "/tmp/fake-docker-started"])
            .status
            .code(),
        Some(1),
        "fake endpoint ran or its absence could not be checked"
    );
    let ping = tokio::time::timeout(REQUEST_TIMEOUT, peer.client(password.clone()).ping())
        .await
        .expect("ping timed out")
        .expect("OpenSSH password ping");
    assert_eq!(ping.api_version.as_deref(), Some("1.55"));
    assert!(
        peer.exec(&["test", "-e", "/tmp/fake-docker-started"])
            .status
            .success()
    );
    let logs = peer.exec(&["cat", "/tmp/sshd.log"]);
    assert!(logs.status.success(), "could not read OpenSSH log");
    let logs = text(&logs);
    assert!(
        logs.contains("Accepted password for fixture"),
        "OpenSSH did not log password acceptance"
    );
    assert!(
        logs.contains("Failed password for fixture"),
        "OpenSSH did not log password rejection"
    );
    assert!(
        !logs.contains(&password) && !logs.contains(&wrong_password),
        "OpenSSH log contained a credential"
    );
    eprintln!(
        "OpenSSH logged rejected and accepted password authentication; fake endpoint answered ping"
    );
}
