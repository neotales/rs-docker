//! Bounded, label-scoped registry fixture for the opt-in `BuildKit` test.
//!
//! SIGKILL, daemon loss, or a delayed Docker operation can outlive cleanup. The
//! emitted label identifies only this invocation for manual reconciliation.

use std::{
    fmt::Write as _,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const LABEL: &str = "neotales.buildkit-cache-test";

fn docker(args: &[&str], seconds: &str) -> std::io::Result<Output> {
    Command::new("timeout")
        .args(["--kill-after=2s", seconds, "docker"])
        .args(args)
        .stdin(Stdio::null())
        .output()
}

fn checked(args: &[&str]) -> Output {
    let output = docker(args, "60s")
        .unwrap_or_else(|_| panic!("live BuildKit cache test requires Docker CLI and timeout"));
    assert!(
        output.status.success(),
        "live BuildKit cache test requires a running Docker daemon and a locally available registry:2 image (Docker {} failed: {})",
        args.first().unwrap_or(&""),
        output.status
    );
    output
}

fn text(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout)
        .expect("Docker output must be UTF-8")
        .trim()
}

pub(super) struct Registry {
    token: String,
    name: String,
    volume: String,
    pub port: u16,
    pub image_tag: String,
    pub image_ids: Vec<String>,
    setup_complete: bool,
    cleaned: bool,
}

impl Registry {
    pub(super) fn start() -> Self {
        assert_eq!(
            std::env::var("NEOTALES_DOCKER_BUILDKIT").as_deref(),
            Ok("1"),
            "set NEOTALES_DOCKER_BUILDKIT=1 to run this live test"
        );
        checked(&["info", "--format", "{{.ServerVersion}}"]);
        let image = checked(&["image", "inspect", "registry:2", "--format", "{{.Id}}"]);
        println!("REGISTRY IMAGE ID: {}", text(&image));
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).expect("OS randomness is required");
        let mut token = String::from("cache-test-");
        for byte in random {
            write!(token, "{byte:02x}").expect("write to string");
        }
        let name = format!("neotales-{token}");
        let volume = format!("neotales-{token}");
        let image_tag = format!("neotales-{token}:test");
        let mut registry = Self {
            token,
            name,
            volume,
            port: 0,
            image_tag,
            image_ids: Vec::new(),
            setup_complete: false,
            cleaned: false,
        };
        let label = format!("{LABEL}={}", registry.token);
        println!("REGISTRY FIXTURE LABEL: {label}");
        checked(&["volume", "create", "--label", &label, &registry.volume]);
        checked(&[
            "run",
            "-d",
            "--pull=never",
            "--name",
            &registry.name,
            "--label",
            &label,
            "-p",
            "127.0.0.1::5000",
            "-v",
            &format!("{}:/var/lib/registry", registry.volume),
            "registry:2",
        ]);
        let output = checked(&["port", &registry.name, "5000/tcp"]);
        let address: SocketAddrV4 = text(&output).parse().expect("loopback registry port");
        assert_eq!(
            *address.ip(),
            Ipv4Addr::LOCALHOST,
            "registry must bind loopback only"
        );
        registry.port = address.port();
        let deadline = Instant::now() + Duration::from_secs(30);
        while registry.request("GET", "/v2/") != Some(200) {
            assert!(
                Instant::now() < deadline,
                "registry /v2/ did not become ready within 30 seconds"
            );
            thread::sleep(Duration::from_millis(200));
        }
        registry.setup_complete = true;
        registry
    }

    pub(super) fn request(&self, method: &str, path: &str) -> Option<u16> {
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port);
        let mut stream =
            TcpStream::connect_timeout(&address.into(), Duration::from_secs(1)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .ok()?;
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json\r\nConnection: close\r\n\r\n").ok()?;
        let mut bytes = [0; 512];
        let n = stream.read(&mut bytes).ok()?;
        let status = std::str::from_utf8(&bytes[..n])
            .ok()?
            .split_whitespace()
            .nth(1)?;
        status.parse().ok()
    }

    pub(super) fn assert_manifest_put(&self) {
        let output = checked(&["logs", &self.name]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.lines().chain(stderr.lines()).any(|line| line
                .contains("PUT /v2/neotales-cache-test/manifests/cache")
                && line.contains(" 201 ")),
            "registry did not log cache manifest PUT 201"
        );
        println!("REGISTRY EVIDENCE: PUT cache manifest 201");
    }
    fn cleanup(&mut self) -> bool {
        if self.cleaned {
            return true;
        }
        // These commands are bounded and non-panicking even while unwinding.
        for args in [
            vec!["rm", "-fv", self.name.as_str()],
            vec!["volume", "rm", self.volume.as_str()],
            vec!["image", "rm", self.image_tag.as_str()],
        ] {
            let _ = docker(&args, "20s");
        }
        for id in &self.image_ids {
            let _ = docker(&["image", "rm", id], "20s");
        }
        let filter = format!("label={LABEL}={}", self.token);
        let containers = docker(&["ps", "-aq", "--filter", &filter], "5s");
        let volumes = docker(&["volume", "ls", "-q", "--filter", &filter], "5s");
        let clean = matches!(&containers, Ok(out) if out.status.success() && out.stdout.is_empty())
            && matches!(&volumes, Ok(out) if out.status.success() && out.stdout.is_empty());
        if clean && self.setup_complete {
            eprintln!("REGISTRY CLEANUP: no containers or volumes with {filter}");
        } else {
            eprintln!(
                "REGISTRY CLEANUP: reconcile {filter} after Docker recovers or delayed operations settle"
            );
        }
        self.cleaned = clean;
        clean
    }

    pub(super) fn finish(mut self) {
        assert!(self.cleanup(), "registry fixture cleanup failed");
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
