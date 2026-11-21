//! The owned transport's HTTPS target, exercised through the public facade.
//!
//! Every fixture here is local and in-process: a synthetic CA, a real
//! `rustls` server on a loopback port, and no credential from any machine. The
//! tests reach the transport the way production does — `DockerClient` builds the
//! target, and `raw_engine()` exposes the engine that uses it — rather than
//! constructing a `RawTarget::Stream` by hand.
//!
//! # What is actually being proved
//!
//! A TLS-required server is the measure for "no plaintext fallback": a client
//! that downgraded would fail the handshake instead of producing the request
//! this file reads. The remaining tests pin the policy edges that are easy to
//! get wrong and impossible to see from a successful request: hostname and CA
//! verification by default, the explicit trust opt-out, expiry, handshake
//! signatures, mTLS client identity, the per-request stream, and the proxy
//! `CONNECT` leg.

#![cfg(feature = "tls")]
#![allow(missing_docs)]

use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use neotales_docker::raw;
use neotales_docker::{
    ApiVersion, DockerClient, Endpoint, ErrorKind, ForwardProxy, ProxyError, ProxyPolicy,
    TlsConfigError, TlsMaterial, TlsMaterialRole, TlsMaterialSource, TlsServerTrust,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// The version an explicit constructor passes to the owned transport.
const EXPLICIT_VERSION: ApiVersion = ApiVersion {
    major: 1,
    minor: 47,
};

/// A CA key and certificate used to sign fixture identities.
struct Ca {
    cert_der: CertificateDer<'static>,
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

/// A server identity signed by a [`Ca`].
struct ServerIdentity {
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
}

/// A client identity signed by a [`Ca`].
struct ClientIdentity {
    cert_pem: String,
    key_pem: String,
}

/// Files a `TlsMaterial` points at, kept alive for the test.
struct MaterialFixture {
    _directory: tempfile::TempDir,
    material: TlsMaterial,
}

/// A loopback TLS server that records what reached it.
struct TlsFixture {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    handshake_failures: Arc<AtomicUsize>,
    closed: Arc<Mutex<Option<Result<(), String>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TlsFixture {
    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn handshake_failures(&self) -> usize {
        self.handshake_failures.load(Ordering::SeqCst)
    }

    fn close_outcome(&self) -> Option<Result<(), String>> {
        self.closed
            .lock()
            .expect("the recorded close outcome")
            .clone()
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the recorded requests").clone()
    }

    fn address(&self) -> String {
        format!("https://localhost:{}", self.address.port())
    }
}

fn generate_ca(common_name: &str) -> Result<Ca, Box<dyn StdError>> {
    let key = KeyPair::generate()?;
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters
        .distinguished_name
        .push(DnType::CommonName, common_name);
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let certificate = parameters.self_signed(&key)?;
    Ok(Ca {
        cert_der: certificate.der().clone(),
        cert_pem: certificate.pem(),
        issuer: Issuer::new(parameters, key),
    })
}

fn generate_server(
    ca: &Ca,
    names: &[&str],
    expired: bool,
) -> Result<ServerIdentity, Box<dyn StdError>> {
    let key = KeyPair::generate()?;
    let mut parameters = CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )?;
    if expired {
        parameters.not_before = rcgen::date_time_ymd(2000, 1, 1);
        parameters.not_after = rcgen::date_time_ymd(2001, 1, 1);
    }
    parameters
        .distinguished_name
        .push(DnType::CommonName, "raw TLS test server");
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = parameters.signed_by(&key, &ca.issuer)?;
    Ok(ServerIdentity {
        cert_der: certificate.der().clone(),
        key_der: key.serialize_der(),
    })
}

fn generate_client(ca: &Ca) -> Result<ClientIdentity, Box<dyn StdError>> {
    let key = KeyPair::generate()?;
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters
        .distinguished_name
        .push(DnType::CommonName, "raw TLS test client");
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let certificate = parameters.signed_by(&key, &ca.issuer)?;
    Ok(ClientIdentity {
        cert_pem: certificate.pem(),
        key_pem: key.serialize_pem(),
    })
}

fn write_material(ca: &Ca, client: &ClientIdentity) -> Result<MaterialFixture, Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let ca_path = directory.path().join("ca.pem");
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&ca_path, &ca.cert_pem)?;
    std::fs::write(&cert_path, &client.cert_pem)?;
    std::fs::write(&key_path, &client.key_pem)?;
    Ok(MaterialFixture {
        _directory: directory,
        material: TlsMaterial {
            ca_path,
            cert_path,
            key_path,
        },
    })
}

fn material_files(
    ca: &str,
    cert: &str,
    key: &str,
) -> Result<(tempfile::TempDir, TlsMaterial), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let ca_path = directory.path().join("ca.pem");
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&ca_path, ca)?;
    std::fs::write(&cert_path, cert)?;
    std::fs::write(&key_path, key)?;
    Ok((
        directory,
        TlsMaterial {
            ca_path,
            cert_path,
            key_path,
        },
    ))
}

/// Records the `ClientHello` SNI and serves one fixed certificate.
struct RecordingResolver {
    certified: Arc<CertifiedKey>,
    sni: Arc<Mutex<Vec<Option<String>>>>,
}

impl fmt::Debug for RecordingResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecordingResolver")
    }
}

impl ResolvesServerCert for RecordingResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.sni
            .lock()
            .expect("the recorded server names")
            .push(hello.server_name().map(str::to_owned));
        Some(Arc::clone(&self.certified))
    }
}

/// Builds a server config whose certificate is `identity`, signed by `key_der`.
///
/// `key_der` is a parameter rather than read from `identity` so a test can
/// present a certificate and sign with a different key: that is the handshake
/// signature failure the explicit trust opt-out must still refuse.
fn server_config(
    identity: &ServerIdentity,
    client_ca: &Ca,
    key_der: &[u8],
    sni: Arc<Mutex<Vec<Option<String>>>>,
) -> Result<Arc<ServerConfig>, Box<dyn StdError>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let signing_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(key_der.to_vec().into()))?;
    let certified = CertifiedKey::new(vec![identity.cert_der.clone()], signing_key);

    let mut roots = RootCertStore::empty();
    roots.add(client_ca.cert_der.clone())?;
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()?;

    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier);
    Ok(Arc::new(builder.with_cert_resolver(Arc::new(
        RecordingResolver {
            certified: Arc::new(certified),
            sni,
        },
    ))))
}

/// Starts the fixture on IPv4 loopback.
fn start_tls_server(config: Arc<ServerConfig>, respond: bool) -> TlsFixture {
    start_tls_server_on("127.0.0.1:0", config, respond)
}

/// Starts the fixture on `bind`. `respond` false makes the peer hold the
/// connection open after reading the request, which is what a cancellation test
/// needs.
fn start_tls_server_on(bind: &str, config: Arc<ServerConfig>, respond: bool) -> TlsFixture {
    let listener = std::net::TcpListener::bind(bind).expect("bind a loopback port");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener non-blocking");
    let address = listener.local_addr().expect("read the bound address");

    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let handshake_failures = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(Mutex::new(None));

    let task = tokio::spawn({
        let connections = Arc::clone(&connections);
        let requests = Arc::clone(&requests);
        let handshake_failures = Arc::clone(&handshake_failures);
        let closed = Arc::clone(&closed);
        async move {
            let listener = TcpListener::from_std(listener).expect("adopt the fixture listener");
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let acceptor = TlsAcceptor::from(Arc::clone(&config));
                let connections = Arc::clone(&connections);
                let requests = Arc::clone(&requests);
                let handshake_failures = Arc::clone(&handshake_failures);
                let closed = Arc::clone(&closed);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        handshake_failures.fetch_add(1, Ordering::SeqCst);
                        return;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let Some(request) = read_head(&mut stream).await else {
                        return;
                    };
                    requests
                        .lock()
                        .expect("the recorded requests")
                        .push(request);
                    if respond {
                        let _ignored = stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                                  Content-Type: application/json\r\nConnection: close\r\n\r\n{}",
                            )
                            .await;
                        let _ignored = stream.flush().await;
                    } else {
                        let mut byte = [0_u8; 1];
                        let outcome = match tokio::time::timeout(
                            Duration::from_secs(2),
                            stream.read(&mut byte),
                        )
                        .await
                        {
                            Ok(Ok(0)) => Ok(()),
                            Ok(Ok(read)) => {
                                Err(format!("peer sent {read} byte(s) after cancellation"))
                            }
                            Ok(Err(error))
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::UnexpectedEof
                                ) =>
                            {
                                Ok(())
                            }
                            Ok(Err(error)) => Err(format!("read failed: {error}")),
                            Err(_) => Err("teardown timed out".to_owned()),
                        };
                        *closed.lock().expect("the recorded close outcome") = Some(outcome);
                    }
                });
            }
        }
    });

    TlsFixture {
        address,
        connections,
        requests,
        handshake_failures,
        closed,
        task,
    }
}

async fn read_head<S>(stream: &mut S) -> Option<String>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    for _ in 0..64 {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    (!head.is_empty()).then(|| String::from_utf8_lossy(&head).into_owned())
}

fn connect(
    host: &str,
    fixture: &TlsFixture,
    material: &TlsMaterial,
    trust: TlsServerTrust,
) -> DockerClient {
    DockerClient::connect_https_with_trust(
        &format!("https://{host}:{}", fixture.address.port()),
        material,
        ProxyPolicy::Direct,
        trust,
    )
    .expect("the HTTPS client")
}

/// One fixture, one CA, one client identity: the shape most tests need.
struct DirectFixture {
    fixture: TlsFixture,
    material: MaterialFixture,
    sni: Arc<Mutex<Vec<Option<String>>>>,
}

fn direct_fixture(
    names: &[&str],
    expired: bool,
    respond: bool,
) -> Result<DirectFixture, Box<dyn StdError>> {
    direct_fixture_on("127.0.0.1:0", names, expired, respond)
}

fn direct_fixture_on(
    bind: &str,
    names: &[&str],
    expired: bool,
    respond: bool,
) -> Result<DirectFixture, Box<dyn StdError>> {
    let ca = generate_ca("raw TLS test CA")?;
    let server = generate_server(&ca, names, expired)?;
    let client = generate_client(&ca)?;
    let material = write_material(&ca, &client)?;
    let sni = Arc::new(Mutex::new(Vec::new()));
    let config = server_config(&server, &ca, &server.key_der, Arc::clone(&sni))?;
    Ok(DirectFixture {
        fixture: start_tls_server_on(bind, config, respond),
        material,
        sni,
    })
}

/// A direct HTTPS request reaches a TLS-required, mTLS peer at the explicit
/// version and carries the target host in `Host`.
#[tokio::test]
async fn direct_https_raw_request_is_versioned_and_uses_mtls() -> Result<(), Box<dyn StdError>> {
    let fixture = direct_fixture(&["localhost"], false, true)?;
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Https {
            address: fixture.fixture.address(),
            material: Some(fixture.material.material.clone()),
        },
        EXPLICIT_VERSION,
    )?;

    let engine = client.raw_engine()?;
    assert_eq!(engine.version(), EXPLICIT_VERSION);
    let document = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine)).await??;
    assert_eq!(document, serde_json::json!({}));

    let requests = fixture.fixture.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("GET /v1.47/info HTTP/1.1\r\n"),
        "{}",
        requests[0]
    );
    assert!(
        requests[0].to_ascii_lowercase().contains(&format!(
            "host: localhost:{}\r\n",
            fixture.fixture.address.port()
        )),
        "{}",
        requests[0]
    );
    let server_names = fixture
        .sni
        .lock()
        .expect("the recorded server names")
        .clone();
    assert_eq!(server_names.len(), 1);
    assert_eq!(
        server_names[0].as_deref(),
        Some("localhost"),
        "the handshake did not carry the target host as SNI"
    );
    Ok(())
}

/// A client certificate signed by a CA the server does not trust is rejected,
/// even though the client trusts the server.
#[tokio::test]
async fn raw_https_rejects_a_client_certificate_from_another_ca() -> Result<(), Box<dyn StdError>> {
    let server_ca = generate_ca("raw TLS server CA")?;
    let client_ca = generate_ca("raw TLS wrong client CA")?;
    let server = generate_server(&server_ca, &["localhost"], false)?;
    let client = generate_client(&client_ca)?;
    let material = write_material(&server_ca, &client)?;
    let config = server_config(
        &server,
        &server_ca,
        &server.key_der,
        Arc::new(Mutex::new(Vec::new())),
    )?;
    let fixture = start_tls_server(config, true);

    let client = connect(
        "localhost",
        &fixture,
        &material.material,
        TlsServerTrust::Verify,
    );
    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&client.raw_engine()?))
        .await?
        .expect_err("the server must reject a client certificate from another CA");
    assert_eq!(error.kind(), ErrorKind::Transport);
    let rendered = error.to_string();
    assert!(
        rendered.contains("TLS handshake") || rendered.contains("connection error"),
        "the failure was not a TLS/client-auth rejection: {rendered}"
    );
    assert!(fixture.handshake_failures() >= 1);
    Ok(())
}

/// Every request opens its own TCP connection and TLS handshake.
#[tokio::test]
async fn raw_https_opens_a_fresh_tls_stream_for_every_request() -> Result<(), Box<dyn StdError>> {
    let fixture = direct_fixture(&["localhost"], false, true)?;
    let client = connect(
        "localhost",
        &fixture.fixture,
        &fixture.material.material,
        TlsServerTrust::Verify,
    );

    let engine = client.raw_engine()?;
    assert_eq!(engine.version(), neotales_docker::API_VERSION);
    for _ in 0..2 {
        let document = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine)).await??;
        assert_eq!(document, serde_json::json!({}));
    }

    assert_eq!(fixture.fixture.connections(), 2, "a duplex was reused");
    let requests = fixture.fixture.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| { request.starts_with("GET /v1.55/info HTTP/1.1\r\n") })
    );
    Ok(())
}

/// A facade operation that prefers the owned transport uses it over HTTPS.
#[tokio::test]
async fn https_facade_routes_version_through_the_owned_transport() -> Result<(), Box<dyn StdError>>
{
    let fixture = direct_fixture(&["localhost"], false, true)?;
    let client = connect(
        "localhost",
        &fixture.fixture,
        &fixture.material.material,
        TlsServerTrust::Verify,
    );

    let value = tokio::time::timeout(Duration::from_secs(5), client.version_value()).await??;
    assert_eq!(value, serde_json::json!({}));
    let requests = fixture.fixture.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("GET /v1.55/version HTTP/1.1\r\n"),
        "{}",
        requests[0]
    );
    Ok(())
}

/// An IP endpoint is verified against an IP SAN, and carries no DNS SNI.
#[tokio::test]
async fn raw_https_accepts_an_ip_target_with_an_ip_san() -> Result<(), Box<dyn StdError>> {
    let fixture = direct_fixture(&["127.0.0.1"], false, true)?;
    let client = DockerClient::connect_https_with_trust(
        &format!("https://127.0.0.1:{}", fixture.fixture.address.port()),
        &fixture.material.material,
        ProxyPolicy::Direct,
        TlsServerTrust::Verify,
    )?;
    let document =
        tokio::time::timeout(Duration::from_secs(5), raw::info(&client.raw_engine()?)).await??;
    assert_eq!(document, serde_json::json!({}));

    let requests = fixture.fixture.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].to_ascii_lowercase().contains(&format!(
            "host: 127.0.0.1:{}\r\n",
            fixture.fixture.address.port()
        )),
        "{}",
        requests[0]
    );
    Ok(())
}

/// An IPv6 target reaches the daemon directly and through a `CONNECT` proxy,
/// with the authority bracketed once and the dialed address unbracketed.
#[tokio::test]
async fn raw_https_reaches_an_ipv6_target_directly_and_through_connect()
-> Result<(), Box<dyn StdError>> {
    match std::net::TcpListener::bind("[::1]:0") {
        Ok(listener) => drop(listener),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
            ) =>
        {
            eprintln!(
                "SKIP raw_https_reaches_an_ipv6_target_directly_and_through_connect: \
                 IPv6 loopback is unavailable ({error})"
            );
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    let fixture = direct_fixture_on("[::1]:0", &["::1"], false, true)?;
    let port = fixture.fixture.address.port();
    let address = format!("https://[::1]:{port}");

    let direct = DockerClient::connect_https_with_trust(
        &address,
        &fixture.material.material,
        ProxyPolicy::Direct,
        TlsServerTrust::Verify,
    )?;
    let document =
        tokio::time::timeout(Duration::from_secs(5), raw::info(&direct.raw_engine()?)).await??;
    assert_eq!(document, serde_json::json!({}));

    let (proxy_address, connect_request, proxy_task) =
        start_connect_proxy(fixture.fixture.address).await?;
    let proxy = ForwardProxy::new(format!("http://{proxy_address}"))?;
    let proxied = DockerClient::connect_https_with_trust(
        &address,
        &fixture.material.material,
        ProxyPolicy::Http(proxy),
        TlsServerTrust::Verify,
    )?;
    let document =
        tokio::time::timeout(Duration::from_secs(5), raw::info(&proxied.raw_engine()?)).await??;
    assert_eq!(document, serde_json::json!({}));

    let connect_request = connect_request
        .await
        .map_err(|_| "the proxy fixture did not report a CONNECT request")?;
    proxy_task.await??;
    assert!(
        connect_request.starts_with(&format!("CONNECT [::1]:{port} HTTP/1.1\r\n")),
        "{connect_request}"
    );
    assert_eq!(fixture.fixture.requests().len(), 2);
    Ok(())
}

/// A certificate for another host is refused by default and accepted only by the
/// explicit opt-out.
#[tokio::test]
async fn raw_https_rejects_hostname_mismatch_unless_explicitly_trusted()
-> Result<(), Box<dyn StdError>> {
    let fixture = direct_fixture(&["docker.invalid"], false, true)?;

    let rejected = connect(
        "localhost",
        &fixture.fixture,
        &fixture.material.material,
        TlsServerTrust::Verify,
    );
    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&rejected.raw_engine()?))
        .await?
        .expect_err("the default must reject a certificate for another host");
    assert_eq!(error.kind(), ErrorKind::Transport);

    let accepted = connect(
        "localhost",
        &fixture.fixture,
        &fixture.material.material,
        TlsServerTrust::AllowExpiredOrUntrusted,
    );
    let document =
        tokio::time::timeout(Duration::from_secs(5), raw::info(&accepted.raw_engine()?)).await??;
    assert_eq!(document, serde_json::json!({}));
    assert!(fixture.fixture.handshake_failures() >= 1);
    Ok(())
}

/// A server signed by a CA the material does not pin is refused by default and
/// accepted only by the explicit opt-out.
#[tokio::test]
async fn raw_https_rejects_untrusted_ca_unless_explicitly_trusted() -> Result<(), Box<dyn StdError>>
{
    let trusted_ca = generate_ca("raw TLS trusted CA")?;
    let server_ca = generate_ca("raw TLS other CA")?;
    let server = generate_server(&server_ca, &["localhost"], false)?;
    let client = generate_client(&server_ca)?;
    let material = write_material(&trusted_ca, &client)?;
    let config = server_config(
        &server,
        &server_ca,
        &server.key_der,
        Arc::new(Mutex::new(Vec::new())),
    )?;
    let fixture = start_tls_server(config, true);

    let rejected = connect(
        "localhost",
        &fixture,
        &material.material,
        TlsServerTrust::Verify,
    );
    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&rejected.raw_engine()?))
        .await?
        .expect_err("the default must reject an untrusted server");
    assert_eq!(error.kind(), ErrorKind::Transport);

    let accepted = connect(
        "localhost",
        &fixture,
        &material.material,
        TlsServerTrust::AllowExpiredOrUntrusted,
    );
    let document =
        tokio::time::timeout(Duration::from_secs(5), raw::info(&accepted.raw_engine()?)).await??;
    assert_eq!(document, serde_json::json!({}));
    Ok(())
}

/// An expired certificate is refused by default and accepted only by the
/// explicit opt-out.
#[tokio::test]
async fn raw_https_rejects_expired_certificate_unless_explicitly_trusted()
-> Result<(), Box<dyn StdError>> {
    let fixture = direct_fixture(&["localhost"], true, true)?;

    let rejected = connect(
        "localhost",
        &fixture.fixture,
        &fixture.material.material,
        TlsServerTrust::Verify,
    );
    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&rejected.raw_engine()?))
        .await?
        .expect_err("the default must reject an expired certificate");
    assert_eq!(error.kind(), ErrorKind::Transport);

    let accepted = connect(
        "localhost",
        &fixture.fixture,
        &fixture.material.material,
        TlsServerTrust::AllowExpiredOrUntrusted,
    );
    let document =
        tokio::time::timeout(Duration::from_secs(5), raw::info(&accepted.raw_engine()?)).await??;
    assert_eq!(document, serde_json::json!({}));
    Ok(())
}

/// The explicit opt-out bypasses trust, time, and hostname — not the handshake
/// signature. A peer that signs with a key other than its certificate's is
/// still refused.
#[tokio::test]
async fn raw_https_explicit_trust_still_verifies_handshake_signature()
-> Result<(), Box<dyn StdError>> {
    let ca = generate_ca("raw TLS signature CA")?;
    let server = generate_server(&ca, &["localhost"], false)?;
    let client = generate_client(&ca)?;
    let material = write_material(&ca, &client)?;
    let wrong_key = KeyPair::generate()?.serialize_der();
    let config = server_config(&server, &ca, &wrong_key, Arc::new(Mutex::new(Vec::new())))?;
    let fixture = start_tls_server(config, true);

    let accepted = connect(
        "localhost",
        &fixture,
        &material.material,
        TlsServerTrust::AllowExpiredOrUntrusted,
    );
    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&accepted.raw_engine()?))
        .await?
        .expect_err("the explicit opt-out must still verify the handshake signature");
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert!(
        error.to_string().contains("TLS handshake"),
        "the failure was not a TLS handshake rejection: {error}"
    );
    Ok(())
}

/// The explicit HTTP proxy leg is a real `CONNECT`, and proxy credentials do not
/// travel to the daemon.
#[tokio::test]
async fn raw_https_connects_through_explicit_http_proxy() -> Result<(), Box<dyn StdError>> {
    let fixture = direct_fixture(&["localhost"], false, true)?;
    let target_port = fixture.fixture.address.port();
    let (proxy_address, connect_request, proxy_task) =
        start_connect_proxy(fixture.fixture.address).await?;

    let proxy = ForwardProxy::with_basic_auth(
        format!("http://{proxy_address}"),
        "proxy-user",
        "proxy-password",
    )?;
    let client = DockerClient::connect_https_with_trust(
        &format!("https://localhost:{target_port}"),
        &fixture.material.material,
        ProxyPolicy::Http(proxy),
        TlsServerTrust::Verify,
    )?;
    let document =
        tokio::time::timeout(Duration::from_secs(5), raw::info(&client.raw_engine()?)).await??;
    assert_eq!(document, serde_json::json!({}));

    let connect_request = connect_request
        .await
        .map_err(|_| "the proxy fixture did not report a CONNECT request")?;
    proxy_task.await??;
    assert!(
        connect_request.starts_with(&format!("CONNECT localhost:{target_port} HTTP/1.1\r\n")),
        "{connect_request}"
    );
    assert!(
        connect_request
            .contains("Proxy-Authorization: Basic cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA==\r\n"),
        "{connect_request}"
    );
    let requests = fixture.fixture.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        !requests[0]
            .to_ascii_lowercase()
            .contains("proxy-authorization"),
        "proxy credentials reached the daemon: {}",
        requests[0]
    );
    for secret in [
        "proxy-user",
        "proxy-password",
        "cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA==",
    ] {
        assert!(
            !requests[0].contains(secret),
            "credential bytes reached the daemon: {secret}"
        );
    }
    Ok(())
}

/// A CONNECT response head split across several reads is assembled, then the
/// TLS handshake proceeds through the tunnel.
#[tokio::test]
async fn raw_https_assembles_a_fragmented_connect_response() -> Result<(), Box<dyn StdError>> {
    let fixture = direct_fixture(&["localhost"], false, true)?;
    let target_port = fixture.fixture.address.port();
    let (proxy_address, connect_request, proxy_task) =
        start_fragmented_connect_proxy(fixture.fixture.address).await?;
    let proxy = ForwardProxy::new(format!("http://{proxy_address}"))?;
    let client = DockerClient::connect_https_with_trust(
        &format!("https://localhost:{target_port}"),
        &fixture.material.material,
        ProxyPolicy::Http(proxy),
        TlsServerTrust::Verify,
    )?;
    let document =
        tokio::time::timeout(Duration::from_secs(5), raw::info(&client.raw_engine()?)).await??;
    assert_eq!(document, serde_json::json!({}));

    let connect_request = connect_request
        .await
        .map_err(|_| "the proxy fixture did not report a CONNECT request")?;
    proxy_task.await??;
    assert!(
        connect_request.starts_with(&format!("CONNECT localhost:{target_port} HTTP/1.1\r\n")),
        "{connect_request}"
    );
    Ok(())
}

/// A request that is cancelled by dropping its future closes the TLS connection.
#[tokio::test]
async fn raw_https_request_cancellation_closes_the_tls_connection() -> Result<(), Box<dyn StdError>>
{
    let fixture = direct_fixture(&["localhost"], false, false)?;
    let client = connect(
        "localhost",
        &fixture.fixture,
        &fixture.material.material,
        TlsServerTrust::Verify,
    );
    let engine = client.raw_engine()?;

    // Poll until the fixture has the request head, then drop the future. If
    // the future is dropped before the head reaches the peer, the fixture is
    // still in its own read and never reaches the close observation, which is
    // a fixture race rather than a client failure.
    let mut request = Box::pin(raw::info(&engine));
    let request_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout(Duration::from_millis(20), request.as_mut()).await {
            Err(_) => {}
            Ok(result) => panic!("the fixture answered instead of holding: {result:?}"),
        }
        if !fixture.fixture.requests().is_empty() {
            break;
        }
        assert!(
            Instant::now() < request_deadline,
            "the fixture never received the request head"
        );
    }
    drop(request);

    // Closure is the property; the bound is only a harness guard. Windows
    // runners can take longer than a few seconds to report the peer close
    // under load, which is not a failure of the client.
    let deadline = Instant::now() + Duration::from_secs(10);
    let outcome = loop {
        if let Some(outcome) = fixture.fixture.close_outcome() {
            break outcome;
        }
        assert!(
            Instant::now() < deadline,
            "the cancelled TLS connection did not close within the bound"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(
        outcome,
        Ok(()),
        "the cancelled TLS peer did not close cleanly: {outcome:?}"
    );
    Ok(())
}

/// Material that cannot be loaded is refused by the constructor, for the direct
/// path and the proxy path alike. The CA bundle and the client identity are
/// both checked here rather than on the first request, and the error keeps the
/// failed role and a content-free source.
#[test]
#[allow(clippy::too_many_lines)] // One explicit case per role and failure source.
fn raw_https_constructor_rejects_invalid_material_synchronously() -> Result<(), Box<dyn StdError>> {
    let ca = generate_ca("raw TLS invalid material CA")?;
    let client = generate_client(&ca)?;

    let (directory, material) = material_files(&ca.cert_pem, &client.cert_pem, &client.key_pem)?;
    std::fs::remove_file(&material.ca_path)?;
    let path = directory.path().to_string_lossy().into_owned();
    assert_material_rejected(
        &material,
        TlsMaterialRole::Ca,
        &[TlsMaterialSource::Open(std::io::ErrorKind::NotFound)],
        &[path.as_str()],
    )?;

    let (directory, material) = material_files(&ca.cert_pem, &client.cert_pem, &client.key_pem)?;
    std::fs::remove_file(&material.cert_path)?;
    let path = directory.path().to_string_lossy().into_owned();
    assert_material_rejected(
        &material,
        TlsMaterialRole::Cert,
        &[TlsMaterialSource::Open(std::io::ErrorKind::NotFound)],
        &[path.as_str()],
    )?;

    let (directory, material) = material_files(&ca.cert_pem, &client.cert_pem, &client.key_pem)?;
    std::fs::remove_file(&material.key_path)?;
    let path = directory.path().to_string_lossy().into_owned();
    assert_material_rejected(
        &material,
        TlsMaterialRole::Key,
        &[TlsMaterialSource::Open(std::io::ErrorKind::NotFound)],
        &[path.as_str()],
    )?;

    let (directory, material) = material_files(
        "-----BEGIN CERTIFICATE-----\nCANARY!\n-----END CERTIFICATE-----\n",
        &client.cert_pem,
        &client.key_pem,
    )?;
    let path = directory.path().to_string_lossy().into_owned();
    assert_material_rejected(
        &material,
        TlsMaterialRole::Ca,
        &[TlsMaterialSource::Parse, TlsMaterialSource::Empty],
        &[path.as_str(), "CANARY!"],
    )?;

    let (directory, material) = material_files(
        &ca.cert_pem,
        "-----BEGIN CERTIFICATE-----\nCANARY!\n-----END CERTIFICATE-----\n",
        &client.key_pem,
    )?;
    let path = directory.path().to_string_lossy().into_owned();
    assert_material_rejected(
        &material,
        TlsMaterialRole::Cert,
        &[TlsMaterialSource::Parse, TlsMaterialSource::Empty],
        &[path.as_str(), "CANARY!"],
    )?;

    let (directory, material) = material_files(
        &ca.cert_pem,
        &client.cert_pem,
        "-----BEGIN PRIVATE KEY-----\nCANARY!\n-----END PRIVATE KEY-----\n",
    )?;
    let path = directory.path().to_string_lossy().into_owned();
    assert_material_rejected(
        &material,
        TlsMaterialRole::Key,
        &[TlsMaterialSource::Parse, TlsMaterialSource::Empty],
        &[path.as_str(), "CANARY!"],
    )?;

    // Two real keys are a multiple-key failure.
    let (directory, material) = material_files(
        &ca.cert_pem,
        &client.cert_pem,
        &format!("{}{}", client.key_pem, client.key_pem),
    )?;
    let path = directory.path().to_string_lossy().into_owned();
    assert_material_rejected(
        &material,
        TlsMaterialRole::Key,
        &[TlsMaterialSource::MultipleKeys],
        &[path.as_str()],
    )?;

    // One real key followed by a malformed section is a read/parse failure, not
    // a multiple-key failure.
    let (directory, material) = material_files(
        &ca.cert_pem,
        &client.cert_pem,
        &format!("{}-----BEGIN PRIVATE KEY-----\nCANARY!\n", client.key_pem),
    )?;
    let path = directory.path().to_string_lossy().into_owned();
    assert_material_rejected(
        &material,
        TlsMaterialRole::Key,
        &[
            TlsMaterialSource::Parse,
            TlsMaterialSource::Read(std::io::ErrorKind::Other),
        ],
        &[path.as_str(), "CANARY!"],
    )?;

    // A PEM certificate block with valid base64 but invalid DER is an invalid
    // entry, not an empty bundle.
    let (directory, material) = material_files(
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        &client.cert_pem,
        &client.key_pem,
    )?;
    let path = directory.path().to_string_lossy().into_owned();
    assert_material_rejected(
        &material,
        TlsMaterialRole::Ca,
        &[TlsMaterialSource::Invalid],
        &[path.as_str()],
    )?;

    // A path that is a directory is an I/O failure, not a parse or empty
    // material. The exact kind differs by platform (open versus read).
    let io_sources = [
        TlsMaterialSource::Open(std::io::ErrorKind::IsADirectory),
        TlsMaterialSource::Read(std::io::ErrorKind::IsADirectory),
        TlsMaterialSource::Open(std::io::ErrorKind::PermissionDenied),
        TlsMaterialSource::Read(std::io::ErrorKind::PermissionDenied),
        TlsMaterialSource::Open(std::io::ErrorKind::Other),
        TlsMaterialSource::Read(std::io::ErrorKind::Other),
    ];
    for role in [
        TlsMaterialRole::Ca,
        TlsMaterialRole::Cert,
        TlsMaterialRole::Key,
    ] {
        let (directory, material) =
            material_files(&ca.cert_pem, &client.cert_pem, &client.key_pem)?;
        let path = match role {
            TlsMaterialRole::Ca => &material.ca_path,
            TlsMaterialRole::Cert => &material.cert_path,
            TlsMaterialRole::Key => &material.key_path,
            _ => unreachable!("only material files are tested"),
        };
        std::fs::remove_file(path)?;
        std::fs::create_dir(path)?;
        let forbidden = directory.path().to_string_lossy().into_owned();
        assert_material_rejected(&material, role, &io_sources, &[forbidden.as_str()])?;
    }
    Ok(())
}

fn tls_config_error(error: &neotales_docker::Error) -> TlsConfigError {
    let source = std::error::Error::source(error).expect("the TlsConfigError source");
    *source
        .downcast_ref::<TlsConfigError>()
        .expect("a TlsConfigError source")
}

fn assert_material_rejected(
    material: &TlsMaterial,
    role: TlsMaterialRole,
    accepted: &[TlsMaterialSource],
    forbidden: &[&str],
) -> Result<(), Box<dyn StdError>> {
    let direct = DockerClient::connect_endpoint_with_version(
        &Endpoint::Https {
            address: "https://localhost:2376".to_owned(),
            material: Some(material.clone()),
        },
        EXPLICIT_VERSION,
    )
    .expect_err("invalid material must fail the direct constructor");
    assert_eq!(direct.kind(), ErrorKind::Proxy);
    let error = tls_config_error(&direct);
    let source = std::error::Error::source(&direct).expect("the TlsConfigError source");
    assert!(source.downcast_ref::<TlsConfigError>().is_some());
    assert!(
        source.downcast_ref::<ProxyError>().is_none(),
        "the TLS material source is no longer ProxyError::TlsConfiguration"
    );
    assert_eq!(error.role, role);
    assert!(
        accepted.contains(&error.source),
        "unexpected source {:?}",
        error.source
    );
    let rendered = direct.to_string();
    for forbidden in forbidden {
        assert!(
            !rendered.contains(forbidden),
            "error leaked {forbidden:?}: {rendered}"
        );
    }

    let proxy = ForwardProxy::new("http://proxy.example:8080")?;
    let proxied = DockerClient::connect_endpoint_with_version_and_policy(
        &Endpoint::Https {
            address: "https://localhost:2376".to_owned(),
            material: Some(material.clone()),
        },
        ProxyPolicy::Http(proxy),
        EXPLICIT_VERSION,
    )
    .expect_err("invalid material must fail the proxy constructor");
    assert_eq!(proxied.kind(), ErrorKind::Proxy);
    let error = tls_config_error(&proxied);
    let source = std::error::Error::source(&proxied).expect("the TlsConfigError source");
    assert!(source.downcast_ref::<TlsConfigError>().is_some());
    assert!(
        source.downcast_ref::<ProxyError>().is_none(),
        "the TLS material source is no longer ProxyError::TlsConfiguration"
    );
    assert_eq!(error.role, role);
    assert!(accepted.contains(&error.source));
    let rendered = proxied.to_string();
    for forbidden in forbidden {
        assert!(
            !rendered.contains(forbidden),
            "error leaked {forbidden:?}: {rendered}"
        );
    }
    Ok(())
}

/// A loopback HTTP proxy that answers one `CONNECT` and forwards the tunnel.
async fn start_connect_proxy(
    target: SocketAddr,
) -> Result<
    (
        SocketAddr,
        tokio::sync::oneshot::Receiver<String>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ),
    Box<dyn StdError>,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await?;
        let request = read_head(&mut client).await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the proxy fixture closed before reading the CONNECT request",
            )
        })?;
        let _ignored = sender.send(request);
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let mut upstream = TcpStream::connect(target).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    });
    Ok((address, receiver, task))
}

/// A loopback HTTP proxy that writes the CONNECT response head in fragments.
async fn start_fragmented_connect_proxy(
    target: SocketAddr,
) -> Result<
    (
        SocketAddr,
        tokio::sync::oneshot::Receiver<String>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ),
    Box<dyn StdError>,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await?;
        let request = read_head(&mut client).await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the proxy fixture closed before reading the CONNECT request",
            )
        })?;
        let _ignored = sender.send(request);
        for fragment in [
            b"HTTP/1.1 200 ".as_slice(),
            b"Connection Established\r\n".as_slice(),
            b"\r\n".as_slice(),
        ] {
            client.write_all(fragment).await?;
            client.flush().await?;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut upstream = TcpStream::connect(target).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    });
    Ok((address, receiver, task))
}
