//! `BuildKit`'s deprecated Engine `/grpc` endpoint upgrades to HTTP/2; the
//! framed RPC is sent on that connection, not in the HTTP/1 upgrade request.
//! Dropping a live stream aborts its connection driver; no task is detached.

#![allow(dead_code)] // Internal substrate, not yet a public build adapter.

use std::{collections::BTreeMap, fmt, future::Future, time::Duration};

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, Method, Request, StatusCode, header};
use neotales_docker_buildkit::{
    grpc::{self, GrpcError, MAX_MESSAGE_BYTES},
    proto::{Message, SolveRequest, SolveResponse, StatusRequest, StatusResponse},
};
use tokio::task::JoinHandle;

use super::{RawEngine, RawRequest, session};

#[derive(Debug)]
pub(crate) enum RpcError {
    Transport,
    Timeout,
    Protocol,
    Oversized,
    Status(u32),
    Unsupported(neotales_docker_buildkit::UnsupportedFeature),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BuildKit RPC error: {self:?}")
    }
}

struct Driver {
    task: Option<JoinHandle<()>>,
}

impl Drop for Driver {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn wait<T>(budget: Option<Duration>, future: impl Future<Output = T>) -> Result<T, RpcError> {
    match budget {
        Some(budget) => tokio::time::timeout(budget, future)
            .await
            .map_err(|_| RpcError::Timeout),
        None => Ok(future.await),
    }
}

pub(crate) struct BuildSession {
    pub(crate) id: String,
    _session: session::SessionHandle,
}

impl BuildSession {
    pub(crate) async fn open(
        engine: &RawEngine,
        secrets: Option<std::sync::Arc<session::Secrets>>,
        context: Option<std::sync::Arc<super::buildkit_context::Snapshot>>,
        ssh: Option<std::sync::Arc<session::SshRegistry>>,
    ) -> Result<Self, RpcError> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| RpcError::Transport)?;
        let mut id = String::with_capacity(32);
        let hex = b"0123456789abcdef";
        for b in random {
            id.push(char::from(hex[usize::from(b >> 4)]));
            id.push(char::from(hex[usize::from(b & 15)]));
        }
        let session = wait(
            engine.grpc_deadline(),
            session::handshake(engine, &id, secrets, context, ssh),
        )
        .await?
        .map_err(|_| RpcError::Transport)?;
        Ok(Self {
            id,
            _session: session,
        })
    }
}

async fn connect(engine: &RawEngine) -> Result<(h2::client::SendRequest<Bytes>, Driver), RpcError> {
    let request = RawRequest::new(Method::POST, "/grpc")
        .with_header(header::CONNECTION, "Upgrade")
        .with_header(header::UPGRADE, "h2c");
    let response = engine
        .send_upgrading_grpc(request)
        .await
        .map_err(|_| RpcError::Transport)?;
    let valid = response
        .headers
        .get_all(header::UPGRADE)
        .iter()
        .any(|value| {
            value
                .to_str()
                .is_ok_and(|s| s.split(',').any(|s| s.trim().eq_ignore_ascii_case("h2c")))
        });
    if response.status != StatusCode::SWITCHING_PROTOCOLS || !valid {
        return Err(RpcError::Protocol);
    }
    let (read, write) = response
        .into_upgraded()
        .await
        .map_err(|_| RpcError::Transport)?;
    let (client, connection) = wait(
        engine.grpc_deadline(),
        h2::client::handshake(read.unsplit(write)),
    )
    .await?
    .map_err(|_| RpcError::Transport)?;
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let driver = Driver { task: Some(task) };
    Ok((client, driver))
}

fn status(headers: &HeaderMap) -> Result<(), RpcError> {
    let value = headers.get("grpc-status").and_then(|h| h.to_str().ok());
    let message = headers
        .get("grpc-message")
        .map(|h| h.to_str())
        .transpose()
        .map_err(|_| RpcError::Protocol)?;
    // Validate grpc-message but discard it from every error.
    match grpc::parse_status(value, message) {
        Ok(()) => Ok(()),
        Err(GrpcError::Status { code, .. }) => Err(RpcError::Status(code)),
        Err(_) => Err(RpcError::Protocol),
    }
}

pub(crate) struct RpcStream {
    incoming: h2::RecvStream,
    outgoing: h2::SendStream<Bytes>,
    _driver: Driver,
    buffer: BytesMut,
    deadline: Option<Duration>,
    done: bool,
    headers_status: Option<HeaderMap>,
}

impl Drop for RpcStream {
    fn drop(&mut self) {
        if !self.done {
            self.outgoing.send_reset(h2::Reason::CANCEL);
            // Closing the connection is the cancellation fallback if the
            // queued reset has not reached the peer yet.
        }
    }
}

impl RpcStream {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, RpcError> {
        if self.done {
            return Ok(None);
        }
        loop {
            match grpc::decode_message(&self.buffer, MAX_MESSAGE_BYTES) {
                Ok((_, message, used)) => {
                    let value = message.to_vec();
                    self.buffer.advance(used);
                    return Ok(Some(value));
                }
                Err(GrpcError::Truncated) => {}
                Err(GrpcError::Oversized) => return Err(RpcError::Oversized),
                Err(_) => return Err(RpcError::Protocol),
            }
            match wait(self.deadline, self.incoming.data()).await? {
                Some(Ok(data)) => {
                    // One h2 DATA frame may also contain the next message.
                    // The client's default h2 maximum frame size is 16 KiB.
                    if self.buffer.len().saturating_add(data.len())
                        > MAX_MESSAGE_BYTES + 5 + 16 * 1024
                    {
                        return Err(RpcError::Oversized);
                    }
                    self.incoming
                        .flow_control()
                        .release_capacity(data.len())
                        .map_err(|_| RpcError::Transport)?;
                    self.buffer.extend_from_slice(&data);
                }
                Some(Err(_)) => return Err(RpcError::Transport),
                None => {
                    if !self.buffer.is_empty() {
                        return Err(RpcError::Protocol);
                    }
                    let trailers = wait(self.deadline, self.incoming.trailers())
                        .await?
                        .map_err(|_| RpcError::Transport)?;
                    let headers = trailers
                        .as_ref()
                        .or(self.headers_status.as_ref())
                        .ok_or(RpcError::Protocol)?;
                    status(headers)?;
                    self.done = true;
                    return Ok(None);
                }
            }
        }
    }
}

async fn request(
    engine: &RawEngine,
    method: &'static str,
    message: &[u8],
) -> Result<RpcStream, RpcError> {
    let (client, driver) = connect(engine).await?;
    let mut client = wait(engine.grpc_deadline(), client.ready())
        .await?
        .map_err(|_| RpcError::Transport)?;
    let req = Request::post(method)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header(header::TE, "trailers")
        .body(())
        .map_err(|_| RpcError::Protocol)?;
    let (response, mut outgoing) = client
        .send_request(req, false)
        .map_err(|_| RpcError::Transport)?;
    let frame =
        grpc::encode_message(0, message, MAX_MESSAGE_BYTES).map_err(|_| RpcError::Oversized)?;
    outgoing
        .send_data(Bytes::from(frame), true)
        .map_err(|_| RpcError::Transport)?;
    let response = wait(engine.grpc_deadline(), response)
        .await?
        .map_err(|_| RpcError::Transport)?;
    if response.status() != StatusCode::OK {
        return Err(RpcError::Protocol);
    }
    let headers_status = (response.body().is_end_stream()
        && response.headers().contains_key("grpc-status"))
    .then(|| response.headers().clone());
    Ok(RpcStream {
        incoming: response.into_body(),
        outgoing,
        _driver: driver,
        buffer: BytesMut::new(),
        deadline: engine.grpc_deadline(),
        done: false,
        headers_status,
    })
}

pub(super) async fn solve(
    engine: &RawEngine,
    session: &BuildSession,
    attrs: BTreeMap<String, String>,
) -> Result<SolveResponse, RpcError> {
    solve_with_exporter(
        engine,
        &session.id,
        attrs,
        Vec::new(),
        neotales_docker_buildkit::proto::CacheOptions::default(),
    )
    .await
}

pub(crate) async fn solve_with_exporter(
    engine: &RawEngine,
    session_id: &str,
    attrs: BTreeMap<String, String>,
    exporters: Vec<neotales_docker_buildkit::proto::Exporter>,
    cache: neotales_docker_buildkit::proto::CacheOptions,
) -> Result<SolveResponse, RpcError> {
    let message = SolveRequest {
        reference: session_id.to_owned(),
        frontend: "dockerfile.v0".into(),
        frontend_attrs: attrs,
        session: session_id.to_owned(),
        exporters,
        cache,
    };
    let mut stream = request(engine, "/moby.buildkit.v1.Control/Solve", &message.encode()).await?;
    let body = stream.next().await?.ok_or(RpcError::Protocol)?;
    let result = SolveResponse::decode(&body).map_err(|_| RpcError::Protocol)?;
    if stream.next().await?.is_some() {
        return Err(RpcError::Protocol);
    }
    Ok(result)
}

pub(crate) async fn status_stream(
    engine: &RawEngine,
    session: &BuildSession,
) -> Result<RpcStream, RpcError> {
    status_stream_for(engine, &session.id).await
}

pub(crate) async fn status_stream_for(
    engine: &RawEngine,
    session_id: &str,
) -> Result<RpcStream, RpcError> {
    let message = StatusRequest {
        reference: session_id.to_owned(),
    };
    request(
        engine,
        "/moby.buildkit.v1.Control/Status",
        &message.encode(),
    )
    .await
}

impl RpcStream {
    pub(crate) async fn next_status(&mut self) -> Result<Option<StatusResponse>, RpcError> {
        self.next()
            .await?
            .map(|bytes| StatusResponse::decode(&bytes).map_err(|_| RpcError::Protocol))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::RawTarget;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    #[ignore = "explicit opt-in: queries the local Engine BuildKit endpoint"]
    async fn live_buildkit_info() {
        assert_eq!(
            std::env::var("NEOTALES_DOCKER_BUILDKIT").as_deref(),
            Ok("1")
        );
        let engine = RawEngine::new(
            RawTarget::Unix("/var/run/docker.sock".into()),
            crate::API_VERSION,
        )
        .with_overall_request_deadline(Some(Duration::from_secs(10)));
        let mut response = request(&engine, "/moby.buildkit.v1.Control/Info", &[])
            .await
            .unwrap();
        let payload = response.next().await.unwrap().unwrap();
        let info = neotales_docker_buildkit::proto::InfoResponse::decode(&payload).unwrap();
        assert!(response.next().await.unwrap().is_none());
        let version = info.version.expect("BuildKit Info must report version");
        println!("BuildKit Control.Info version: {}", version.version);
    }

    #[tokio::test]
    async fn configured_deadline_bounds_response_wait() {
        assert!(matches!(
            wait(Some(Duration::from_millis(5)), std::future::pending::<()>()).await,
            Err(RpcError::Timeout)
        ));
    }

    async fn fixture(
        frames: Vec<Vec<u8>>,
        trailer: Option<&'static str>,
    ) -> (RawEngine, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                io.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
                assert!(head.len() < 8192);
            }
            assert!(head.starts_with(b"POST /grpc HTTP/1.1\r\n"));
            io.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
            )
            .await
            .unwrap();
            let mut conn = h2::server::handshake(io).await.unwrap();
            let (request, mut respond) = conn.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), Method::POST);
            assert_eq!(request.headers()[header::CONTENT_TYPE], "application/grpc");
            assert_eq!(request.headers()[header::TE], "trailers");
            let mut handler = tokio::spawn(async move {
                let mut body = request.into_body();
                let mut incoming = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    incoming.extend_from_slice(&chunk);
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                }
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                for frame in frames {
                    send.send_data(Bytes::from(frame), false).unwrap();
                }
                if let Some(code) = trailer {
                    let mut trailers = HeaderMap::new();
                    trailers.insert("grpc-status", code.parse().unwrap());
                    trailers.insert("grpc-message", "peer-secret-canary".parse().unwrap());
                    send.send_trailers(trailers).unwrap();
                } else {
                    send.send_data(Bytes::new(), true).unwrap();
                }
                incoming
            });
            loop {
                tokio::select! {
                    result = &mut handler => {
                        let incoming = result.unwrap();
                        // Continue polling the connection until the client has
                        // received the queued DATA and trailers.
                        while conn.accept().await.is_some() {}
                        return incoming;
                    }
                    _ = conn.accept() => {}
                }
            }
        });
        (
            RawEngine::new(
                RawTarget::Tcp {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                crate::API_VERSION,
            ),
            task,
        )
    }

    fn frame(data: &[u8]) -> Vec<u8> {
        grpc::encode_message(0, data, MAX_MESSAGE_BYTES).unwrap()
    }

    async fn mock_session() -> (
        BuildSession,
        h2::client::SendRequest<Bytes>,
        JoinHandle<Result<(), h2::Error>>,
    ) {
        let (client, server) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move { h2::server::handshake(server).await.unwrap() });
        let (client, connection) = h2::client::handshake(client).await.unwrap();
        let peer = tokio::spawn(connection);
        let session = BuildSession {
            id: "id".into(),
            _session: session::drive(server.await.unwrap(), session::WRITE_CAPACITY_BUDGET),
        };
        (session, client, peer)
    }

    #[tokio::test]
    async fn unary_and_status_trailers() {
        let expected = SolveResponse {
            exporter_response: [("image".into(), "digest".into())].into(),
        };
        let (engine, server) = fixture(vec![frame(&expected.encode())], Some("0")).await;
        let (session, _client, peer) = mock_session().await;
        assert_eq!(
            solve(
                &engine,
                &session,
                [("a".into(), "1".into()), ("b".into(), "2".into())].into()
            )
            .await
            .unwrap(),
            expected
        );
        drop(session);
        peer.abort();
        let wire = server.await.unwrap();
        assert_eq!(
            grpc::decode_message(&wire, MAX_MESSAGE_BYTES).unwrap().1,
            [
                0x0a, 2, b'i', b'd', 0x2a, 2, b'i', b'd', 0x32, 13, b'd', b'o', b'c', b'k', b'e',
                b'r', b'f', b'i', b'l', b'e', b'.', b'v', b'0', 0x3a, 6, 0x0a, 1, b'a', 0x12, 1,
                b'1', 0x3a, 6, 0x0a, 1, b'b', 0x12, 1, b'2'
            ]
        );

        for (trailer, oversize) in [(Some("7"), false), (None, false), (Some("0"), true)] {
            let bytes = if oversize {
                vec![0, 0, 64, 0, 1]
            } else {
                Vec::new()
            };
            let (engine, server) = fixture(vec![bytes], trailer).await;
            let mut stream = request(&engine, "/moby.buildkit.v1.Control/Solve", b"")
                .await
                .unwrap();
            let error = stream.next().await.unwrap_err();
            assert!(matches!(
                (trailer, oversize, &error),
                (Some("7"), false, RpcError::Status(7))
                    | (None, false, RpcError::Protocol)
                    | (Some("0"), true, RpcError::Oversized)
            ));
            assert!(!format!("{error:?}").contains("peer-secret-canary"));
            drop(stream);
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn ordered_status_messages() {
        let first = StatusResponse {
            vertexes: vec![neotales_docker_buildkit::proto::Vertex {
                name: "one".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let second = StatusResponse {
            vertexes: vec![neotales_docker_buildkit::proto::Vertex {
                name: "two".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let (engine, server) = fixture(
            vec![frame(&first.encode()), frame(&second.encode())],
            Some("0"),
        )
        .await;
        let (session, _client, peer) = mock_session().await;
        let mut stream = status_stream(&engine, &session).await.unwrap();
        assert_eq!(stream.next_status().await.unwrap(), Some(first));
        assert_eq!(stream.next_status().await.unwrap(), Some(second));
        assert!(stream.next_status().await.unwrap().is_none());
        drop(stream);
        drop(session);
        peer.abort();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dropping_stream_closes_or_resets_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                io.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            io.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
            )
            .await
            .unwrap();
            let mut conn = h2::server::handshake(io).await.unwrap();
            let (_, mut respond) = conn.accept().await.unwrap().unwrap();
            let mut stream = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            loop {
                tokio::select! {
                    result = futures_util::future::poll_fn(|cx| stream.poll_reset(cx)) => return result,
                    accepted = conn.accept() => if accepted.is_none() {
                        return futures_util::future::poll_fn(|cx| stream.poll_reset(cx)).await;
                    }
                }
            }
        });
        let engine = RawEngine::new(
            RawTarget::Tcp {
                host: address.ip().to_string(),
                port: address.port(),
            },
            crate::API_VERSION,
        );
        let stream = request(&engine, "/moby.buildkit.v1.Control/Status", b"")
            .await
            .unwrap();
        drop(stream);
        let outcome = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        if let Ok(reason) = outcome {
            assert_eq!(reason, h2::Reason::CANCEL);
        }
    }
}
