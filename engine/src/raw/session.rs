//! Internal wire substrate; no `BuildKit` solve is exposed.

use bytes::{Buf, Bytes, BytesMut};
use futures_util::future::poll_fn;
use hyper::header::{CONNECTION, HeaderName, UPGRADE};
use hyper::{Method, StatusCode};
use neotales_docker_buildkit::{
    grpc::{GrpcError, MAX_MESSAGE_BYTES, decode_message},
    proto::{
        BytesMessage, CheckAgentRequest, CheckAgentResponse, FilePacket, GetSecretRequest, Message,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::{JoinHandle, JoinSet};
use zeroize::Zeroizing;

use super::{RawEngine, RawRequest, SwitchedConnection};
use crate::Error;

/// Maximum time without write capacity before a session stream is abandoned.
pub(crate) const WRITE_CAPACITY_BUDGET: Duration = Duration::from_secs(30);
const SECRET_PATH: &str = "/moby.buildkit.secrets.v1.Secrets/GetSecret";
const FILESYNC_PATH: &str = "/moby.filesync.v1.FileSync/DiffCopy";
const SSH_CHECK_PATH: &str = "/moby.sshforward.v1.SSH/CheckAgent";
const SSH_FORWARD_PATH: &str = "/moby.sshforward.v1.SSH/ForwardAgent";
const MAX_SECRETS: usize = 128;
const MAX_SECRET_ID_BYTES: usize = 256;
// Leave room for the protobuf tag and length within the gRPC message cap.
const MAX_SECRET_BYTES: usize = MAX_MESSAGE_BYTES - 16;
const MAX_SECRET_TOTAL: usize = MAX_MESSAGE_BYTES;

/// An explicit allow-list. Values are wiped when the last session drops.
pub(crate) struct Secrets(BTreeMap<String, Zeroizing<Vec<u8>>>);

/// Explicit SSH forwarding sources; no ambient agent is discovered.
#[allow(dead_code)]
pub(crate) enum SshForward {
    Socket(std::path::PathBuf),
    Key(std::sync::Mutex<neotales_ssh::agent_server::AgentServer>),
}

type SshForwards = BTreeMap<String, SshForward>;

pub(crate) struct SshRegistry {
    forwards: SshForwards,
    missing: std::sync::Mutex<BTreeSet<String>>,
}

impl SshRegistry {
    pub(crate) fn new(forwards: SshForwards) -> Self {
        Self {
            forwards,
            missing: std::sync::Mutex::new(BTreeSet::new()),
        }
    }

    pub(crate) fn missing(&self) -> Option<String> {
        self.missing.lock().ok()?.first().cloned()
    }
}

fn ssh_id(id: &str) -> &str {
    if id.is_empty() { "default" } else { id }
}

impl Secrets {
    #[allow(dead_code)] // The future build entry point supplies the allow-list.
    pub(crate) fn new(values: BTreeMap<String, Vec<u8>>) -> Result<Self, SecretError> {
        let values: BTreeMap<_, _> = values
            .into_iter()
            .map(|(id, value)| (id, Zeroizing::new(value)))
            .collect();
        let mut total = 0_usize;
        if values.len() > MAX_SECRETS {
            return Err(SecretError::TooLarge);
        }
        for (id, value) in &values {
            if id.is_empty() || id.len() > MAX_SECRET_ID_BYTES {
                return Err(SecretError::InvalidId);
            }
            if value.len() > MAX_SECRET_BYTES {
                return Err(SecretError::TooLarge);
            }
            total = total
                .checked_add(value.len())
                .ok_or(SecretError::TooLarge)?;
            if total > MAX_SECRET_TOTAL {
                return Err(SecretError::TooLarge);
            }
        }
        Ok(Self(values))
    }
}

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)] // The future build entry point reports these validation errors.
pub(crate) enum SecretError {
    InvalidId,
    TooLarge,
}

// Only methods we intend to provide may be dispatched. They remain explicitly
// unimplemented until their individual providers are installed.
const SESSION_PATHS: &[&str] = &[
    "/moby.filesync.v1.FileSync/DiffCopy",
    "/moby.filesync.v1.FileSend/DiffCopy",
    "/moby.buildkit.v1.Auth/Credentials",
    "/moby.buildkit.v1.Auth/FetchToken",
    "/moby.buildkit.v1.Auth/GetTokenAuthority",
    "/moby.buildkit.v1.Auth/VerifyTokenAuthority",
    "/moby.buildkit.secrets.v1.Secrets/GetSecret",
    "/moby.sshforward.v1.SSH/CheckAgent",
    "/moby.sshforward.v1.SSH/ForwardAgent",
];

#[derive(Debug, PartialEq, Eq)]
enum StreamError {
    Wire(GrpcError),
    Closed,
    Timeout,
    Unimplemented,
    InvalidArgument,
    NotFound,
    PermissionDenied,
    Unavailable,
}

/// Owns all stream tasks as well as the connection; dropping it closes both.
#[allow(dead_code)]
pub(crate) struct SessionHandle(JoinHandle<()>);

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[allow(dead_code)]
pub(super) fn drive<T>(
    connection: h2::server::Connection<T, Bytes>,
    budget: Duration,
) -> SessionHandle
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    drive_with_secrets(connection, budget, None)
}

fn drive_with_secrets<T>(
    connection: h2::server::Connection<T, Bytes>,
    budget: Duration,
    secrets: Option<Arc<Secrets>>,
) -> SessionHandle
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    drive_with_providers(connection, budget, secrets, None, None)
}

fn drive_with_providers<T>(
    mut connection: h2::server::Connection<T, Bytes>,
    budget: Duration,
    secrets: Option<Arc<Secrets>>,
    context: Option<Arc<super::buildkit_context::Snapshot>>,
    ssh: Option<Arc<SshRegistry>>,
) -> SessionHandle
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    SessionHandle(tokio::spawn(async move {
        let mut streams = JoinSet::new();
        loop {
            tokio::select! {
                accepted = connection.accept() => match accepted {
                    Some(Ok((request, response))) => {
                        let secrets = secrets.clone();
                        let context = context.clone();
                        let ssh = ssh.clone();
                        streams.spawn(async move {
                            if request.method() == Method::POST && request.uri().path() == SSH_FORWARD_PATH {
                                return serve_ssh_forward(request, response, budget, ssh.as_deref()).await;
                            }
                            if request.method() == Method::POST && request.uri().path() == FILESYNC_PATH
                                && let Some(context) = context.as_deref() {
                                return serve_filesync(request, response, budget, context).await;
                            }
                            serve(request, response, budget, secrets.as_deref(), ssh.as_deref()).await
                        });
                    }
                    Some(Err(_)) | None => break,
                },
                Some(_) = streams.join_next(), if !streams.is_empty() => {}
            }
        }
        // Dropping JoinSet aborts every stream before the connection is dropped.
    }))
}

async fn read_message(stream: &mut h2::RecvStream) -> Result<Vec<u8>, StreamError> {
    let mut buffer = BytesMut::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.map_err(|_| StreamError::Closed)?;
        // Check the header as soon as it is available, without allowing an
        // unbounded peer-controlled body to accumulate.
        if buffer.len().saturating_add(chunk.len()) > MAX_MESSAGE_BYTES + 5 {
            return Err(StreamError::Wire(GrpcError::Oversized));
        }
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|_| StreamError::Closed)?;
        buffer.extend_from_slice(&chunk);
        match decode_message(&buffer, MAX_MESSAGE_BYTES) {
            Ok((_, payload, consumed)) => {
                if consumed != buffer.len() {
                    return Err(StreamError::Wire(GrpcError::Truncated));
                }
                return Ok(payload.to_vec());
            }
            Err(GrpcError::Truncated) => {}
            Err(error) => return Err(StreamError::Wire(error)),
        }
    }
    Err(StreamError::Wire(GrpcError::Truncated))
}

/// Incremental reader for bidirectional RPCs. A DATA frame can contain
/// fragments of several gRPC messages; retain unread bytes for the next call.
#[allow(dead_code)] // Used once the DiffCopy state machine is installed.
#[derive(Default)]
struct MessageReader {
    buffer: BytesMut,
    pending: Bytes,
}

impl MessageReader {
    #[allow(dead_code)]
    async fn next(&mut self, stream: &mut h2::RecvStream) -> Result<Option<Vec<u8>>, StreamError> {
        loop {
            match decode_message(&self.buffer, MAX_MESSAGE_BYTES) {
                Ok((_, payload, used)) => {
                    let result = payload.to_vec();
                    self.buffer.advance(used);
                    return Ok(Some(result));
                }
                Err(GrpcError::Truncated) => {}
                Err(error) => return Err(StreamError::Wire(error)),
            }
            if self.pending.is_empty() {
                match stream.data().await {
                    Some(Ok(data)) => self.pending = data,
                    Some(Err(_)) => return Err(StreamError::Closed),
                    None if self.buffer.is_empty() => return Ok(None),
                    None => return Err(StreamError::Wire(GrpcError::Truncated)),
                }
                if self.pending.is_empty() {
                    continue;
                }
            }
            let needed = if self.buffer.len() < 5 {
                5 - self.buffer.len()
            } else {
                let len = u32::from_be_bytes([
                    self.buffer[1],
                    self.buffer[2],
                    self.buffer[3],
                    self.buffer[4],
                ]) as usize;
                5 + len - self.buffer.len()
            };
            let count = needed.min(self.pending.len());
            self.buffer.extend_from_slice(&self.pending.split_to(count));
            stream
                .flow_control()
                .release_capacity(count)
                .map_err(|_| StreamError::Closed)?;
        }
    }
}

async fn write_body(
    send: &mut h2::SendStream<Bytes>,
    mut body: Bytes,
    budget: Duration,
) -> Result<(), StreamError> {
    while !body.is_empty() {
        send.reserve_capacity(body.len());
        let capacity = tokio::time::timeout(budget, async {
            loop {
                match poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(0)) => {}
                    Some(Ok(capacity)) => break Ok(capacity),
                    Some(Err(_)) | None => break Err(StreamError::Closed),
                }
            }
        })
        .await
        .map_err(|_| StreamError::Timeout)??;
        let count = capacity.min(body.len());
        send.send_data(body.split_to(count), false)
            .map_err(|_| StreamError::Closed)?;
    }
    Ok(())
}

// sshforward carries arbitrary agent bytes in protobuf BytesMessage frames.
// The two directions must progress independently: an agent may answer while
// BuildKit is still holding its request stream open.
async fn ssh_bridge<T: AsyncRead + AsyncWrite + Unpin>(
    incoming: h2::RecvStream,
    outgoing: &mut h2::SendStream<Bytes>,
    io: T,
    budget: Duration,
) -> Result<(), StreamError> {
    let (mut read, mut write) = tokio::io::split(io);
    let receive = async {
        let mut incoming = incoming;
        let mut reader = MessageReader::default();
        while let Some(message) = reader.next(&mut incoming).await? {
            let bytes = BytesMessage::decode(&message).map_err(|_| StreamError::InvalidArgument)?;
            tokio::time::timeout(budget, write.write_all(&bytes.data))
                .await
                .map_err(|_| StreamError::Timeout)?
                .map_err(|_| StreamError::Unavailable)?;
        }
        write.shutdown().await.map_err(|_| StreamError::Unavailable)
    };
    let transmit = async {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let count = read
                .read(&mut buffer)
                .await
                .map_err(|_| StreamError::Unavailable)?;
            if count == 0 {
                return Ok(());
            }
            let message = BytesMessage {
                data: buffer[..count].to_vec(),
            }
            .encode();
            let frame =
                neotales_docker_buildkit::grpc::encode_message(0, &message, MAX_MESSAGE_BYTES)
                    .map_err(StreamError::Wire)?;
            write_body(outgoing, Bytes::from(frame), budget).await?;
        }
    };
    tokio::pin!(receive, transmit);
    tokio::select! {
        result = &mut transmit => result,
        result = &mut receive => {
            result?;
            tokio::time::timeout(budget, &mut transmit).await.map_err(|_| StreamError::Timeout)?
        }
    }
}

async fn ssh_key_agent(
    mut io: tokio::io::DuplexStream,
    server: &std::sync::Mutex<neotales_ssh::agent_server::AgentServer>,
) -> Result<(), StreamError> {
    loop {
        let mut length = [0_u8; 4];
        if io.read_exact(&mut length).await.is_err() {
            return Ok(());
        }
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > neotales_ssh::agent::MAX_FRAME_SIZE {
            return Err(StreamError::InvalidArgument);
        }
        let mut request = Zeroizing::new(vec![0; length]);
        io.read_exact(&mut request)
            .await
            .map_err(|_| StreamError::Closed)?;
        let response = server
            .lock()
            .map_err(|_| StreamError::Unavailable)?
            .answer_read_only(&request);
        let length = u32::try_from(response.len()).map_err(|_| StreamError::InvalidArgument)?;
        io.write_all(&length.to_be_bytes())
            .await
            .map_err(|_| StreamError::Closed)?;
        io.write_all(&response)
            .await
            .map_err(|_| StreamError::Closed)?;
    }
}

async fn serve_ssh_forward(
    request: http::Request<h2::RecvStream>,
    mut response: h2::server::SendResponse<Bytes>,
    budget: Duration,
    forwards: Option<&SshRegistry>,
) -> Result<(), StreamError> {
    let id = request
        .headers()
        .get("buildkit.ssh.id")
        .map(|v| v.to_str().map_err(|_| StreamError::InvalidArgument))
        .transpose();
    let selected = id.and_then(|id| {
        forwards
            .and_then(|f| f.forwards.get(ssh_id(id.unwrap_or(""))))
            .ok_or(StreamError::NotFound)
    });
    let mut head = http::Response::new(());
    head.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    let mut send = response
        .send_response(head, false)
        .map_err(|_| StreamError::Closed)?;
    let result = match selected {
        Err(error) => Err(error),
        #[cfg(unix)]
        Ok(SshForward::Socket(path)) => {
            match tokio::time::timeout(budget, tokio::net::UnixStream::connect(path)).await {
                Ok(Ok(socket)) => ssh_bridge(request.into_body(), &mut send, socket, budget).await,
                Ok(Err(_)) => Err(StreamError::Unavailable),
                Err(_) => Err(StreamError::Timeout),
            }
        }
        #[cfg(not(unix))]
        Ok(SshForward::Socket(_)) => Err(StreamError::Unimplemented),
        Ok(SshForward::Key(server)) => {
            let (bridge, agent) = tokio::io::duplex(32 * 1024);
            tokio::select! {
                result = ssh_bridge(request.into_body(), &mut send, bridge, budget) => result,
                result = ssh_key_agent(agent, server) => result,
            }
        }
    };
    let (code, message) = match &result {
        Ok(()) => ("0", ""),
        Err(StreamError::NotFound) => ("5", "SSH agent not found"),
        Err(StreamError::InvalidArgument | StreamError::Wire(_)) => {
            ("3", "invalid SSH agent request")
        }
        Err(StreamError::Timeout) => ("4", "SSH agent timeout"),
        Err(StreamError::Unimplemented) => ("12", "SSH agent unavailable"),
        Err(_) => ("14", "SSH agent unavailable"),
    };
    send_status(&mut send, code, message)?;
    result
}

// Wire protocol: tonistiigi/fsutil e075fd9305eb send.go and receive.go;
// moby/buildkit 6aebc64bd145fdf0bc27d439a75a47890fee80ba
// session/filesync/{filesync.go,filesync.proto} and source/local/source.go.
// The local name and filters are gRPC metadata, not REQ packet fields.
// STAT is emitted in sorted order; REQ.id indexes that order, DATA carries
// chunks and an empty DATA terminates that file. FIN is acknowledged with FIN.
// This engine is not advertised until its metadata filters are implemented.
#[allow(dead_code)]
#[allow(clippy::too_many_lines)] // Keep the two flow-control directions in one state machine.
async fn diffcopy(
    mut incoming: h2::RecvStream,
    outgoing: &mut h2::SendStream<Bytes>,
    snapshot: &super::buildkit_context::Snapshot,
    selected: &[usize],
    budget: Duration,
) -> Result<(), StreamError> {
    let entries: Vec<_> = selected.iter().map(|&i| &snapshot.entries[i]).collect();
    let mut reader = MessageReader::default();
    let mut stat_index = 0;
    let mut stats_finished = false;
    let mut requests = VecDeque::new();
    let mut requested = vec![false; entries.len()];
    let mut active: Option<(usize, usize)> = None;
    let mut encoded = Bytes::new();
    let mut received_fin = false;
    let mut sent_fin = false;

    loop {
        if encoded.is_empty() {
            let packet = if stat_index < entries.len() {
                let packet = FilePacket {
                    stat: Some(entries[stat_index].stat.clone()),
                    ..FilePacket::default()
                };
                stat_index += 1;
                Some(packet)
            } else if !stats_finished {
                stats_finished = true;
                Some(FilePacket::default())
            } else if let Some((id, offset)) = active {
                let data = entries[id]
                    .data
                    .as_ref()
                    .ok_or(StreamError::InvalidArgument)?;
                let end = offset.saturating_add(32 * 1024).min(data.len());
                let packet = FilePacket {
                    kind: 2,
                    id: u32::try_from(id).map_err(|_| StreamError::InvalidArgument)?,
                    data: data[offset..end].to_vec(),
                    ..FilePacket::default()
                };
                active = if offset == data.len() {
                    None
                } else {
                    Some((id, end))
                };
                Some(packet)
            } else if let Some(id) = requests.pop_front() {
                active = Some((id, 0));
                continue;
            } else if received_fin && !sent_fin {
                sent_fin = true;
                Some(FilePacket {
                    kind: 3,
                    ..FilePacket::default()
                })
            } else if sent_fin {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                outgoing
                    .send_trailers(trailers)
                    .map_err(|_| StreamError::Closed)?;
                return Ok(());
            } else {
                None
            };
            if let Some(packet) = packet {
                if std::env::var_os("NEOTALES_BUILDKIT_TRACE").as_deref()
                    == Some(std::ffi::OsStr::new("1"))
                {
                    eprintln!("buildkit filesync send={} id={}", packet.kind, packet.id);
                }
                encoded = Bytes::from(
                    neotales_docker_buildkit::grpc::encode_message(
                        0,
                        &packet.encode(),
                        MAX_MESSAGE_BYTES,
                    )
                    .map_err(StreamError::Wire)?,
                );
            }
        }

        if !encoded.is_empty() {
            outgoing.reserve_capacity(encoded.len());
        }
        tokio::time::timeout(budget, async {
            tokio::select! {
                incoming = reader.next(&mut incoming), if !received_fin => {
                    let message = incoming?.ok_or(StreamError::Closed)?;
                    let packet = FilePacket::decode(&message).map_err(|_| StreamError::InvalidArgument)?;
                    if std::env::var_os("NEOTALES_BUILDKIT_TRACE").as_deref() == Some(std::ffi::OsStr::new("1")) {
                        eprintln!("buildkit filesync recv={} id={}", packet.kind, packet.id);
                    }
                    match packet.kind {
                        1 => {
                            let id = usize::try_from(packet.id).map_err(|_| StreamError::InvalidArgument)?;
                            if id >= stat_index || id >= entries.len() || requested[id] || entries[id].data.is_none() {
                                return Err(StreamError::InvalidArgument);
                            }
                            requested[id] = true;
                            requests.push_back(id);
                        }
                        3 if stats_finished && active.is_none() && requests.is_empty() && encoded.is_empty() => received_fin = true,
                        // ERR is intentionally not echoed: its data is peer text.
                        _ => return Err(StreamError::InvalidArgument),
                    }
                }
                capacity = poll_fn(|cx| outgoing.poll_capacity(cx)), if !encoded.is_empty() => {
                    match capacity {
                        Some(Ok(0)) => {},
                        Some(Ok(capacity)) => {
                            let size = capacity.min(encoded.len());
                            outgoing.send_data(encoded.split_to(size), false).map_err(|_| StreamError::Closed)?;
                        }
                        Some(Err(_)) | None => return Err(StreamError::Closed),
                    }
                }
            }
            Ok(())
        }).await.map_err(|_| StreamError::Timeout)??;
    }
}

fn dispatch(
    path: &str,
    message: &[u8],
    secrets: Option<&Secrets>,
    ssh: Option<&SshRegistry>,
) -> Result<Vec<u8>, StreamError> {
    if path == SSH_CHECK_PATH {
        let request =
            CheckAgentRequest::decode(message).map_err(|_| StreamError::InvalidArgument)?;
        let id = ssh_id(&request.id);
        if id.len() > 256 || id.chars().any(char::is_control) {
            return Err(StreamError::InvalidArgument);
        }
        return if ssh.is_some_and(|registry| registry.forwards.contains_key(id)) {
            Ok(CheckAgentResponse.encode())
        } else {
            if let Some(registry) = ssh
                && let Ok(mut missing) = registry.missing.lock()
            {
                // Bound storage even if the peer asks about arbitrary IDs.
                if missing.len() < 128 {
                    missing.insert(id.to_owned());
                }
            }
            Err(StreamError::NotFound)
        };
    }
    if path != SECRET_PATH {
        return Err(StreamError::Unimplemented);
    }
    let secrets = secrets.ok_or(StreamError::Unimplemented)?;
    let request = GetSecretRequest::decode(message).map_err(|_| StreamError::InvalidArgument)?;
    let value = secrets.0.get(&request.id).ok_or(StreamError::NotFound)?;
    Ok(BytesMessage {
        data: value.to_vec(),
    }
    .encode())
}

fn selected_files(
    headers: &http::HeaderMap,
    snapshot: &super::buildkit_context::Snapshot,
) -> Result<Vec<usize>, StreamError> {
    let name = headers
        .get("dir-name")
        .and_then(|value| value.to_str().ok())
        .ok_or(StreamError::InvalidArgument)?;
    // BuildKit's dockerui/context.go defaults to these two independent local
    // source names. They refer to this explicitly supplied snapshot only.
    if name != "context" && name != "dockerfile" {
        return Err(StreamError::NotFound);
    }
    if std::env::var_os("NEOTALES_BUILDKIT_TRACE").as_deref() == Some(std::ffi::OsStr::new("1")) {
        eprintln!("buildkit filesync source={name}");
    }
    let mut includes = metadata_values(headers, "include-patterns")?;
    let excludes = metadata_values(headers, "exclude-patterns")?;
    // filesync passes repeated, optionally QueryEscape-encoded header values
    // as fsutil FollowPaths. Snapshots reject symlinks, so FollowLinks has no
    // extra link targets to resolve; matching the resulting patterns during
    // the bounded snapshot walk covers their files and descendants.
    for path in metadata_values(headers, "followpaths")? {
        if path == "." {
            continue;
        }
        if path.is_empty()
            || path.starts_with('!')
            || path.contains('\\')
            || std::path::Path::new(&path)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(StreamError::PermissionDenied);
        }
        includes.push(path);
    }
    super::buildkit_filter::select(snapshot, &includes, &excludes)
        .map_err(|()| StreamError::Unimplemented)
}

fn metadata_values(headers: &http::HeaderMap, name: &str) -> Result<Vec<String>, StreamError> {
    let encoded = headers
        .get(format!("{name}-encoded"))
        .map(|v| v.to_str().map_err(|_| StreamError::InvalidArgument))
        .transpose()?
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("t"));
    let mut result = Vec::new();
    let mut total = 0_usize;
    for value in headers.get_all(name) {
        let value = value.to_str().map_err(|_| StreamError::InvalidArgument)?;
        total = total
            .checked_add(value.len())
            .ok_or(StreamError::InvalidArgument)?;
        if total > 64 * 1024 || result.len() >= 4096 {
            return Err(StreamError::InvalidArgument);
        }
        if encoded {
            let bytes = value.as_bytes();
            let mut decoded = Vec::with_capacity(bytes.len());
            let mut index = 0;
            while index < bytes.len() {
                match bytes[index] {
                    b'%' => {
                        let hex = |offset| {
                            bytes
                                .get(index + offset)
                                .and_then(|b| char::from(*b).to_digit(16))
                                .ok_or(StreamError::InvalidArgument)
                        };
                        decoded.push(
                            u8::try_from((hex(1)? << 4) | hex(2)?)
                                .map_err(|_| StreamError::InvalidArgument)?,
                        );
                        index += 3;
                    }
                    b'+' => {
                        decoded.push(b' ');
                        index += 1;
                    }
                    byte => {
                        decoded.push(byte);
                        index += 1;
                    }
                }
            }
            result.push(String::from_utf8(decoded).map_err(|_| StreamError::InvalidArgument)?);
        } else {
            result.push(value.to_owned());
        }
    }
    Ok(result)
}

fn send_status(
    send: &mut h2::SendStream<Bytes>,
    code: &'static str,
    message: &'static str,
) -> Result<(), StreamError> {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static(code));
    trailers.insert("grpc-message", http::HeaderValue::from_static(message));
    send.send_trailers(trailers)
        .map_err(|_| StreamError::Closed)
}

async fn serve_filesync(
    request: http::Request<h2::RecvStream>,
    mut response: h2::server::SendResponse<Bytes>,
    budget: Duration,
    snapshot: &super::buildkit_context::Snapshot,
) -> Result<(), StreamError> {
    let selected = selected_files(request.headers(), snapshot);
    let mut head = http::Response::new(());
    head.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    let mut send = response
        .send_response(head, false)
        .map_err(|_| StreamError::Closed)?;
    let result = match selected {
        Ok(selected) => diffcopy(request.into_body(), &mut send, snapshot, &selected, budget).await,
        Err(error) => Err(error),
    };
    if let Err(error) = &result {
        let (code, message) = match error {
            StreamError::InvalidArgument | StreamError::Wire(_) => {
                ("3", "invalid filesync request")
            }
            StreamError::PermissionDenied => ("7", "filesync path refused"),
            StreamError::NotFound => ("5", "filesync source not found"),
            StreamError::Unimplemented => ("12", "filesync filter unsupported"),
            _ => ("13", "filesync transfer failed"),
        };
        send_status(&mut send, code, message)?;
    }
    result
}

async fn serve(
    request: http::Request<h2::RecvStream>,
    mut response: h2::server::SendResponse<Bytes>,
    budget: Duration,
    secrets: Option<&Secrets>,
    ssh: Option<&SshRegistry>,
) -> Result<(), StreamError> {
    let valid = request.method() == Method::POST && SESSION_PATHS.contains(&request.uri().path());
    let path = request.uri().path().to_owned();
    let mut body = request.into_body();
    let result = if valid {
        match read_message(&mut body).await {
            Ok(message) => dispatch(&path, &message, secrets, ssh),
            Err(error) => Err(error),
        }
    } else {
        Err(StreamError::Unimplemented)
    };
    let status = match &result {
        Ok(_) => "0",
        Err(StreamError::Unimplemented) => "12",
        Err(StreamError::Wire(GrpcError::Oversized)) => "8",
        Err(StreamError::InvalidArgument) => "3",
        Err(StreamError::NotFound) => "5",
        Err(StreamError::PermissionDenied) => "7",
        Err(_) => "13",
    };
    let mut head = http::Response::new(());
    head.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    let mut send = response
        .send_response(head, false)
        .map_err(|_| StreamError::Closed)?;
    if let Ok(payload) = &result {
        let frame = neotales_docker_buildkit::grpc::encode_message(0, payload, MAX_MESSAGE_BYTES)
            .map_err(StreamError::Wire)?;
        write_body(&mut send, Bytes::from(frame), budget).await?;
    }
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static(status));
    if status == "12" {
        trailers.insert(
            "grpc-message",
            http::HeaderValue::from_static("session method not implemented"),
        );
    }
    if path == SSH_CHECK_PATH && status == "5" {
        trailers.insert(
            "grpc-message",
            http::HeaderValue::from_static("SSH agent not found"),
        );
    }
    send.send_trailers(trailers)
        .map_err(|_| StreamError::Closed)?;
    result.map(|_| ())
}

// HTTP2-Settings contains a SETTINGS_MAX_CONCURRENT_STREAMS value of 100.
// The server-side HTTP/2 handshake remains responsible for its own settings.
#[allow(dead_code)] // Used by the future internal session connection driver.
pub(crate) async fn upgrade(
    engine: &RawEngine,
    id: &str,
    expose_secrets: bool,
    expose_filesync: bool,
    expose_ssh: bool,
) -> Result<SwitchedConnection, Error> {
    let mut request = RawRequest::new(Method::POST, "/session")
        .with_header(CONNECTION, "Upgrade, HTTP2-Settings")
        .with_header(UPGRADE, "h2c")
        .with_header(HeaderName::from_static("http2-settings"), "AAMAAABk")
        .with_header(HeaderName::from_static("x-docker-expose-session-uuid"), id);
    if expose_secrets {
        request = request.with_header(
            HeaderName::from_static("x-docker-expose-session-grpc-method"),
            SECRET_PATH,
        );
    }
    if expose_filesync {
        request.headers.append(
            HeaderName::from_static("x-docker-expose-session-grpc-method"),
            http::HeaderValue::from_static(FILESYNC_PATH),
        );
    }
    if expose_ssh {
        for path in [SSH_CHECK_PATH, SSH_FORWARD_PATH] {
            request.headers.append(
                HeaderName::from_static("x-docker-expose-session-grpc-method"),
                http::HeaderValue::from_static(path),
            );
        }
    }
    let response = engine.send_upgrading_session(request).await?;
    let valid_upgrade = response.headers.get_all(UPGRADE).iter().any(|header| {
        header.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case("h2c"))
        })
    });
    if response.status != StatusCode::SWITCHING_PROTOCOLS || !valid_upgrade {
        return Err(Error::transport("Engine session protocol upgrade rejected"));
    }
    // Hyper's Upgraded retains any bytes read beyond the HTTP response head.
    response.into_upgraded().await
}

/// Start the HTTP/2 driver, which owns the upgraded connection and streams.
#[allow(dead_code)] // The session RPC dispatcher is not implemented yet.
pub(crate) async fn handshake(
    engine: &RawEngine,
    id: &str,
    secrets: Option<Arc<Secrets>>,
    context: Option<Arc<super::buildkit_context::Snapshot>>,
    ssh: Option<Arc<SshRegistry>>,
) -> Result<SessionHandle, Error> {
    let (read, write) = upgrade(
        engine,
        id,
        secrets.is_some(),
        context.is_some(),
        ssh.is_some(),
    )
    .await?;
    // `Upgraded` includes hyper's read-ahead buffer; unsplitting preserves it.
    let io = read.unsplit(write);
    let connection = h2::server::handshake(io)
        .await
        .map_err(|_| Error::transport("Engine session HTTP/2 handshake failed"))?;
    Ok(drive_with_providers(
        connection,
        WRITE_CAPACITY_BUDGET,
        secrets,
        context,
        ssh,
    ))
}

#[cfg(test)]
pub(crate) async fn check_missing_default_for_test() {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let server = tokio::spawn(async move { h2::server::handshake(server_io).await.unwrap() });
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(connection);
    let registry = Arc::new(SshRegistry::new(BTreeMap::new()));
    let handle = drive_with_providers(
        server.await.unwrap(),
        WRITE_CAPACITY_BUDGET,
        None,
        None,
        Some(registry.clone()),
    );
    let (response, mut send) = client
        .send_request(http::Request::post(SSH_CHECK_PATH).body(()).unwrap(), false)
        .unwrap();
    let request = CheckAgentRequest { id: String::new() }.encode();
    let frame =
        neotales_docker_buildkit::grpc::encode_message(0, &request, MAX_MESSAGE_BYTES).unwrap();
    send.send_data(Bytes::from(frame), true).unwrap();
    let mut body = response.await.unwrap().into_body();
    while let Some(data) = body.data().await {
        data.unwrap();
    }
    assert_eq!(body.trailers().await.unwrap().unwrap()["grpc-status"], "5");
    assert_eq!(registry.missing().as_deref(), Some("default"));
    drop(handle);
    driver.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{RawEngine, RawTarget};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn filesync_selection_is_bounded_and_fails_closed_on_filters() {
        use neotales_docker_buildkit::proto::FileStat;
        let snapshot = super::super::buildkit_context::Snapshot {
            entries: ["dir", "dir/file", "secret"]
                .into_iter()
                .map(|path| super::super::buildkit_context::Entry {
                    stat: FileStat {
                        path: path.into(),
                        ..FileStat::default()
                    },
                    data: None,
                })
                .collect(),
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("dir-name", "dockerfile".parse().unwrap());
        headers.insert("followpaths", "dir/file".parse().unwrap());
        assert_eq!(selected_files(&headers, &snapshot).unwrap(), [0, 1]);
        headers.insert("followpaths", "../secret".parse().unwrap());
        assert_eq!(
            selected_files(&headers, &snapshot),
            Err(StreamError::PermissionDenied)
        );
        headers.remove("followpaths");
        headers.insert("exclude-patterns", "*.key".parse().unwrap());
        assert_eq!(selected_files(&headers, &snapshot).unwrap(), [0, 1, 2]);
        headers.remove("exclude-patterns");
        headers.insert("dir-name", "unregistered".parse().unwrap());
        assert_eq!(
            selected_files(&headers, &snapshot),
            Err(StreamError::NotFound)
        );
    }

    #[test]
    fn followpaths_patterns_select_files_and_directories_and_reject_unsafe_inputs() {
        use neotales_docker_buildkit::proto::FileStat;
        let snapshot = super::super::buildkit_context::Snapshot {
            entries: [
                ("dir", false),
                ("dir/a.txt", true),
                ("dir/nested", false),
                ("dir/nested/file", true),
                ("other", true),
            ]
            .into_iter()
            .map(|(path, file)| super::super::buildkit_context::Entry {
                stat: FileStat {
                    path: path.into(),
                    ..Default::default()
                },
                data: file.then(Vec::new),
            })
            .collect(),
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("dir-name", "context".parse().unwrap());
        for (path, expected) in [
            ("dir/a.txt", vec![0, 1]),
            ("dir/*.txt", vec![0, 1]),
            ("dir/nested", vec![0, 2, 3]),
        ] {
            headers.insert("followpaths", path.parse().unwrap());
            assert_eq!(selected_files(&headers, &snapshot).unwrap(), expected);
        }
        for path in ["../other", "/other", "dir/../../other", "!other"] {
            headers.insert("followpaths", path.parse().unwrap());
            assert_eq!(
                selected_files(&headers, &snapshot),
                Err(StreamError::PermissionDenied)
            );
        }
        headers.insert("followpaths-encoded", "1".parse().unwrap());
        headers.insert("followpaths", "dir%2F%2A.txt".parse().unwrap());
        assert_eq!(selected_files(&headers, &snapshot).unwrap(), [0, 1]);
        headers.insert("followpaths", "a".repeat(65537).parse().unwrap());
        assert_eq!(
            selected_files(&headers, &snapshot),
            Err(StreamError::InvalidArgument)
        );
    }

    #[test]
    fn encoded_metadata_is_decoded_without_lossy_path_aliases() {
        let mut headers = http::HeaderMap::new();
        headers.insert("followpaths-encoded", "1".parse().unwrap());
        headers.insert("followpaths", "a%2Fb+c%26d".parse().unwrap());
        assert_eq!(
            metadata_values(&headers, "followpaths").unwrap(),
            ["a/b c&d"]
        );
        headers.insert("followpaths-encoded", "t".parse().unwrap());
        assert_eq!(
            metadata_values(&headers, "followpaths").unwrap(),
            ["a/b c&d"]
        );
        for bad in ["%ff", "%0", "%zz"] {
            headers.insert("followpaths", bad.parse().unwrap());
            assert_eq!(
                metadata_values(&headers, "followpaths"),
                Err(StreamError::InvalidArgument)
            );
        }
    }

    #[tokio::test]
    async fn filesync_rejections_are_grpc_trailers() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move { h2::server::handshake(server_io).await.unwrap() });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let snapshot = Arc::new(super::super::buildkit_context::Snapshot {
            entries: Vec::new(),
        });
        let handle = drive_with_providers(
            server.await.unwrap(),
            WRITE_CAPACITY_BUDGET,
            None,
            Some(snapshot),
            None,
        );
        for (name, follow, expected) in [("other", "", "5"), ("context", "../bad", "7")] {
            let request = http::Request::post(FILESYNC_PATH)
                .header("dir-name", name)
                .header("followpaths", follow)
                .body(())
                .unwrap();
            let (response, _send) = client.send_request(request, false).unwrap();
            let mut body = response.await.unwrap().into_body();
            while let Some(data) = body.data().await {
                data.unwrap();
            }
            let trailers = body.trailers().await.unwrap().unwrap();
            assert_eq!(trailers["grpc-status"], expected);
            assert!(!format!("{trailers:?}").contains("../bad"));
        }
        drop(handle);
        driver.abort();
    }

    #[tokio::test]
    async fn diffcopy_transfers_requested_file_and_acknowledges_fin() {
        use neotales_docker_buildkit::proto::FileStat;
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (request, mut response) = conn.accept().await.unwrap().unwrap();
            let mut outgoing = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            let snapshot = super::super::buildkit_context::Snapshot {
                entries: vec![super::super::buildkit_context::Entry {
                    stat: FileStat {
                        path: "file".into(),
                        mode: 0o644,
                        size: 3,
                        ..FileStat::default()
                    },
                    data: Some(b"abc".to_vec()),
                }],
            };
            let mut handler = tokio::spawn(async move {
                diffcopy(
                    request.into_body(),
                    &mut outgoing,
                    &snapshot,
                    &[0],
                    Duration::from_secs(3),
                )
                .await
            });
            loop {
                tokio::select! {
                    result = &mut handler => { result.unwrap().unwrap(); break; }
                    accepted = conn.accept() => assert!(accepted.is_some(), "unexpected close"),
                }
            }
            while conn.accept().await.is_some() {}
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let (response, mut send) = client
            .send_request(http::Request::post("/test").body(()).unwrap(), false)
            .unwrap();
        let mut incoming = response.await.unwrap().into_body();
        let mut reader = MessageReader::default();
        let stat = FilePacket::decode(&reader.next(&mut incoming).await.unwrap().unwrap()).unwrap();
        assert_eq!(stat.stat.unwrap().path, "file");
        let end = FilePacket::decode(&reader.next(&mut incoming).await.unwrap().unwrap()).unwrap();
        assert_eq!(end, FilePacket::default());
        let packet = FilePacket {
            kind: 1,
            id: 0,
            ..FilePacket::default()
        };
        let frame =
            neotales_docker_buildkit::grpc::encode_message(0, &packet.encode(), MAX_MESSAGE_BYTES)
                .unwrap();
        send.send_data(Bytes::from(frame), false).unwrap();
        let data = FilePacket::decode(&reader.next(&mut incoming).await.unwrap().unwrap()).unwrap();
        assert_eq!(data.kind, 2);
        assert_eq!(data.id, 0);
        assert_eq!(data.data, b"abc");
        let eof = FilePacket::decode(&reader.next(&mut incoming).await.unwrap().unwrap()).unwrap();
        assert_eq!(eof.kind, 2);
        assert!(eof.data.is_empty(), "expected eof.data to be empty");
        let fin = FilePacket {
            kind: 3,
            ..FilePacket::default()
        };
        let frame =
            neotales_docker_buildkit::grpc::encode_message(0, &fin.encode(), MAX_MESSAGE_BYTES)
                .unwrap();
        send.send_data(Bytes::from(frame), true).unwrap();
        assert_eq!(
            FilePacket::decode(&reader.next(&mut incoming).await.unwrap().unwrap())
                .unwrap()
                .kind,
            3
        );
        assert!(reader.next(&mut incoming).await.unwrap().is_none());
        assert_eq!(
            incoming.trailers().await.unwrap().unwrap()["grpc-status"],
            "0"
        );
        drop(incoming);
        drop(send);
        drop(client);
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        driver.abort();
    }

    #[tokio::test]
    async fn diffcopy_refuses_unknown_packets() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (request, mut response) = conn.accept().await.unwrap().unwrap();
            let mut outgoing = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            let snapshot = super::super::buildkit_context::Snapshot {
                entries: Vec::new(),
            };
            let mut handler = tokio::spawn(async move {
                diffcopy(
                    request.into_body(),
                    &mut outgoing,
                    &snapshot,
                    &[],
                    Duration::from_secs(3),
                )
                .await
            });
            loop {
                tokio::select! {
                    result = &mut handler => return result.unwrap(),
                    accepted = conn.accept() => if accepted.is_none() { return Err(StreamError::Closed); }
                }
            }
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let (response, mut send) = client
            .send_request(http::Request::post("/test").body(()).unwrap(), false)
            .unwrap();
        let _incoming = response.await.unwrap().into_body();
        let packet = FilePacket {
            kind: 99,
            ..FilePacket::default()
        };
        let frame =
            neotales_docker_buildkit::grpc::encode_message(0, &packet.encode(), MAX_MESSAGE_BYTES)
                .unwrap();
        send.send_data(Bytes::from(frame), true).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap(),
            Err(StreamError::InvalidArgument)
        );
        driver.abort();
    }

    #[tokio::test]
    async fn streaming_reader_preserves_coalesced_and_split_frames() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (request, mut response) = conn.accept().await.unwrap().unwrap();
            let mut handler = tokio::spawn(async move {
                let mut body = request.into_body();
                let mut reader = MessageReader::default();
                assert_eq!(reader.next(&mut body).await.unwrap().unwrap(), b"first");
                assert_eq!(reader.next(&mut body).await.unwrap().unwrap(), b"second");
                assert!(reader.next(&mut body).await.unwrap().is_none());
                response
                    .send_response(http::Response::new(()), true)
                    .unwrap();
            });
            loop {
                tokio::select! {
                    result = &mut handler => { result.unwrap(); break; }
                    accepted = conn.accept() => if accepted.is_none() { break; }
                }
            }
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let (_response, mut send) = client
            .send_request(http::Request::post("/test").body(()).unwrap(), false)
            .unwrap();
        let mut first =
            neotales_docker_buildkit::grpc::encode_message(0, b"first", MAX_MESSAGE_BYTES).unwrap();
        first.extend_from_slice(
            &neotales_docker_buildkit::grpc::encode_message(0, b"second", MAX_MESSAGE_BYTES)
                .unwrap(),
        );
        send.send_data(Bytes::copy_from_slice(&first[..2]), false)
            .unwrap();
        send.send_data(Bytes::copy_from_slice(&first[2..]), true)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        driver.abort();
    }

    #[tokio::test]
    async fn secret_provider_serves_only_explicit_ids() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move { h2::server::handshake(server_io).await.unwrap() });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let peer = tokio::spawn(connection);
        let secrets =
            Arc::new(Secrets::new([("token".into(), b"test-value".to_vec())].into()).unwrap());
        let handle =
            drive_with_secrets(server.await.unwrap(), WRITE_CAPACITY_BUDGET, Some(secrets));
        for (id, expected) in [("token", "0"), ("other", "5")] {
            let request = http::Request::post(SECRET_PATH).body(()).unwrap();
            let (response, mut send) = client.send_request(request, false).unwrap();
            let message = GetSecretRequest {
                id: id.into(),
                ..GetSecretRequest::default()
            }
            .encode();
            let frame =
                neotales_docker_buildkit::grpc::encode_message(0, &message, MAX_MESSAGE_BYTES)
                    .unwrap();
            send.send_data(Bytes::from(frame), true).unwrap();
            let response = response.await.unwrap();
            assert_eq!(
                response.headers()[http::header::CONTENT_TYPE],
                "application/grpc"
            );
            let mut body = response.into_body();
            let mut received = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                received.extend_from_slice(&chunk);
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
            let trailers = body.trailers().await.unwrap().unwrap();
            assert_eq!(trailers["grpc-status"], expected);
            if expected == "0" {
                let (_, message, _) = decode_message(&received, MAX_MESSAGE_BYTES).unwrap();
                assert_eq!(BytesMessage::decode(message).unwrap().data, b"test-value");
            } else {
                assert!(received.is_empty(), "expected received to be empty");
                assert!(!format!("{trailers:?}").contains("test-value"));
            }
        }
        drop(handle);
        peer.abort();
    }

    #[test]
    fn secret_provider_rejects_excessive_input() {
        assert!(matches!(
            Secrets::new([(String::new(), Vec::new())].into()),
            Err(SecretError::InvalidId)
        ));
        assert!(matches!(
            Secrets::new([("x".into(), vec![0; MAX_SECRET_BYTES + 1])].into()),
            Err(SecretError::TooLarge)
        ));
        let many = (0..=MAX_SECRETS)
            .map(|i| (i.to_string(), Vec::new()))
            .collect();
        assert!(matches!(Secrets::new(many), Err(SecretError::TooLarge)));
    }

    async fn pair() -> (
        h2::client::SendRequest<Bytes>,
        SessionHandle,
        JoinHandle<Result<(), h2::Error>>,
    ) {
        let (client, server) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move { h2::server::handshake(server).await.unwrap() });
        let (client, connection) = h2::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(connection);
        (
            client,
            drive(server.await.unwrap(), WRITE_CAPACITY_BUDGET),
            driver,
        )
    }

    async fn call(client: &mut h2::client::SendRequest<Bytes>, path: &str, body: Bytes) -> u32 {
        let request = http::Request::post(path).body(()).unwrap();
        let (response, mut send) = client.send_request(request, false).unwrap();
        send.send_data(body, true).unwrap();
        let mut body = response.await.unwrap().into_body();
        while let Some(data) = body.data().await {
            data.unwrap();
        }
        let trailers = body.trailers().await.unwrap().unwrap();
        let status = trailers["grpc-status"].to_str().unwrap();
        // Do not pass peer-provided grpc-message into the typed error.
        match neotales_docker_buildkit::grpc::parse_status(Some(status), None) {
            Ok(()) => 0,
            Err(GrpcError::Status {
                code,
                message: None,
            }) => code,
            other => panic!("unexpected status: {other:?}"),
        }
    }

    #[tokio::test]
    async fn ssh_check_uses_request_id_and_default() {
        for has_default in [false, true] {
            let (client_io, server_io) = tokio::io::duplex(65536);
            let server =
                tokio::spawn(async move { h2::server::handshake(server_io).await.unwrap() });
            let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
            let driver = tokio::spawn(connection);
            let mut forwards = SshForwards::new();
            forwards.insert("named".into(), SshForward::Socket("unused".into()));
            if has_default {
                forwards.insert("default".into(), SshForward::Socket("unused".into()));
            }
            let handle = drive_with_providers(
                server.await.unwrap(),
                WRITE_CAPACITY_BUDGET,
                None,
                None,
                Some(Arc::new(SshRegistry::new(forwards))),
            );
            for (id, expected) in [
                ("named", 0),
                ("missing", 5),
                ("", if has_default { 0 } else { 5 }),
            ] {
                let message = CheckAgentRequest { id: id.into() }.encode();
                let frame =
                    neotales_docker_buildkit::grpc::encode_message(0, &message, MAX_MESSAGE_BYTES)
                        .unwrap();
                assert_eq!(
                    call(&mut client, SSH_CHECK_PATH, Bytes::from(frame)).await,
                    expected
                );
            }
            drop(handle);
            driver.abort();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ssh_forward_socket_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            socket.write_all(b"pong").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let signer = neotales_ssh::auth::PublicKeySigner::ed25519(
            neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [77; 32]),
        );
        let blob = signer.public_key_blob().unwrap();
        let server = neotales_ssh::agent_server::AgentServer::from_signer(signer).unwrap();
        let forwards = SshForwards::from([
            ("default".into(), SshForward::Socket(path)),
            (
                "refused".into(),
                SshForward::Socket(dir.path().join("missing")),
            ),
            ("key".into(), SshForward::Key(std::sync::Mutex::new(server))),
        ]);
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move { h2::server::handshake(server_io).await.unwrap() });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let handle = drive_with_providers(
            server.await.unwrap(),
            WRITE_CAPACITY_BUDGET,
            None,
            None,
            Some(Arc::new(SshRegistry::new(forwards))),
        );
        for (id, status) in [("unknown", "5"), ("refused", "14")] {
            let (response, _send) = client
                .send_request(
                    http::Request::post(SSH_FORWARD_PATH)
                        .header("buildkit.ssh.id", id)
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let mut body = response.await.unwrap().into_body();
            while let Some(data) = body.data().await {
                data.unwrap();
            }
            let trailers = body.trailers().await.unwrap().unwrap();
            assert_eq!(trailers["grpc-status"], status);
            assert!(!format!("{trailers:?}").contains("missing"));
        }
        for (id, input, expected) in [
            ("", b"ping".as_slice(), b"pong".as_slice()),
            ("key", &[0, 0, 0, 1, 11], &[]),
        ] {
            let (response, mut send) = client
                .send_request(
                    http::Request::post(SSH_FORWARD_PATH)
                        .header("buildkit.ssh.id", id)
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let message = BytesMessage {
                data: input.to_vec(),
            }
            .encode();
            let frame =
                neotales_docker_buildkit::grpc::encode_message(0, &message, MAX_MESSAGE_BYTES)
                    .unwrap();
            send.send_data(Bytes::from(frame), false).unwrap();
            let mut body = response.await.unwrap().into_body();
            let mut reader = MessageReader::default();
            let output = BytesMessage::decode(&reader.next(&mut body).await.unwrap().unwrap())
                .unwrap()
                .data;
            if id == "key" {
                assert_eq!(output[4], 12);
                assert!(output.windows(blob.len()).any(|window| window == blob));
            } else {
                assert_eq!(output, expected);
            }
            if id == "key" {
                send.send_data(Bytes::new(), true).unwrap();
            }
            while reader.next(&mut body).await.unwrap().is_some() {}
            assert_eq!(body.trailers().await.unwrap().unwrap()["grpc-status"], "0");
        }
        echo.await.unwrap();
        drop(handle);
        driver.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "opt-in: requires local sshd and /run/sshd"]
    #[allow(clippy::too_many_lines)] // One test owns the sshd and both transport ends.
    async fn ssh_forward_authenticates_real_sshd() {
        use base64::Engine as _;
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        assert!(
            std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&host)
                .status()
                .unwrap()
                .success()
        );
        let signer = neotales_ssh::auth::PublicKeySigner::ed25519(
            neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [82; 32]),
        );
        let blob = signer.public_key_blob().unwrap();
        let authorized = dir.path().join("authorized_keys");
        std::fs::write(
            &authorized,
            format!(
                "ssh-ed25519 {}\n",
                base64::engine::general_purpose::STANDARD.encode(blob)
            ),
        )
        .unwrap();
        let user = String::from_utf8(
            std::process::Command::new("id")
                .arg("-un")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let user = user.trim();
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let config = dir.path().join("sshd_config");
        std::fs::write(&config, format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\nLogLevel ERROR\n",
            host.display(), dir.path().join("pid").display(), authorized.display())).unwrap();
        let mut sshd = tokio::process::Command::new("/usr/bin/sshd")
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .kill_on_drop(true)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let ready = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    break;
                }
                if let Some(status) = sshd.try_wait().unwrap() {
                    panic!("sshd exited: {status}");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        ready.expect("sshd started");
        let socket = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move { h2::server::handshake(server_io).await.unwrap() });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let registry = SshRegistry::new(SshForwards::from([(
            "default".into(),
            SshForward::Key(std::sync::Mutex::new(
                neotales_ssh::agent_server::AgentServer::from_signer(signer).unwrap(),
            )),
        )]));
        let handle = drive_with_providers(
            server.await.unwrap(),
            WRITE_CAPACITY_BUDGET,
            None,
            None,
            Some(Arc::new(registry)),
        );
        let shim = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (response, mut send) = client
                .send_request(
                    http::Request::post(SSH_FORWARD_PATH).body(()).unwrap(),
                    false,
                )
                .unwrap();
            let mut incoming = response.await.unwrap().into_body();
            let (mut read, mut write) = socket.into_split();
            let mut reader = MessageReader::default();
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                tokio::select! {
                    data = read.read(&mut buffer) => {
                        let count = data.unwrap();
                        if count == 0 { let _ = send.send_data(Bytes::new(), true); break; }
                        let payload = BytesMessage { data: buffer[..count].to_vec() }.encode();
                        let frame = neotales_docker_buildkit::grpc::encode_message(0, &payload, MAX_MESSAGE_BYTES).unwrap();
                        send.send_data(Bytes::from(frame), false).unwrap();
                    }
                    data = reader.next(&mut incoming) => match data.unwrap() {
                        Some(message) => write.write_all(&BytesMessage::decode(&message).unwrap().data).await.unwrap(),
                        None => break,
                    },
                }
            }
        });
        let output = tokio::time::timeout(
            Duration::from_secs(20),
            tokio::process::Command::new("ssh")
                .args([
                    "-F",
                    "/dev/null",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "IdentityFile=none",
                    "-o",
                ])
                .arg(format!("IdentityAgent={}", socket.display()))
                .args(["-p", &port.to_string(), "-l", user, "127.0.0.1", "true"])
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "ssh failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        tokio::time::timeout(Duration::from_secs(5), shim)
            .await
            .unwrap()
            .unwrap();
        drop(handle);
        driver.abort();
        let _ = sshd.kill().await;
    }

    #[tokio::test]
    async fn unknown_and_valid_streams_share_connection() {
        let (mut client, handle, driver) = pair().await;
        assert_eq!(call(&mut client, "/unknown", Bytes::new()).await, 12);
        let frame =
            neotales_docker_buildkit::grpc::encode_message(0, b"hello", MAX_MESSAGE_BYTES).unwrap();
        assert_eq!(
            call(&mut client, SESSION_PATHS[0], Bytes::from(frame)).await,
            12
        );
        let oversized = Bytes::from_static(&[0, 0, 64, 0, 1]);
        assert_eq!(call(&mut client, SESSION_PATHS[0], oversized).await, 8);
        drop(handle);
        let _ = tokio::time::timeout(Duration::from_secs(2), driver)
            .await
            .expect("peer observes closure");
    }

    #[tokio::test]
    async fn framed_exchange_and_capacity_timeout() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (request, mut response) = conn.accept().await.unwrap().unwrap();
            let mut streams = JoinSet::new();
            streams.spawn(async move {
                let mut incoming = request.into_body();
                assert_eq!(read_message(&mut incoming).await.unwrap(), b"hello");
                let mut send = response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let frame =
                    neotales_docker_buildkit::grpc::encode_message(0, b"world", MAX_MESSAGE_BYTES)
                        .unwrap();
                write_body(&mut send, Bytes::from(frame), Duration::from_secs(1))
                    .await
                    .unwrap();
                let error = write_body(
                    &mut send,
                    Bytes::from(vec![0; 4 * 1024 * 1024]),
                    Duration::from_millis(50),
                )
                .await
                .unwrap_err();
                assert_eq!(error, StreamError::Timeout);
            });
            loop {
                tokio::select! {
                    _ = streams.join_next() => break,
                    _ = conn.accept() => {}
                }
            }
        });
        let (mut client, conn) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(conn);
        let (response, mut send) = client
            .send_request(
                http::Request::post(SESSION_PATHS[0]).body(()).unwrap(),
                false,
            )
            .unwrap();
        send.send_data(
            Bytes::from(
                neotales_docker_buildkit::grpc::encode_message(0, b"hello", MAX_MESSAGE_BYTES)
                    .unwrap(),
            ),
            true,
        )
        .unwrap();
        let mut incoming = response.await.unwrap().into_body();
        let first = incoming.data().await.unwrap().unwrap();
        assert_eq!(
            decode_message(&first, MAX_MESSAGE_BYTES).unwrap().1,
            b"world"
        );
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        driver.abort();
    }

    async fn peer(
        response: &'static [u8],
        secrets: bool,
    ) -> (RawEngine, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                bytes.push(byte[0]);
                assert!(bytes.len() < 8192);
            }
            let request = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("post /session http/1.1\r\n"));
            assert!(request.contains("connection: upgrade, http2-settings\r\n"));
            assert!(request.contains("upgrade: h2c\r\n"));
            assert!(request.contains("http2-settings: "));
            assert!(request.contains("x-docker-expose-session-uuid: test-id\r\n"));
            assert_eq!(request.contains("x-docker-expose-session-grpc-method: /moby.buildkit.secrets.v1.secrets/getsecret\r\n"), secrets);
            stream.write_all(response).await.unwrap();
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

    #[tokio::test]
    async fn upgraded_connection_accepts_http2_client_preface() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n").await.unwrap();
            let (client, connection) = h2::client::handshake(socket).await.unwrap();
            drop(client);
            connection.await
        });
        let engine = RawEngine::new(
            RawTarget::Tcp {
                host: address.ip().to_string(),
                port: address.port(),
            },
            crate::API_VERSION,
        );
        let connection = super::handshake(&engine, "test-id", None, None, None)
            .await
            .unwrap();
        drop(connection);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), peer)
            .await
            .expect("connection closes")
            .unwrap();
    }

    #[tokio::test]
    async fn upgrade_preserves_pipelined_bytes() {
        let (engine, peer) = peer(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\nprecious", false).await;
        let (mut read, _write) = super::upgrade(&engine, "test-id", false, false, false)
            .await
            .unwrap();
        let mut bytes = [0; 8];
        read.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"precious");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn upgrade_advertises_secret_provider_only_when_enabled() {
        let (engine, peer) = peer(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
            true,
        )
        .await;
        drop(
            super::upgrade(&engine, "test-id", true, false, false)
                .await
                .unwrap(),
        );
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_wrong_status_or_missing_upgrade() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n".as_slice(),
        ] {
            let (engine, peer) = peer(response, false).await;
            assert_eq!(
                super::upgrade(&engine, "test-id", false, false, false)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                crate::ErrorKind::Transport
            );
            peer.await.unwrap();
        }
    }
}
