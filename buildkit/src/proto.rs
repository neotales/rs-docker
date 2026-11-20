#![allow(missing_docs)] // Internal cross-crate wire types, not a stable API.
//! Minimal protobuf messages, without framing. `crate::grpc` supplies framing.
//!
//! Field numbers and wire types: moby/buildkit commit
//! 6aebc64bd145fdf0bc27d439a75a47890fee80ba,
//! `api/services/control/control.proto`, `session/secrets/secrets.proto`,
//! and `session/filesync/filesync.proto`. In particular SolveRequest's Session,
//! Frontend and FrontendAttrs are 5, 6 and 7, not 10, 1 and 2. Vertex has no
//! logs field; logs belong to StatusResponse. VertexLog.stream is int64.
//! Timestamp is google/protobuf/timestamp.proto (seconds=1, nanos=2).
//! FileSync's packets are from tonistiigi/fsutil commit e075fd9305eb,
//! `types/wire.proto` and `types/stat.proto`, pinned in BuildKit's go.mod.

use std::collections::BTreeMap;

use crate::grpc::MAX_MESSAGE_BYTES;

pub const SECRETS_SERVICE: &str = "moby.buildkit.secrets.v1.Secrets";
pub const FILESYNC_SERVICE: &str = "moby.filesync.v1.FileSync";
pub const FILESEND_SERVICE: &str = "moby.filesync.v1.FileSend";
pub const SSHFORWARD_SERVICE: &str = "moby.sshforward.v1.SSH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    Truncated,
    Varint,
    InvalidTag,
    WireType,
    Utf8,
    Oversized,
}

type Result<T> = std::result::Result<T, ProtoError>;

fn varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 128 {
        out.push(n.to_le_bytes()[0] | 0x80);
        n >>= 7;
    }
    out.push(n.to_le_bytes()[0]);
}

fn tag(field: u32, wire: u8, out: &mut Vec<u8>) {
    varint((u64::from(field) << 3) | u64::from(wire), out);
}

fn number(field: u32, value: u64, out: &mut Vec<u8>) {
    tag(field, 0, out);
    varint(value, out);
}

#[allow(dead_code)] // Primitive available for future verified messages.
fn fixed64(field: u32, value: u64, out: &mut Vec<u8>) {
    tag(field, 1, out);
    out.extend_from_slice(&value.to_le_bytes());
}

fn bytes(field: u32, value: &[u8], out: &mut Vec<u8>) {
    tag(field, 2, out);
    varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn string(field: u32, value: &str, out: &mut Vec<u8>) {
    if !value.is_empty() {
        bytes(field, value.as_bytes(), out);
    }
}

#[derive(Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Result<Self> {
        if input.len() > MAX_MESSAGE_BYTES {
            return Err(ProtoError::Oversized);
        }
        Ok(Self { input, pos: 0 })
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0;
        for i in 0..10 {
            let byte = *self.input.get(self.pos).ok_or(ProtoError::Truncated)?;
            self.pos += 1;
            if i == 9 && byte > 1 {
                return Err(ProtoError::Varint);
            }
            value |= u64::from(byte & 0x7f) << (i * 7);
            if byte & 0x80 == 0 {
                if i > 0 && byte == 0 {
                    return Err(ProtoError::Varint);
                }
                return Ok(value);
            }
        }
        Err(ProtoError::Varint)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(ProtoError::Truncated)?;
        let value = self.input.get(self.pos..end).ok_or(ProtoError::Truncated)?;
        self.pos = end;
        Ok(value)
    }

    fn next(&mut self) -> Result<Option<(u32, u8)>> {
        if self.pos == self.input.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = key >> 3;
        if field == 0 || field > 0x1fff_ffff {
            return Err(ProtoError::InvalidTag);
        }
        Ok(Some((
            u32::try_from(field).map_err(|_| ProtoError::InvalidTag)?,
            key.to_le_bytes()[0] & 7,
        )))
    }

    fn number(&mut self, wire: u8) -> Result<u64> {
        if wire != 0 {
            return Err(ProtoError::WireType);
        }
        self.varint()
    }

    fn fixed64(&mut self, wire: u8) -> Result<u64> {
        if wire != 1 {
            return Err(ProtoError::WireType);
        }
        let mut value = [0; 8];
        value.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(value))
    }

    fn bytes(&mut self, wire: u8) -> Result<&'a [u8]> {
        if wire != 2 {
            return Err(ProtoError::WireType);
        }
        let len = usize::try_from(self.varint()?).map_err(|_| ProtoError::Truncated)?;
        self.take(len)
    }

    fn string(&mut self, wire: u8) -> Result<String> {
        Ok(std::str::from_utf8(self.bytes(wire)?)
            .map_err(|_| ProtoError::Utf8)?
            .to_owned())
    }

    fn skip(&mut self, wire: u8) -> Result<()> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => {
                self.fixed64(1)?;
            }
            2 => {
                self.bytes(2)?;
            }
            5 => {
                self.take(4)?;
            }
            _ => return Err(ProtoError::WireType),
        }
        Ok(())
    }
}

pub trait Message: Sized + Default {
    fn encode_to(&self, out: &mut Vec<u8>);
    fn merge_field(&mut self, field: u32, wire: u8, reader: &mut Reader<'_>) -> Result<()>;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_to(&mut out);
        out
    }

    fn decode(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input)?;
        let mut value = Self::default();
        while let Some((field, wire)) = reader.next()? {
            value.merge_field(field, wire, &mut reader)?;
        }
        Ok(value)
    }
}

fn nested<M: Message>(field: u32, message: &M, out: &mut Vec<u8>) {
    bytes(field, &message.encode(), out);
}

fn map_encode(field: u32, map: &BTreeMap<String, String>, out: &mut Vec<u8>) {
    for (key, value) in map {
        let mut entry = Vec::new();
        string(1, key, &mut entry);
        string(2, value, &mut entry);
        bytes(field, &entry, out);
    }
}

fn map_decode(input: &[u8], map: &mut BTreeMap<String, String>) -> Result<()> {
    let mut r = Reader::new(input)?;
    let (mut key, mut value) = (String::new(), String::new());
    while let Some((field, wire)) = r.next()? {
        match field {
            1 => key = r.string(wire)?,
            2 => value = r.string(wire)?,
            _ => r.skip(wire)?,
        }
    }
    map.insert(key, value);
    Ok(())
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SolveRequest {
    pub reference: String,
    pub frontend: String,
    pub frontend_attrs: BTreeMap<String, String>,
    pub session: String,
    pub exporters: Vec<Exporter>,
    pub cache: CacheOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CacheOptions {
    pub exports: Vec<CacheOptionsEntry>,
    pub imports: Vec<CacheOptionsEntry>,
}

#[derive(Default, Clone, PartialEq, Eq)]
pub struct CacheOptionsEntry {
    pub kind: String,
    pub attrs: BTreeMap<String, String>,
}

impl std::fmt::Debug for CacheOptionsEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheOptionsEntry")
            .field("kind", &self.kind)
            .field("attrs", &"<withheld>")
            .finish()
    }
}

impl Message for CacheOptionsEntry {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.kind, out);
        map_encode(2, &self.attrs, out);
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.kind = r.string(wire)?,
            2 => map_decode(r.bytes(wire)?, &mut self.attrs)?,
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

impl Message for CacheOptions {
    fn encode_to(&self, out: &mut Vec<u8>) {
        for export in &self.exports {
            nested(4, export, out);
        }
        for import in &self.imports {
            nested(5, import, out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            4 => self
                .exports
                .push(CacheOptionsEntry::decode(r.bytes(wire)?)?),
            5 => self
                .imports
                .push(CacheOptionsEntry::decode(r.bytes(wire)?)?),
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

/// `moby.buildkit.v1.Exporter`, from control.proto.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Exporter {
    pub kind: String,
    pub attrs: BTreeMap<String, String>,
}
impl Message for Exporter {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.kind, out);
        map_encode(2, &self.attrs, out);
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.kind = r.string(wire)?,
            2 => map_decode(r.bytes(wire)?, &mut self.attrs)?,
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

impl Message for SolveRequest {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.reference, out);
        string(5, &self.session, out);
        string(6, &self.frontend, out);
        map_encode(7, &self.frontend_attrs, out);
        if !self.cache.exports.is_empty() || !self.cache.imports.is_empty() {
            nested(8, &self.cache, out);
        }
        for exporter in &self.exporters {
            nested(13, exporter, out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.reference = r.string(wire)?,
            5 => self.session = r.string(wire)?,
            6 => self.frontend = r.string(wire)?,
            7 => map_decode(r.bytes(wire)?, &mut self.frontend_attrs)?,
            8 => self.cache = CacheOptions::decode(r.bytes(wire)?)?,
            13 => self.exporters.push(Exporter::decode(r.bytes(wire)?)?),
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SolveResponse {
    pub exporter_response: BTreeMap<String, String>,
}

/// BuildKit's `InfoResponse`, from control.proto and api/types/worker.proto.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InfoResponse {
    pub version: Option<BuildkitVersion>,
}
impl Message for InfoResponse {
    fn encode_to(&self, out: &mut Vec<u8>) {
        if let Some(version) = &self.version {
            nested(1, version, out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.version = Some(BuildkitVersion::decode(r.bytes(wire)?)?),
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

/// The version embedded in `InfoResponse`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BuildkitVersion {
    pub package: String,
    pub version: String,
    pub revision: String,
    pub dockerfile_version: String,
}
impl Message for BuildkitVersion {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.package, out);
        string(2, &self.version, out);
        string(3, &self.revision, out);
        string(4, &self.dockerfile_version, out);
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.package = r.string(wire)?,
            2 => self.version = r.string(wire)?,
            3 => self.revision = r.string(wire)?,
            4 => self.dockerfile_version = r.string(wire)?,
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}
impl Message for SolveResponse {
    fn encode_to(&self, out: &mut Vec<u8>) {
        map_encode(1, &self.exporter_response, out);
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => map_decode(r.bytes(wire)?, &mut self.exporter_response)?,
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}
impl Message for Timestamp {
    fn encode_to(&self, out: &mut Vec<u8>) {
        if self.seconds != 0 {
            number(1, self.seconds.cast_unsigned(), out);
        }
        if self.nanos != 0 {
            number(2, i64::from(self.nanos).cast_unsigned(), out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.seconds = r.number(wire)?.cast_signed(),
            2 => {
                let bytes = r.number(wire)?.to_le_bytes();
                self.nanos = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            }
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StatusRequest {
    pub reference: String,
}
impl Message for StatusRequest {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.reference, out);
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.reference = r.string(wire)?,
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Vertex {
    pub digest: String,
    pub inputs: Vec<String>,
    pub name: String,
    pub cached: bool,
    pub started: Option<Timestamp>,
    pub completed: Option<Timestamp>,
    pub error: String,
}
impl Message for Vertex {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.digest, out);
        for input in &self.inputs {
            bytes(2, input.as_bytes(), out);
        }
        string(3, &self.name, out);
        if self.cached {
            number(4, 1, out);
        }
        if let Some(v) = &self.started {
            nested(5, v, out);
        }
        if let Some(v) = &self.completed {
            nested(6, v, out);
        }
        string(7, &self.error, out);
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.digest = r.string(wire)?,
            2 => self.inputs.push(r.string(wire)?),
            3 => self.name = r.string(wire)?,
            4 => self.cached = r.number(wire)? != 0,
            5 => self.started = Some(Timestamp::decode(r.bytes(wire)?)?),
            6 => self.completed = Some(Timestamp::decode(r.bytes(wire)?)?),
            7 => self.error = r.string(wire)?,
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VertexStatus {
    pub id: String,
    pub vertex: String,
    pub name: String,
    pub current: i64,
    pub total: i64,
    pub timestamp: Option<Timestamp>,
    pub started: Option<Timestamp>,
    pub completed: Option<Timestamp>,
}
impl Message for VertexStatus {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.id, out);
        string(2, &self.vertex, out);
        string(3, &self.name, out);
        if self.current != 0 {
            number(4, self.current.cast_unsigned(), out);
        }
        if self.total != 0 {
            number(5, self.total.cast_unsigned(), out);
        }
        if let Some(v) = &self.timestamp {
            nested(6, v, out);
        }
        if let Some(v) = &self.started {
            nested(7, v, out);
        }
        if let Some(v) = &self.completed {
            nested(8, v, out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.id = r.string(wire)?,
            2 => self.vertex = r.string(wire)?,
            3 => self.name = r.string(wire)?,
            4 => self.current = r.number(wire)?.cast_signed(),
            5 => self.total = r.number(wire)?.cast_signed(),
            6 => self.timestamp = Some(Timestamp::decode(r.bytes(wire)?)?),
            7 => self.started = Some(Timestamp::decode(r.bytes(wire)?)?),
            8 => self.completed = Some(Timestamp::decode(r.bytes(wire)?)?),
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VertexLog {
    pub vertex: String,
    pub timestamp: Option<Timestamp>,
    pub stream: i64,
    pub msg: Vec<u8>,
}
impl Message for VertexLog {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.vertex, out);
        if let Some(v) = &self.timestamp {
            nested(2, v, out);
        }
        if self.stream != 0 {
            number(3, self.stream.cast_unsigned(), out);
        }
        if !self.msg.is_empty() {
            bytes(4, &self.msg, out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.vertex = r.string(wire)?,
            2 => self.timestamp = Some(Timestamp::decode(r.bytes(wire)?)?),
            3 => self.stream = r.number(wire)?.cast_signed(),
            4 => self.msg = r.bytes(wire)?.to_vec(),
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StatusResponse {
    pub vertexes: Vec<Vertex>,
    pub statuses: Vec<VertexStatus>,
    pub logs: Vec<VertexLog>,
}
impl Message for StatusResponse {
    fn encode_to(&self, out: &mut Vec<u8>) {
        for v in &self.vertexes {
            nested(1, v, out);
        }
        for v in &self.statuses {
            nested(2, v, out);
        }
        for v in &self.logs {
            nested(3, v, out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.vertexes.push(Vertex::decode(r.bytes(wire)?)?),
            2 => self.statuses.push(VertexStatus::decode(r.bytes(wire)?)?),
            3 => self.logs.push(VertexLog::decode(r.bytes(wire)?)?),
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GetSecretRequest {
    pub id: String,
    pub annotations: BTreeMap<String, String>,
}
impl Message for GetSecretRequest {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.id, out);
        map_encode(2, &self.annotations, out);
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.id = r.string(wire)?,
            2 => map_decode(r.bytes(wire)?, &mut self.annotations)?,
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

// secrets.proto defines no uid, gid, or mode response fields: the Dockerfile
// frontend supplies those as LLB secret mount options, not session data.

/// `moby.sshforward.v1.CheckAgentRequest`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CheckAgentRequest {
    pub id: String,
}

impl Message for CheckAgentRequest {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.id, out);
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.id = r.string(wire)?,
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

/// `moby.sshforward.v1.CheckAgentResponse` has no fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CheckAgentResponse;

impl Message for CheckAgentResponse {
    fn encode_to(&self, _out: &mut Vec<u8>) {}
    fn merge_field(&mut self, _field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        r.skip(wire)
    }
}

// GetSecretResponse, FileSend.BytesMessage and sshforward.BytesMessage
// have the same data field.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BytesMessage {
    pub data: Vec<u8>,
}

/// `fsutil.types.Stat`, sent inside a DiffCopy `PACKET_STAT`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileStat {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
    pub mod_time: i64,
    pub linkname: String,
    pub devmajor: i64,
    pub devminor: i64,
    pub xattrs: BTreeMap<String, Vec<u8>>,
}

impl Message for FileStat {
    fn encode_to(&self, out: &mut Vec<u8>) {
        string(1, &self.path, out);
        if self.mode != 0 {
            number(2, u64::from(self.mode), out);
        }
        if self.uid != 0 {
            number(3, u64::from(self.uid), out);
        }
        if self.gid != 0 {
            number(4, u64::from(self.gid), out);
        }
        if self.size != 0 {
            number(5, self.size.cast_unsigned(), out);
        }
        if self.mod_time != 0 {
            number(6, self.mod_time.cast_unsigned(), out);
        }
        string(7, &self.linkname, out);
        if self.devmajor != 0 {
            number(8, self.devmajor.cast_unsigned(), out);
        }
        if self.devminor != 0 {
            number(9, self.devminor.cast_unsigned(), out);
        }
        for (key, value) in &self.xattrs {
            let mut entry = Vec::new();
            string(1, key, &mut entry);
            if !value.is_empty() {
                bytes(2, value, &mut entry);
            }
            bytes(10, &entry, out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.path = r.string(wire)?,
            2 => self.mode = u32::try_from(r.number(wire)?).map_err(|_| ProtoError::Varint)?,
            3 => self.uid = u32::try_from(r.number(wire)?).map_err(|_| ProtoError::Varint)?,
            4 => self.gid = u32::try_from(r.number(wire)?).map_err(|_| ProtoError::Varint)?,
            5 => self.size = r.number(wire)?.cast_signed(),
            6 => self.mod_time = r.number(wire)?.cast_signed(),
            7 => self.linkname = r.string(wire)?,
            8 => self.devmajor = r.number(wire)?.cast_signed(),
            9 => self.devminor = r.number(wire)?.cast_signed(),
            10 => {
                let mut entry = Reader::new(r.bytes(wire)?)?;
                let (mut key, mut value) = (String::new(), Vec::new());
                while let Some((field, wire)) = entry.next()? {
                    match field {
                        1 => key = entry.string(wire)?,
                        2 => value = entry.bytes(wire)?.to_vec(),
                        _ => entry.skip(wire)?,
                    }
                }
                self.xattrs.insert(key, value);
            }
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

/// `fsutil.types.Packet`. A missing stat on a STAT packet marks the end of
/// the file list; it is not an empty file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FilePacket {
    pub kind: i32,
    pub stat: Option<FileStat>,
    pub id: u32,
    pub data: Vec<u8>,
}

impl Message for FilePacket {
    fn encode_to(&self, out: &mut Vec<u8>) {
        if self.kind != 0 {
            number(1, i64::from(self.kind).cast_unsigned(), out);
        }
        if let Some(stat) = &self.stat {
            nested(2, stat, out);
        }
        if self.id != 0 {
            number(3, u64::from(self.id), out);
        }
        if !self.data.is_empty() {
            bytes(4, &self.data, out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => {
                let bytes = r.number(wire)?.to_le_bytes();
                self.kind = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            }
            2 => self.stat = Some(FileStat::decode(r.bytes(wire)?)?),
            3 => self.id = u32::try_from(r.number(wire)?).map_err(|_| ProtoError::Varint)?,
            4 => self.data = r.bytes(wire)?.to_vec(),
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}
impl Message for BytesMessage {
    fn encode_to(&self, out: &mut Vec<u8>) {
        if !self.data.is_empty() {
            bytes(1, &self.data, out);
        }
    }
    fn merge_field(&mut self, field: u32, wire: u8, r: &mut Reader<'_>) -> Result<()> {
        match field {
            1 => self.data = r.bytes(wire)?.to_vec(),
            _ => r.skip(wire)?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_options_match_control_proto_field_numbers() {
        let request = SolveRequest {
            cache: CacheOptions {
                exports: vec![CacheOptionsEntry {
                    kind: "registry".into(),
                    attrs: [("ref".into(), "a".into())].into(),
                }],
                imports: vec![CacheOptionsEntry {
                    kind: "registry".into(),
                    attrs: [("ref".into(), "b".into())].into(),
                }],
            },
            ..Default::default()
        };
        let golden = [
            0x42, 0x2c, 0x22, 0x14, 0x0a, 0x08, b'r', b'e', b'g', b'i', b's', b't', b'r', b'y',
            0x12, 0x08, 0x0a, 0x03, b'r', b'e', b'f', 0x12, 0x01, b'a', 0x2a, 0x14, 0x0a, 0x08,
            b'r', b'e', b'g', b'i', b's', b't', b'r', b'y', 0x12, 0x08, 0x0a, 0x03, b'r', b'e',
            b'f', 0x12, 0x01, b'b',
        ];
        assert_eq!(request.encode(), golden);
        assert_eq!(SolveRequest::decode(&golden), Ok(request));
    }

    #[test]
    fn solve_request_golden_and_roundtrip() {
        let request = SolveRequest {
            reference: String::new(),
            exporters: Vec::new(),
            frontend: "dockerfile.v0".into(),
            frontend_attrs: [("a".into(), "1".into()), ("b".into(), "2".into())].into(),
            session: "s".into(),
            cache: CacheOptions::default(),
        };
        let golden = [
            0x2a, 1, b's', 0x32, 13, b'd', b'o', b'c', b'k', b'e', b'r', b'f', b'i', b'l', b'e',
            b'.', b'v', b'0', 0x3a, 6, 0x0a, 1, b'a', 0x12, 1, b'1', 0x3a, 6, 0x0a, 1, b'b', 0x12,
            1, b'2',
        ];
        assert_eq!(request.encode(), golden);
        assert_eq!(SolveRequest::decode(&golden), Ok(request));
        let framed = crate::grpc::encode_message(0, &golden, MAX_MESSAGE_BYTES).unwrap();
        let (_, payload, _) = crate::grpc::decode_message(&framed, MAX_MESSAGE_BYTES).unwrap();
        assert_eq!(
            SolveRequest::decode(payload).unwrap().frontend,
            "dockerfile.v0"
        );
    }

    #[test]
    fn skips_all_supported_unknown_wire_types() {
        let mut input = StatusRequest {
            reference: "x".into(),
        }
        .encode();
        number(22, 300, &mut input);
        fixed64(23, 0x0102_0304_0506_0708, &mut input);
        bytes(24, b"unknown", &mut input);
        tag(25, 5, &mut input);
        input.extend_from_slice(&42_u32.to_le_bytes());
        assert_eq!(StatusRequest::decode(&input).unwrap().reference, "x");
    }

    #[test]
    fn numeric_wire_primitives() {
        let mut encoded = Vec::new();
        varint(u64::MAX, &mut encoded);
        assert_eq!(Reader::new(&encoded).unwrap().varint(), Ok(u64::MAX));
        encoded.clear();
        fixed64(3, 0x0102_0304_0506_0708, &mut encoded);
        let mut reader = Reader::new(&encoded).unwrap();
        assert_eq!(reader.next(), Ok(Some((3, 1))));
        assert_eq!(reader.fixed64(1), Ok(0x0102_0304_0506_0708));
        assert_eq!(
            Reader::new(&[0; 7]).unwrap().fixed64(1),
            Err(ProtoError::Truncated)
        );
    }

    #[test]
    fn rejects_bad_varints_and_lengths() {
        assert_eq!(
            Reader::new(&[0x80]).unwrap().varint(),
            Err(ProtoError::Truncated)
        );
        assert_eq!(
            Reader::new(&[0x80, 0]).unwrap().varint(),
            Err(ProtoError::Varint)
        );
        assert_eq!(
            Reader::new(&[0xff; 10]).unwrap().varint(),
            Err(ProtoError::Varint)
        );
        assert_eq!(
            Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2])
                .unwrap()
                .varint(),
            Err(ProtoError::Varint)
        );
        assert_eq!(
            StatusRequest::decode(&[0x0a, 3, b'a']),
            Err(ProtoError::Truncated)
        );
        assert_eq!(StatusRequest::decode(&[0]), Err(ProtoError::InvalidTag));
        assert_eq!(
            StatusRequest::decode(&[0x0a, 0xff]),
            Err(ProtoError::Truncated)
        );
        assert_eq!(StatusRequest::decode(&[0x0b]), Err(ProtoError::WireType));
        assert!(matches!(
            Reader::new(&vec![0; MAX_MESSAGE_BYTES + 1]),
            Err(ProtoError::Oversized)
        ));
    }

    #[test]
    fn duplicate_map_keys_use_last_value() {
        let input = [
            0x0a, 6, 0x0a, 1, b'a', 0x12, 1, b'1', 0x0a, 6, 0x0a, 1, b'a', 0x12, 1, b'2',
        ];
        assert_eq!(
            SolveResponse::decode(&input).unwrap().exporter_response["a"],
            "2"
        );
    }

    #[test]
    fn vertex_log_golden_and_status_roundtrip() {
        let log = VertexLog {
            vertex: "v".into(),
            timestamp: Some(Timestamp {
                seconds: 1,
                nanos: 2,
            }),
            stream: 2,
            msg: b"hi".to_vec(),
        };
        let golden = [
            0x0a, 1, b'v', 0x12, 4, 8, 1, 16, 2, 0x18, 2, 0x22, 2, b'h', b'i',
        ];
        assert_eq!(log.encode(), golden);
        assert_eq!(VertexLog::decode(&golden).unwrap(), log);
        let status = StatusResponse {
            vertexes: vec![Vertex {
                digest: "sha256:x".into(),
                name: "build".into(),
                cached: true,
                ..Vertex::default()
            }],
            statuses: vec![VertexStatus {
                id: "id".into(),
                current: -1,
                ..VertexStatus::default()
            }],
            logs: vec![log],
        };
        assert_eq!(StatusResponse::decode(&status.encode()).unwrap(), status);
    }

    #[test]
    fn secrets_and_filesend_vectors() {
        let request = GetSecretRequest {
            id: "token".into(),
            ..GetSecretRequest::default()
        };
        assert_eq!(request.encode(), b"\x0a\x05token");
        assert_eq!(
            GetSecretRequest::decode(&request.encode()).unwrap(),
            request
        );
        let message = BytesMessage {
            data: b"hi".to_vec(),
        };
        assert_eq!(message.encode(), b"\x0a\x02hi");
        assert_eq!(BytesMessage::decode(&message.encode()).unwrap(), message);
    }

    #[test]
    fn sshforward_messages_match_pinned_proto() {
        let request = CheckAgentRequest {
            id: "default".into(),
        };
        assert_eq!(request.encode(), b"\x0a\x07default");
        assert_eq!(
            CheckAgentRequest::decode(&request.encode()).unwrap(),
            request
        );
        assert_eq!(CheckAgentResponse.encode(), b"");
        assert_eq!(CheckAgentResponse::decode(b"").unwrap(), CheckAgentResponse);
        assert_eq!(
            BytesMessage {
                data: b"hi".to_vec()
            }
            .encode(),
            b"\x0a\x02hi"
        );
    }

    #[test]
    fn filesync_packets_match_published_wire_format() {
        let stat = FileStat {
            path: "a".into(),
            mode: 0o644,
            size: 3,
            ..FileStat::default()
        };
        let packet = FilePacket {
            stat: Some(stat),
            ..FilePacket::default()
        };
        assert_eq!(
            packet.encode(),
            [0x12, 8, 0x0a, 1, b'a', 0x10, 0xa4, 0x03, 0x28, 3]
        );
        assert_eq!(FilePacket::decode(&packet.encode()).unwrap(), packet);
        let request = FilePacket {
            kind: 1,
            id: 7,
            ..FilePacket::default()
        };
        assert_eq!(request.encode(), [8, 1, 24, 7]);
        assert_eq!(FilePacket::decode(&request.encode()).unwrap(), request);
        let data = FilePacket {
            kind: 2,
            id: 7,
            data: b"abc".to_vec(),
            ..FilePacket::default()
        };
        assert_eq!(data.encode(), [8, 2, 24, 7, 34, 3, b'a', b'b', b'c']);
        assert_eq!(FilePacket::decode(&data.encode()).unwrap(), data);
        assert_eq!(FilePacket::decode(&[]).unwrap().stat, None);
    }

    #[test]
    fn exporter_field_matches_control_proto() {
        let exporter = Exporter {
            kind: "moby".into(),
            attrs: BTreeMap::new(),
        };
        let request = SolveRequest {
            exporters: vec![exporter],
            ..SolveRequest::default()
        };
        assert_eq!(request.encode(), [0x6a, 6, 0x0a, 4, b'm', b'o', b'b', b'y']);
        assert_eq!(SolveRequest::decode(&request.encode()).unwrap(), request);
    }
}
