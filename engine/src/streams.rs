//! Repository-owned streaming operations.
//!
//! A handle owns the response stream, yields one decoded
//! item at a time, and releases the underlying HTTP body when it is cancelled
//! or dropped.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;
use futures_util::StreamExt;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::{
    CredentialError, DockerClient, DockerCredentialHelper, Error, EventOptions, ImageSaveOptions,
    RegistryCredentialProvider, RegistryCredentials, normalize_registry, registry_for_image,
};
use crate::raw;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Error>> + Send>>;

fn receiver_stream<T>(receiver: mpsc::Receiver<T>) -> impl Stream<Item = T> + Send + 'static
where
    T: Send + 'static,
{
    futures_util::stream::unfold(Some(receiver), |state| async move {
        let mut receiver = state?;
        receiver.recv().await.map(|item| (item, Some(receiver)))
    })
}

/// A caller-owned, cancellation-safe Docker response stream.
///
/// `DockerStream` does not buffer items.  Each call to [`DockerStream::next`]
/// polls at most one item from the underlying response.  Dropping the handle,
/// or calling [`DockerStream::cancel`], drops the response body and therefore
/// closes the request/socket when the transport supports it.  The client may be
/// dropped independently after a stream is created.
#[must_use = "a DockerStream owns a response and should be consumed or cancelled"]
pub struct DockerStream<T> {
    inner: Option<BoxStream<T>>,
    cancellation: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl<T> DockerStream<T> {
    pub(crate) fn new(inner: impl Stream<Item = Result<T, Error>> + Send + 'static) -> Self {
        Self {
            inner: Some(Box::pin(inner)),
            cancellation: None,
            task: None,
        }
    }

    /// Creates a response handle whose producer runs in an owned Tokio task.
    ///
    /// The task owns the underlying Docker client and request body. Dropping or
    /// cancelling the returned handle signals the task and aborts it, so the
    /// caller does not need to keep the originating client alive.
    pub(crate) fn spawn<F, Fut>(operation: F) -> Self
    where
        F: FnOnce(oneshot::Receiver<()>, mpsc::Sender<Result<T, Error>>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
        T: Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(32);
        let (cancellation, cancel_receiver) = oneshot::channel();
        let task = tokio::spawn(operation(cancel_receiver, sender));
        Self {
            inner: Some(Box::pin(receiver_stream(receiver))),
            cancellation: Some(cancellation),
            task: Some(task),
        }
    }

    /// Reads the next decoded stream item.
    ///
    /// `None` means that the response reached end-of-stream or that the handle
    /// was cancelled.  Transport and decoding failures are returned as
    /// `Some(Err(_))`; callers may continue polling after an item error, but
    /// should stop once cancellation is more appropriate.
    pub async fn next(&mut self) -> Option<Result<T, Error>> {
        let item = self.inner.as_mut()?.next().await;
        if item.is_none() {
            self.finish();
        }
        item
    }

    /// Cancels the response stream and releases its transport resources.
    ///
    /// This operation is synchronous because dropping the response body is
    /// synchronous. It is intentionally idempotent.
    pub fn cancel(&mut self) {
        self.inner.take();
        if let Some(cancellation) = self.cancellation.take() {
            let _ = cancellation.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }

    fn finish(&mut self) {
        self.inner.take();
        self.cancellation.take();
        self.task.take();
    }

    /// Alias for [`DockerStream::cancel`] that reads naturally at call sites
    /// handling a response they no longer need.
    pub fn close(&mut self) {
        self.cancel();
    }

    /// Returns whether this handle has been cancelled or reached EOF.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_none()
    }

    /// Returns whether this handle has been cancelled or reached EOF.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.is_closed()
    }
}

impl<T> Unpin for DockerStream<T> {}

impl<T> std::fmt::Debug for DockerStream<T> {
    /// Reports whether the handle is still open, and no item.
    ///
    /// The items are whatever the daemon said: a container's output, an image
    /// pull's progress, a build's log lines, a credential helper's document.
    /// Several of those types redact their own payloads in `Debug`, and this
    /// handle must not become a way around that, so it prints none of them.
    ///
    /// There is deliberately **no `T: Debug` bound**, and that is the reason
    /// this is hand-written rather than derived twice over. A derive on this
    /// struct is impossible anyway — the field is a `Pin<Box<dyn Stream>>` — but
    /// a derive on a *wrapper* around it, such as
    /// [`ContainerArchive`](crate::ContainerArchive), would silently add a `T:
    /// Debug` requirement to every caller's type. A handle has to be printable
    /// whether or not the thing it carries is.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DockerStream")
            .field("open", &self.inner.is_some())
            .field("owned_task", &self.task.is_some())
            .finish_non_exhaustive()
    }
}

impl<T> Drop for DockerStream<T> {
    fn drop(&mut self) {
        // Make the ownership/cancellation contract explicit. `take` drops the
        // boxed response body and aborts an owned producer task before the
        // handle itself is deallocated.
        self.cancel();
    }
}

impl<T> Stream for DockerStream<T> {
    type Item = Result<T, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(None);
        };

        match inner.as_mut().poll_next(cx) {
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

pub(crate) fn map_owned_stream<S, B, T, F>(source: S, mut map: F) -> DockerStream<T>
where
    S: Stream<Item = Result<B, Error>> + Send + 'static,
    B: 'static,
    F: FnMut(B) -> Result<T, Error> + Send + 'static,
{
    DockerStream::new(source.map(move |item| match item {
        Ok(value) => map(value),
        Err(error) => Err(error),
    }))
}

/// An open owned response, adapted to the item type its caller asked for.
///
/// The owned transport's readers are `async fn`s on borrowed handles —
/// [`raw::FrameStream::next_json`] and [`raw::FrameStream::next_data`] — rather
/// than `Stream` implementations, because each owns a decoder that outlives any
/// single poll. This is therefore the one place that turns them into the
/// `Stream<Item = Result<T, Error>>` a [`DockerStream`] holds, and its three
/// variants are the three answer shapes the Engine writes: newline-delimited
/// JSON records, raw byte chunks, and one bounded document.
/// Decodes one record from its original bytes.
///
/// A named alias rather than an inline `Box<dyn FnMut ...>`: the two record
/// variants take different inputs, and the longer one reads as a type error at
/// the definition site otherwise.
type RecordDecoder<T> = Box<dyn FnMut(&[u8]) -> Result<T, Error> + Send>;

/// Replaces a Docker-kind in-band error on a route that withholds peer text.
///
/// Serialization and transport errors are left alone: they describe the record
/// shape or the connection, not text the proxy chose. Direct and unauthenticated
/// proxy streams keep their daemon message.
fn withhold_in_band_error(error: Error, frames: &raw::FrameStream) -> Error {
    if frames.withholds_error_message() && error.kind() == crate::ErrorKind::Docker {
        frames.withheld_error()
    } else {
        error
    }
}

pub(crate) enum OwnedResponse<T> {
    /// One JSON value per line, as `stats`, `events`, `pull` and `push` write.
    Records {
        /// The open response, read a record at a time.
        frames: raw::FrameStream,
        /// Projects one record onto the facade's own item type.
        ///
        /// Fallible because a record the daemon sent may not have the shape the
        /// item type describes. A projection failure is the item for that
        /// record; the frame stream is left where it is, so the next poll reads
        /// the next record rather than ending the subscription.
        map: Box<dyn FnMut(serde_json::Value) -> Result<T, Error> + Send>,
    },
    /// One JSON record per line, decoded from the record's original bytes.
    ///
    /// [`Self::Records`] parses each record into a [`serde_json::Value`] first,
    /// which keeps only the last of two duplicate object members. A caller that
    /// must reject a duplicate known member gets the bytes here and decodes
    /// them itself.
    RawRecords {
        /// The open response, read a record at a time.
        frames: raw::FrameStream,
        /// Decodes one record from its bytes onto the facade's own item type.
        map: RecordDecoder<T>,
    },
    /// Raw byte chunks, as an image archive is written.
    Chunks {
        /// The open response, read a chunk at a time.
        frames: raw::FrameStream,
        /// Turns one transport chunk into one caller-owned item.
        into_item: fn(bytes::Bytes) -> T,
    },
    /// One document that has already been read: one item, then end of stream.
    Once(Option<T>),
    /// Multiplexed log frames from an owned reader.
    ///
    /// The reader is [`raw::SwarmLogFrames`](crate::raw::SwarmLogFrames), the
    /// same decoder the owned task and service log streams use. Keeping it here
    /// rather than rebuilding one from a [`raw::FrameStream`] means the
    /// eight-byte header rules, [`MAX_FRAME_BYTES`](crate::raw::MAX_FRAME_BYTES),
    /// and the truncated-body refusal are the ones the `raw` module documents,
    /// not a second implementation in this file.
    LogFrames {
        /// The open response, decoded a frame at a time.
        frames: raw::SwarmLogFrames,
        /// Projects one decoded frame onto the facade's own item type.
        map: fn(raw::LogFrame) -> T,
    },
    /// The request failed. The failure has been reported; nothing is left.
    Reported,
}

impl<T> OwnedResponse<T> {
    /// Reads the next item, or `None` at end of stream.
    async fn next(&mut self) -> Result<Option<T>, Error> {
        match self {
            Self::Records { frames, map } => {
                let Some(record) = frames
                    .next_json()
                    .await
                    .map_err(|error| withhold_in_band_error(error, frames))?
                else {
                    return Ok(None);
                };
                map(record)
                    .map_err(|error| withhold_in_band_error(error, frames))
                    .map(Some)
            }
            Self::RawRecords { frames, map } => frames
                .next_record(|bytes| map(bytes))
                .await
                .map_err(|error| withhold_in_band_error(error, frames)),
            Self::Chunks { frames, into_item } => Ok(frames
                .next_data()
                .await
                .map_err(Error::from)?
                .map(into_item)),
            Self::LogFrames { frames, map } => Ok(frames.next_frame().await?.map(map)),
            Self::Once(item) => Ok(item.take()),
            Self::Reported => Ok(None),
        }
    }
}

/// Whether an owned request has been sent yet.
///
/// `Open` is boxed, and the reason is not the allocation — it is the *move*. The
/// state of an `unfold` is passed by value into its closure and returned by value
/// out of it, so every poll of every stream memmoves this whole enum once in and
/// once out. With the response inline that is the size of a `FrameStream` — the
/// hyper body, its headers, its extensions, the connection driver, and the record
/// buffer — moved twice per poll, for a struct that is read in place and never
/// moved anywhere else. One allocation per stream, once, in exchange for a
/// pointer.
///
/// Boxing the response rather than the `FrameStream` is deliberate. The frame
/// stream is public and is carried by value through `logs`, `stats_stream`,
/// `events` and the image-transfer operations, so indirection there would ripple
/// through the published API to save nothing; this enum is crate-internal and its
/// other variant is already a boxed future, so the two are now the same shape.
///
/// The result is 16 bytes on 64-bit: the data and vtable pointers of
/// [`Self::Request`]'s `Box<dyn Future>`, with the variant tag living in a spare
/// bit pattern of the non-null pointer rather than in a word of its own. `Open`
/// being a thin pointer does not make the enum 8 bytes, because the fat one is
/// the wider of the two — the bound is the largest variant, and this comment
/// records which variant that is so the next reader does not have to measure it.
enum PendingResponse<T> {
    /// The request exists and has not been polled, so no connection is open.
    Request(Pin<Box<dyn Future<Output = Result<OwnedResponse<T>, Error>> + Send + 'static>>),
    /// The response is open.
    Open(Box<OwnedResponse<T>>),
}

/// Turns an owned operation into a caller-owned handle.
///
/// The owned operations are `async` and every facade method here that uses one
/// is not, so the request cannot be sent before the method returns. It is
/// therefore *held as an unpolled future* rather than awaited, and `unfold` does
/// not enter its closure until the handle is first polled. That is what keeps a
/// rewired handle as lazy as the generated client's stream: a caller that
/// creates a handle and never polls it opens no connection and writes no
/// request, exactly as before.
///
/// Cancellation is unchanged for the same reason it works for the generated
/// client — it is ownership, not a protocol. [`DockerStream::cancel`] and
/// `Drop` both release the handle's state, which is either the unpolled future
/// (nothing to close) or the open [`raw::FrameStream`], and dropping the
/// response aborts the connection driver with it.
pub(crate) fn owned_response<T>(
    request: impl Future<Output = Result<OwnedResponse<T>, Error>> + Send + 'static,
) -> DockerStream<T>
where
    T: Send + 'static,
{
    DockerStream::new(futures_util::stream::unfold(
        PendingResponse::<T>::Request(Box::pin(request)),
        |state| async move {
            let (item, state) = match state {
                PendingResponse::Request(mut request) => match request.as_mut().await {
                    Ok(mut response) => {
                        let item = response.next().await.transpose();
                        (item, PendingResponse::Open(Box::new(response)))
                    }
                    // The failure is one stream item and then the end, which is
                    // the contract a `DockerStream` already states: request
                    // errors arrive as items, not as a return value.
                    Err(error) => (
                        Some(Err(error)),
                        PendingResponse::Open(Box::new(OwnedResponse::Reported)),
                    ),
                },
                PendingResponse::Open(mut response) => {
                    let item = response.next().await.transpose();
                    (item, PendingResponse::Open(response))
                }
            };
            item.map(|item| (item, state))
        },
    ))
}

/// Identifies the source of a Docker log frame.
///
/// `Console` represents a TTY/raw response.  Docker does not prefix raw TTY
/// output with an eight-byte multiplexed header; callers should therefore not
/// treat `Console` as stdout even though the bytes are commonly written to a
/// terminal as stdout.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ContainerLogStream {
    /// Standard input frame (normally only relevant to attach/exec output).
    Stdin,
    /// Standard output frame.
    Stdout,
    /// Standard error frame.
    Stderr,
    /// Raw/TTY output without Docker multiplexed framing.
    Console,
}

impl ContainerLogStream {
    /// Returns whether this frame came from Docker's multiplexed stream.
    #[must_use]
    pub const fn is_multiplexed(self) -> bool {
        !matches!(self, Self::Console)
    }
}

/// One decoded Docker log frame.
///
/// The frame payload is exactly one the former generated client decoder item; frames are not
/// concatenated and the eight-byte Docker header is not exposed to callers.
///
/// `Debug` is hand-written rather than derived, because `payload` is the
/// container's own stdout and a derive renders it as a decimal byte list — the
/// one form a search for the payload as text would miss. This is the
/// the former generated client-backed spelling of
/// [`raw::LogFrame`](crate::raw::LogFrame), and it is redacted for the same
/// reason and kept in step with it: a derived impl here would mean the same
/// bytes were printed on the former generated client path and redacted on the owned one,
/// depending only on which transport a caller configured.
///
/// The payload stays a public field returned by value. Redaction is a property
/// of the formatting, not of what a caller can read.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ContainerLogFrame {
    /// Source stream for this frame.
    pub stream: ContainerLogStream,
    /// Unmodified payload bytes for this frame.
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for ContainerLogFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContainerLogFrame")
            .field("stream", &self.stream)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl ContainerLogFrame {
    /// Creates a typed frame from a source and payload.
    #[must_use]
    pub fn new(stream: ContainerLogStream, payload: Vec<u8>) -> Self {
        Self { stream, payload }
    }

    /// Returns whether this is a multiplexed rather than raw TTY frame.
    #[must_use]
    pub const fn is_multiplexed(&self) -> bool {
        self.stream.is_multiplexed()
    }
}

/// Short alias for [`ContainerLogFrame`].
pub type LogFrame = ContainerLogFrame;
/// Short alias for [`ContainerLogStream`].
pub type LogStream = ContainerLogStream;

/// Options for the container logs endpoint.
///
/// The default values match the former generated client's generated v1.53 request defaults.  Pass
/// `None` to let Docker apply its endpoint defaults instead.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContainerLogsOptions {
    /// Keep the HTTP response open after the current logs are returned.
    pub follow: bool,
    /// Include standard output.
    pub stdout: bool,
    /// Include standard error.
    pub stderr: bool,
    /// Unix timestamp lower bound, or zero when unset.
    pub since: i32,
    /// Unix timestamp upper bound, or zero when unset.
    pub until: i32,
    /// Prefix each log line with a timestamp.
    pub timestamps: bool,
    /// Number of lines to return, or `all`.
    pub tail: String,
}

impl Default for ContainerLogsOptions {
    fn default() -> Self {
        Self {
            follow: false,
            stdout: false,
            stderr: false,
            since: 0,
            until: 0,
            timestamps: false,
            tail: "all".to_owned(),
        }
    }
}

/// Short alias for [`ContainerLogsOptions`].
pub type LogsOptions = ContainerLogsOptions;

/// Options for the container stats endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerStatsOptions {
    /// Whether Docker continuously emits samples.
    pub stream: bool,
    /// Whether Docker emits a single sample.
    pub one_shot: bool,
}

impl Default for ContainerStatsOptions {
    fn default() -> Self {
        Self {
            stream: true,
            one_shot: false,
        }
    }
}

/// Short alias for [`ContainerStatsOptions`].
pub type StatsOptions = ContainerStatsOptions;

/// A typed, forward-compatible container statistics sample.
///
/// The nested Docker statistics objects remain JSON values rather than
/// the former generated client-generated models.  This keeps the public contract repository-owned
/// while retaining fields added by newer daemons.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ContainerStatsResponse {
    /// Container identifier.
    pub id: Option<String>,
    /// Container name.
    pub name: Option<String>,
    /// Operating system reported for the container.
    pub os_type: Option<String>,
    /// RFC 3339 sample timestamp.
    pub read: Option<String>,
    /// Raw Docker CPU statistics object.
    pub cpu_stats: Option<serde_json::Value>,
    /// Raw Docker memory statistics object.
    pub memory_stats: Option<serde_json::Value>,
    /// Per-interface network statistics.
    pub networks: Option<BTreeMap<String, serde_json::Value>>,
    /// Process ID statistics.
    pub pids_stats: Option<serde_json::Value>,
    /// Block I/O statistics.
    pub blkio_stats: Option<serde_json::Value>,
    /// Number of processors reported by the daemon.
    pub num_procs: Option<u32>,
    /// Storage statistics (primarily used by Windows daemons).
    pub storage_stats: Option<serde_json::Value>,
    /// RFC 3339 timestamp for the first sample.
    pub preread: Option<String>,
    /// Previous CPU statistics object.
    pub precpu_stats: Option<serde_json::Value>,
}

/// Short alias for [`ContainerStatsResponse`].
pub type ContainerStats = ContainerStatsResponse;

/// Options for the daemon event stream.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DockerEventsOptions {
    /// Return events after this Docker timestamp and then follow.
    pub since: Option<String>,
    /// Return events until this Docker timestamp and then stop.
    pub until: Option<String>,
    /// Docker event filters, such as `type=container`.
    pub filters: Option<BTreeMap<String, Vec<String>>>,
}

/// Short alias for [`DockerEventsOptions`].
pub type EventsOptions = DockerEventsOptions;

/// The actor/resource associated with a daemon event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DockerEventActor {
    /// Resource identifier.
    pub id: Option<String>,
    /// Resource attributes supplied by the daemon.
    pub attributes: BTreeMap<String, String>,
}

/// One typed daemon event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DockerEventResponse {
    /// Resource type, such as `container` or `image`.
    pub event_type: Option<String>,
    /// Event action, such as `start` or `die`.
    pub action: Option<String>,
    /// Resource that emitted the event.
    pub actor: Option<DockerEventActor>,
    /// Event scope, normally `local` or `swarm`.
    pub scope: Option<String>,
    /// Event time in Unix seconds.
    pub time: Option<i64>,
    /// Event time in Unix nanoseconds.
    pub time_nano: Option<i64>,
}

/// Short alias for [`DockerEventResponse`].
pub type DockerEvent = DockerEventResponse;

/// Options for a streaming image pull.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImagePullOptions {
    /// Optional tag or digest to pull.
    pub tag: Option<String>,
    /// Optional platform selector, such as `linux/amd64`.
    pub platform: Option<String>,
}

/// Options for a streaming image push.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImagePushOptions {
    /// Optional destination tag or digest.
    pub tag: Option<String>,
    /// Optional OCI platform selector, such as `linux/amd64`.
    pub platform: Option<String>,
}

/// A progress update emitted by a pull, push, or other image operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ImageProgress {
    /// Current progress count.
    pub current: Option<i64>,
    /// Total progress count.
    pub total: Option<i64>,
}

/// One typed image-operation stream event.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ImageStreamEvent {
    /// Image or layer identifier, when supplied by Docker.
    pub id: Option<String>,
    /// Human-readable status.
    pub status: Option<String>,
    /// Raw text output emitted by a build-style operation.
    pub stream: Option<String>,
    /// Structured progress, when supplied by Docker.
    pub progress: Option<ImageProgress>,
    /// Error text if the daemon includes one in an otherwise successful HTTP
    /// response.
    pub error: Option<String>,
}

/// Short alias for [`ImageStreamEvent`].
pub type ImageProgressEvent = ImageStreamEvent;

/// Projects one frame decoded by the owned reader onto the facade's frame.
///
/// The two enums are separate types so the `raw` module does not depend on a
/// public facade spelling, but their variants are the same four sources. The
/// payload is moved rather than re-read, and no bytes are dropped: a service
/// log is the same multiplexed body a container log is.
pub(crate) fn map_owned_log_frame(frame: raw::LogFrame) -> ContainerLogFrame {
    let stream = match frame.stream {
        raw::LogStream::Stdin => ContainerLogStream::Stdin,
        raw::LogStream::Stdout => ContainerLogStream::Stdout,
        raw::LogStream::Stderr => ContainerLogStream::Stderr,
        raw::LogStream::Console => ContainerLogStream::Console,
    };
    ContainerLogFrame::new(stream, frame.payload)
}

pub(crate) fn json_string(object: &serde_json::Value, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Projects one statistics document onto the facade's own sample.
///
/// The input is the document the daemon sent rather than a generated model, so
/// unknown members are ignored by this facade.
fn map_stats(stats: &serde_json::Value) -> ContainerStatsResponse {
    let networks = stats
        .get("networks")
        .and_then(serde_json::Value::as_object)
        .map(|networks| {
            networks
                .iter()
                .map(|(name, stats)| (name.clone(), stats.clone()))
                .collect()
        });

    ContainerStatsResponse {
        id: json_string(stats, "id"),
        name: json_string(stats, "name"),
        os_type: json_string(stats, "os_type"),
        read: json_string(stats, "read"),
        cpu_stats: stats.get("cpu_stats").cloned(),
        memory_stats: stats.get("memory_stats").cloned(),
        networks,
        pids_stats: stats.get("pids_stats").cloned(),
        blkio_stats: stats.get("blkio_stats").cloned(),
        num_procs: stats
            .get("num_procs")
            .and_then(serde_json::Value::as_u64)
            .and_then(|number| u32::try_from(number).ok()),
        storage_stats: stats.get("storage_stats").cloned(),
        preread: json_string(stats, "preread"),
        precpu_stats: stats.get("precpu_stats").cloned(),
    }
}

/// Projects one event record onto the facade's own event, without refusing a
/// known member of the wrong JSON type.
///
/// The daemon's spelling is the generated model's, and the capitals are the
/// daemon's rather than a style choice: `Type`, `Action`, and an `Actor`
/// carrying `ID` and `Attributes` are what `registrytypes` writes, so those are
/// the names read here. A `null` member is absent, which is what the generated
/// model does with it too.
///
/// Two members the generated model would have refused to decode are read
/// instead: an event `Type` added after the model was generated, and an
/// `Attributes` value that is not a string. The generated path fails the whole
/// record on either; this one reports the event with that member absent, which
/// is the same answer a daemon that did not send it would get. This is the
/// deliberate widening [`DockerClient::events`] has always had; a caller that
/// needs the generated model's refusal of a wrong JSON *type* uses
/// [`map_event_record_strict`], which is what [`DockerClient::system_events`]
/// uses because that entry point replaced a typed decode.
pub(crate) fn map_event_record_lenient(record: &serde_json::Value) -> DockerEventResponse {
    let actor = record
        .get("Actor")
        .filter(|actor| !actor.is_null())
        .map(|actor| DockerEventActor {
            id: json_string(actor, "ID"),
            attributes: actor
                .get("Attributes")
                .and_then(serde_json::Value::as_object)
                .map_or_default(|attributes| {
                    attributes
                        .iter()
                        .filter_map(|(name, value)| {
                            value.as_str().map(|value| (name.clone(), value.to_owned()))
                        })
                        .collect()
                }),
        });

    DockerEventResponse {
        event_type: json_string(record, "Type"),
        action: json_string(record, "Action"),
        actor,
        scope: json_string(record, "scope"),
        time: record.get("time").and_then(serde_json::Value::as_i64),
        time_nano: record.get("timeNano").and_then(serde_json::Value::as_i64),
    }
}

/// Projects one event record, refusing a known member whose JSON type is wrong.
///
/// This is the projection [`DockerClient::system_events`] uses, because that
/// entry point replaced a decode into the generated `EventMessage` model and
/// keeps its refusal of a malformed record: a member the model declares as a
/// string or an integer is not silently read as absent when the daemon sent a
/// different JSON type. Absent and `null` members are still absent, which is
/// what the generated model's `Option` fields do.
///
/// An unknown *value* of `Type` or `scope` is accepted. [`DockerEventResponse`]
/// and [`SystemEvent`](crate::SystemEvent) expose those as strings so a daemon
/// value added after this crate was built passes through; rejecting them would
/// put a closed enum back in a model that deliberately has none. Only the JSON
/// type is checked, which is the part a decode genuinely knows is wrong.
///
/// # Errors
///
/// Returns a serialization error naming the first known member with the wrong
/// JSON type. The record's value is not included, so an error cannot echo an
/// attribute the daemon attached to an event.
pub(crate) fn map_event_record_strict(
    record: &serde_json::Value,
) -> Result<DockerEventResponse, Error> {
    validate_event_record(record)?;
    Ok(map_event_record_lenient(record))
}

/// Checks the JSON type of every event member the projection reads.
fn validate_event_record(record: &serde_json::Value) -> Result<(), Error> {
    let Some(record) = record.as_object() else {
        return Err(event_decode_error(
            "the daemon's event record must be a JSON object",
        ));
    };
    for member in ["Type", "Action", "scope"] {
        validate_event_string(record, member, member)?;
    }
    for member in ["time", "timeNano"] {
        validate_event_integer(record, member)?;
    }
    let Some(actor) = record.get("Actor") else {
        return Ok(());
    };
    if actor.is_null() {
        return Ok(());
    }
    let Some(actor) = actor.as_object() else {
        return Err(malformed_event_member("Actor", "a JSON object or null"));
    };
    validate_event_string(actor, "ID", "Actor.ID")?;
    let Some(attributes) = actor.get("Attributes") else {
        return Ok(());
    };
    if attributes.is_null() {
        return Ok(());
    }
    let Some(attributes) = attributes.as_object() else {
        return Err(malformed_event_member(
            "Actor.Attributes",
            "a JSON object of string values or null",
        ));
    };
    if attributes.values().any(|value| !value.is_string()) {
        return Err(event_decode_error(
            "the daemon's event record member `Actor.Attributes` must be an object \
             whose values are strings",
        ));
    }
    Ok(())
}

/// Accepts an absent or `null` string member, and refuses any other non-string.
///
/// `member` is the key read from `record`; `path` is the name the error reports,
/// so an actor's `ID` is named as `Actor.ID` rather than as a top-level `ID`.
fn validate_event_string(
    record: &serde_json::Map<String, serde_json::Value>,
    member: &str,
    path: &str,
) -> Result<(), Error> {
    match record.get(member) {
        None | Some(serde_json::Value::Null | serde_json::Value::String(_)) => Ok(()),
        Some(_) => Err(malformed_event_member(path, "a string or null")),
    }
}

/// Accepts an absent or `null` integer member, and refuses any other non-integer.
fn validate_event_integer(
    record: &serde_json::Map<String, serde_json::Value>,
    member: &str,
) -> Result<(), Error> {
    match record.get(member) {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(value) if value.as_i64().is_some() => Ok(()),
        Some(_) => Err(malformed_event_member(member, "an integer or null")),
    }
}

/// Names the member and the type it needed, never the value the daemon sent.
fn malformed_event_member(member: &str, expected: &str) -> Error {
    event_decode_error(format!(
        "the daemon's event record member `{member}` must be {expected}"
    ))
}

fn event_decode_error(message: impl std::fmt::Display) -> Error {
    Error::serialization(<serde_json::Error as serde::de::Error>::custom(message))
}

pub(crate) fn map_image_event(value: &serde_json::Value) -> ImageStreamEvent {
    let progress = value.get("progressDetail").map(|progress| ImageProgress {
        current: progress.get("current").and_then(serde_json::Value::as_i64),
        total: progress.get("total").and_then(serde_json::Value::as_i64),
    });
    let error = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .get("errorDetail")
                .and_then(|detail| detail.get("message"))
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_owned);

    ImageStreamEvent {
        id: json_string(value, "id"),
        status: json_string(value, "status"),
        stream: json_string(value, "stream"),
        progress,
        error,
    }
}

impl DockerClient {
    /// Opens a typed container log stream using the owned inspect and logs
    /// endpoints. Inspect resolves the TTY mode before opening the logs body;
    /// that mode selects raw console bytes or stdcopy multiplexed decoding.
    /// The generated fallback is intentionally removed because its path can
    /// log response bodies containing streamed container output.
    pub fn logs(
        &self,
        container: &str,
        options: Option<ContainerLogsOptions>,
    ) -> DockerStream<ContainerLogFrame> {
        let options = options.unwrap_or_default();
        let container = container.to_owned();
        let engine = self
            .container_stream_engine()
            .map_err(|error| super::containers::sanitize_stream_error(&error));
        DockerStream::spawn(move |mut cancellation, sender| async move {
            let engine = match engine {
                Ok(engine) => engine,
                Err(error) => {
                    let _ = sender
                        .send(Err(super::containers::sanitize_stream_error(&error)))
                        .await;
                    return;
                }
            };
            let tty = match raw::inspect(&engine, &container).await {
                Ok(inspect) => {
                    if let Some(tty) = inspect.tty() {
                        tty
                    } else {
                        let _ = sender
                            .send(Err(Error::transport(
                                "container inspect omitted its TTY setting",
                            )))
                            .await;
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender
                        .send(Err(super::containers::sanitize_stream_error(&error)))
                        .await;
                    return;
                }
            };
            let mut frames = match raw::logs(
                &engine,
                &container,
                &raw::ContainerLogOptions {
                    follow: options.follow,
                    stdout: options.stdout,
                    stderr: options.stderr,
                    since: i64::from(options.since),
                    until: i64::from(options.until),
                    timestamps: options.timestamps,
                    tail: options.tail,
                    tty,
                },
            )
            .await
            {
                Ok(frames) => frames,
                Err(error) => {
                    let _ = sender
                        .send(Err(super::containers::sanitize_stream_error(&error)))
                        .await;
                    return;
                }
            };
            loop {
                let next = tokio::select! {
                    _ = &mut cancellation => return,
                    frame = frames.next_frame() => frame,
                };
                match next {
                    Ok(Some(frame)) => {
                        let stream = match frame.stream {
                            raw::LogStream::Stdin => ContainerLogStream::Stdin,
                            raw::LogStream::Stdout => ContainerLogStream::Stdout,
                            raw::LogStream::Stderr => ContainerLogStream::Stderr,
                            raw::LogStream::Console => ContainerLogStream::Console,
                        };
                        if sender
                            .send(Ok(ContainerLogFrame::new(stream, frame.payload)))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = sender
                            .send(Err(super::containers::sanitize_stream_error(&error)))
                            .await;
                        return;
                    }
                }
            }
        })
    }

    /// Opens a typed container statistics stream.
    ///
    /// Rewired onto [`raw::stats`] and [`raw::stats_stream`]. The one flag that
    /// decides the shape of the answer is the same flag on both sides, so the
    /// choice is the caller's and is made here rather than guessed at from the
    /// response: a following stats answer is a record stream, and a one-shot
    /// answer is one bounded document that yields exactly one item and then
    /// ends — which is what the generated client's stream did with it too.
    ///
    /// `one_shot` is still accepted and is no longer put on the wire. The daemon
    /// ignores it in favour of `stream`, so sending both made a recorded request
    /// say two things where one decides the answer.
    pub fn stats(
        &self,
        container: &str,
        options: Option<ContainerStatsOptions>,
    ) -> DockerStream<ContainerStatsResponse> {
        let options = options.unwrap_or_default();
        let engine = self.raw_engine();
        let container = container.to_owned();
        owned_response(async move {
            let engine = engine?;
            if options.stream {
                let frames =
                    raw::stats_stream(&engine, &container, raw::StatsOptions { stream: true })
                        .await?;
                Ok(OwnedResponse::Records {
                    frames,
                    map: Box::new(|record| Ok(map_stats(&record))),
                })
            } else {
                let document =
                    raw::stats(&engine, &container, raw::StatsOptions { stream: false }).await?;
                Ok(OwnedResponse::Once(Some(map_stats(&document))))
            }
        })
    }

    /// Opens a typed daemon event stream.
    ///
    /// Rewired onto [`raw::events`]. The daemon writes this endpoint as
    /// newline-delimited JSON over an ordinary chunked response, which is the
    /// shape [`raw::FrameStream::next_json`] is the reader for — so this is a
    /// response stream the owned transport genuinely supports, and not a
    /// hijacked connection. The records are projected by
    /// `map_event_record_lenient`, which reads the same members the generated
    /// model exposes and keeps this entry point's forward-compatible reading of
    /// a member whose JSON type is not the model's.
    ///
    /// [`Self::system_events`](super::DockerClient::system_events) is the other
    /// event entry point. It is declared in `system.rs` and rewired there onto
    /// the same [`raw::events`] transport, but it uses
    /// `map_event_record_strict`: it replaced a typed decode and keeps that
    /// decode's refusal of a malformed known field. The two differ only in what
    /// a wrong JSON type for a known member does — this one reads it as absent,
    /// that one returns an error item.
    pub fn events(
        &self,
        options: Option<DockerEventsOptions>,
    ) -> DockerStream<DockerEventResponse> {
        let engine = self.raw_engine();
        let options = options.map_or_else(EventOptions::default, |options| EventOptions {
            since: options.since,
            until: options.until,
            filters: options.filters,
        });
        owned_response(async move {
            let engine = engine?;
            let frames = raw::events(&engine, &options).await?;
            Ok(OwnedResponse::Records {
                frames,
                map: Box::new(|record| Ok(map_event_record_lenient(&record))),
            })
        })
    }

    /// Pulls an image and returns Docker's typed progress events.
    ///
    /// This unauthenticated form remains free of registry credentials. Use
    /// [`Self::pull_image_with_provider`] or
    /// [`Self::pull_image_with_credential_helper`] when authentication is
    /// explicitly required.
    ///
    /// Rewired onto [`raw::pull_stream`] with [`raw::RegistryAuth::none`], which
    /// sends no `X-Registry-Auth` header at all. That is the honest spelling of
    /// "no credentials were sent", and it is deliberately not the same request as
    /// one carrying an empty auth object: a header the daemon cannot decode reads
    /// as no credential, which would blur exactly the distinction the
    /// credentialed forms exist to keep.
    pub fn pull_image(
        &self,
        image: &str,
        options: Option<ImagePullOptions>,
    ) -> DockerStream<ImageStreamEvent> {
        let engine = self.raw_engine();
        let image = image.to_owned();
        let options = options.unwrap_or_default();
        owned_response(async move {
            let engine = engine?;
            let frames =
                raw::pull_stream(&engine, &image, &options, raw::RegistryAuth::none()).await?;
            Ok(OwnedResponse::Records {
                frames,
                map: Box::new(|record| Ok(map_image_event(&record))),
            })
        })
    }

    /// Pushes an image and returns Docker's typed progress events.
    ///
    /// This unauthenticated form remains free of caller-supplied registry
    /// credentials. Use [`Self::push_image_with_provider`] or
    /// [`Self::push_image_with_credential_helper`] when authentication is
    /// explicitly required.
    ///
    /// Rewired onto [`raw::push_stream`], with the same [`raw::RegistryAuth::none`]
    /// spelling as the unauthenticated pull.
    ///
    /// **A `200` is not a result.** The daemon answers a refused push with `200`
    /// and the refusal in a record, so the failure is still an
    /// [`ImageStreamEvent::error`] on this stream exactly as it was on the
    /// generated one.
    pub fn push_image(
        &self,
        image: &str,
        options: Option<ImagePushOptions>,
    ) -> DockerStream<ImageStreamEvent> {
        let engine = self.raw_engine();
        let image = image.to_owned();
        let options = options.unwrap_or_default();
        owned_response(async move {
            let engine = engine?;
            let frames =
                raw::push_stream(&engine, &image, &options, raw::RegistryAuth::none()).await?;
            Ok(OwnedResponse::Records {
                frames,
                map: Box::new(|record| Ok(map_image_event(&record))),
            })
        })
    }

    /// Pulls an image with credentials supplied directly by the caller.
    ///
    /// The registry is derived from `image` using Docker's image-reference
    /// rules. The credentials are copied into only the registry-auth
    /// request; the returned stream remains caller-owned and can be cancelled
    /// or dropped independently of the client.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the image/registry is invalid, the
    /// credentials are incomplete or oversized, or their server address does
    /// not match the requested registry. No HTTP request is opened on error.
    pub fn pull_image_with_credentials(
        &self,
        image: &str,
        options: Option<ImagePullOptions>,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError> {
        let registry = registry_for_image(image)?;
        self.pull_image_with_credentials_for_registry(image, options, &registry, credentials)
    }

    /// Pulls an image using credentials from a caller-owned provider.
    ///
    /// The provider is called synchronously before the response stream is
    /// constructed. The client never reads Docker's credential configuration
    /// or persists the returned value.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the image is invalid or the provider
    /// cannot supply matching credentials.
    pub fn pull_image_with_provider<P>(
        &self,
        image: &str,
        options: Option<ImagePullOptions>,
        provider: &P,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError>
    where
        P: RegistryCredentialProvider + ?Sized,
    {
        let registry = registry_for_image(image)?;
        self.pull_image_with_provider_for_registry(image, options, &registry, provider)
    }

    /// Pulls an image using an explicitly selected registry and provider.
    ///
    /// This variant is useful when a local image name needs credentials for a
    /// registry that cannot be inferred from the image reference.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the registry is invalid or the
    /// provider cannot supply matching credentials.
    pub fn pull_image_with_provider_for_registry<P>(
        &self,
        image: &str,
        options: Option<ImagePullOptions>,
        registry: &str,
        provider: &P,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError>
    where
        P: RegistryCredentialProvider + ?Sized,
    {
        let registry = normalize_registry(registry)?;
        let credentials = provider.credentials_for(&registry)?;
        self.pull_image_with_credentials_for_registry(image, options, &registry, credentials)
    }

    /// Pulls an image with an explicitly selected registry and credentials.
    ///
    /// This is the **canonical** credentialed pull: every other `pull_image`
    /// form that takes a credential reaches the transport through here. The
    /// provider and helper variants differ only in how a [`RegistryCredentials`]
    /// is obtained — each resolves one and then calls this method — so giving
    /// them their own transport call would mean two places to keep the
    /// credential handling identical.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the registry or credentials are invalid,
    /// oversized, or associated with a different registry. That check runs
    /// before any request is opened.
    pub fn pull_image_with_credentials_for_registry(
        &self,
        image: &str,
        options: Option<ImagePullOptions>,
        registry: &str,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError> {
        let registry = normalize_registry(registry)?;
        credentials.validate_for(&registry)?;
        let engine = self.raw_engine();
        let image = image.to_owned();
        let options = options.unwrap_or_default();
        Ok(owned_response(async move {
            let engine = engine?;
            // The credential is built here rather than when the handle was
            // created, so a credential that cannot be encoded arrives as a
            // stream item — the same place every other request failure does.
            // There is no path that sends an empty auth object instead: a
            // header the daemon cannot decode reads as *no* credential, and
            // "no credentials were sent" has to stay distinguishable from
            // "credentials were sent and were refused".
            let auth = raw::RegistryAuth::credentials(&registry, &credentials)?;
            let frames = raw::pull_stream(&engine, &image, &options, auth).await?;
            Ok(OwnedResponse::Records {
                frames,
                map: Box::new(|record| Ok(map_image_event(&record))),
            })
        }))
    }

    /// Pulls an image using a bounded Docker credential helper.
    ///
    /// Helper execution completes before the response stream is constructed;
    /// helper stdout, lifetime, and diagnostics remain bounded by
    /// [`DockerCredentialHelper`]. The helper is never discovered or invoked
    /// implicitly by [`Self::pull_image`].
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the image, helper response, or
    /// resulting credentials are invalid.
    pub async fn pull_image_with_credential_helper(
        &self,
        image: &str,
        options: Option<ImagePullOptions>,
        helper: &DockerCredentialHelper,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError> {
        let registry = registry_for_image(image)?;
        self.pull_image_with_credential_helper_for_registry(image, options, &registry, helper)
            .await
    }

    /// Pulls an image using an explicit registry and bounded helper.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the registry, helper, or credentials
    /// are invalid.
    pub async fn pull_image_with_credential_helper_for_registry(
        &self,
        image: &str,
        options: Option<ImagePullOptions>,
        registry: &str,
        helper: &DockerCredentialHelper,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError> {
        let normalized_registry = normalize_registry(registry)?;
        let credentials = helper.get(registry).await?;
        self.pull_image_with_credentials_for_registry(
            image,
            options,
            &normalized_registry,
            credentials,
        )
    }

    /// Pushes an image with credentials supplied directly by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the image/registry is invalid, the
    /// credentials are incomplete or oversized, or their server address does
    /// not match the requested registry. No HTTP request is opened on error.
    pub fn push_image_with_credentials(
        &self,
        image: &str,
        options: Option<ImagePushOptions>,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError> {
        let registry = registry_for_image(image)?;
        self.push_image_with_credentials_for_registry(image, options, &registry, credentials)
    }

    /// Pushes an image using credentials from a caller-owned provider.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the image is invalid or the provider
    /// cannot supply matching credentials.
    pub fn push_image_with_provider<P>(
        &self,
        image: &str,
        options: Option<ImagePushOptions>,
        provider: &P,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError>
    where
        P: RegistryCredentialProvider + ?Sized,
    {
        let registry = registry_for_image(image)?;
        self.push_image_with_provider_for_registry(image, options, &registry, provider)
    }

    /// Pushes an image using an explicitly selected registry and provider.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the registry is invalid or the
    /// provider cannot supply matching credentials.
    pub fn push_image_with_provider_for_registry<P>(
        &self,
        image: &str,
        options: Option<ImagePushOptions>,
        registry: &str,
        provider: &P,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError>
    where
        P: RegistryCredentialProvider + ?Sized,
    {
        let registry = normalize_registry(registry)?;
        let credentials = provider.credentials_for(&registry)?;
        self.push_image_with_credentials_for_registry(image, options, &registry, credentials)
    }

    /// Pushes an image using an explicit registry and credentials.
    ///
    /// This is the **canonical** credentialed push, for the same reason
    /// [`Self::pull_image_with_credentials_for_registry`] is the canonical pull:
    /// every other `push_image` form that takes a credential resolves one and
    /// then calls this.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the registry or credentials are invalid,
    /// oversized, or associated with a different registry.
    pub fn push_image_with_credentials_for_registry(
        &self,
        image: &str,
        options: Option<ImagePushOptions>,
        registry: &str,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError> {
        let registry = normalize_registry(registry)?;
        credentials.validate_for(&registry)?;
        let engine = self.raw_engine();
        let image = image.to_owned();
        let options = options.unwrap_or_default();
        Ok(owned_response(async move {
            let engine = engine?;
            let auth = raw::RegistryAuth::credentials(&registry, &credentials)?;
            let frames = raw::push_stream(&engine, &image, &options, auth).await?;
            Ok(OwnedResponse::Records {
                frames,
                map: Box::new(|record| Ok(map_image_event(&record))),
            })
        }))
    }

    /// Pushes an image using a bounded Docker credential helper.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the image, helper response, or
    /// resulting credentials are invalid.
    pub async fn push_image_with_credential_helper(
        &self,
        image: &str,
        options: Option<ImagePushOptions>,
        helper: &DockerCredentialHelper,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError> {
        let registry = registry_for_image(image)?;
        self.push_image_with_credential_helper_for_registry(image, options, &registry, helper)
            .await
    }

    /// Pushes an image using an explicit registry and bounded helper.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the registry, helper, or credentials
    /// are invalid.
    pub async fn push_image_with_credential_helper_for_registry(
        &self,
        image: &str,
        options: Option<ImagePushOptions>,
        registry: &str,
        helper: &DockerCredentialHelper,
    ) -> Result<DockerStream<ImageStreamEvent>, CredentialError> {
        let normalized_registry = normalize_registry(registry)?;
        let credentials = helper.get(registry).await?;
        self.push_image_with_credentials_for_registry(
            image,
            options,
            &normalized_registry,
            credentials,
        )
    }

    /// Downloads an image archive as caller-owned byte chunks.
    ///
    /// The archive is never collected or buffered by the facade; each poll
    /// yields the next transport chunk.
    ///
    /// Rewired onto [`raw::save`], which reads the same body with
    /// [`raw::FrameStream::next_data`]. An archive is bytes, not JSON, so it must
    /// not go through a record reader; that is recorded where the owned
    /// operation documents it.
    pub fn export_image(&self, image: &str) -> DockerStream<Vec<u8>> {
        let engine = self.raw_engine();
        let options = ImageSaveOptions::new([image]);
        owned_response(async move {
            let engine = engine?;
            Ok(OwnedResponse::Chunks {
                frames: raw::save(&engine, &options).await?,
                into_item: |chunk| chunk.to_vec(),
            })
        })
    }

    /// Downloads an archive containing multiple image repositories as chunks.
    ///
    /// Rewired onto [`raw::save`] with more than one name, which is the
    /// `GET /images/get` form with one repeated `names=` pair each.
    pub fn export_images(&self, images: &[&str]) -> DockerStream<Vec<u8>> {
        let engine = self.raw_engine();
        let options = ImageSaveOptions::new(
            images
                .iter()
                .map(|image| (*image).to_owned())
                .collect::<Vec<String>>(),
        );
        owned_response(async move {
            let engine = engine?;
            Ok(OwnedResponse::Chunks {
                frames: raw::save(&engine, &options).await?,
                into_item: |chunk| chunk.to_vec(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ContainerLogFrame, OwnedResponse, PendingResponse};
    use std::future::Future;
    use std::mem::size_of;
    use std::pin::Pin;

    /// The unfold state is moved twice per poll, so its size is a per-poll cost.
    ///
    /// This is the assertion behind boxing `PendingResponse::Open`, and it is a
    /// test rather than a comment because the regression is silent and cheap to
    /// reintroduce: un-boxing it costs no wall-clock in any test, no correctness,
    /// and no clippy warning until the enum crosses the lint's threshold — at
    /// which point the fix is to shrink the enum again, by whatever means. The
    /// per-poll memmove is the reason the box is there, and a bound on the size
    /// is what keeps the reason from being quietly undone.
    ///
    /// # What the sixteen bytes are
    ///
    /// Two words: the *data pointer and the vtable pointer* of the
    /// `Box<dyn Future>` in [`PendingResponse::Request`]. It is a fat pointer, and
    /// it is the largest variant, so the enum is exactly as wide as it.
    ///
    /// The tag is not on top of those words — it is free. A non-null `Box` leaves
    /// spare bit patterns in the pointer, and the layout uses one of them to say
    /// which variant this is, so the discriminant costs no bytes at all. Measured:
    /// an enum of one `Pin<Box<dyn Future>>` and one `Box<T>` is 16 bytes for
    /// every `T` tried, and 16 is the fat pointer on its own.
    ///
    /// An earlier version of this comment said the size was "a pointer's width"
    /// and then asserted twice that, which is the same number arrived at by the
    /// wrong reasoning: it read as though a word of tag sat on top of a thin
    /// pointer. The number was right and the explanation was not, which is the
    /// same failure as a wrong number — a reader who takes it literally will size
    /// the next thing wrongly.
    #[test]
    fn the_unfold_state_is_a_fat_pointer_wide_whatever_the_response_holds() {
        let fat = size_of::<Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'static>>>();
        assert_eq!(
            fat,
            2 * size_of::<*const ()>(),
            "a fat pointer is two words"
        );
        // The enum is the width of its largest variant, and `T` cannot reach it:
        // `T` appears inside the future's output, which the trait object erases,
        // and inside the response, which is boxed. A large `T` is the case that
        // would catch it if that ever stopped being true.
        assert_eq!(size_of::<PendingResponse<[u8; 4096]>>(), fat);
        assert_eq!(size_of::<PendingResponse<Vec<u8>>>(), fat);
        // The response itself is the large thing, and it is behind the pointer.
        assert!(
            size_of::<OwnedResponse<ContainerLogFrame>>() > 8 * size_of::<*const ()>(),
            "the response is larger than eight words, so boxing it is worth its one allocation"
        );
    }
}
