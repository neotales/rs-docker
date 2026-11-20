//! Container control operations: `kill`, `pause`, `unpause`, `rename`,
//! `resize`, and `attach`.
//!
//! These are the container endpoints whose success is a status rather than a
//! document, plus the two that take a query the caller has to spell out. They
//! share one shape — a versioned path, an optional query, and a body that is
//! either empty or a two-field document — so the shared
//! [`completed`](super::containers::completed) mapping is used rather than a
//! per-operation status check.
//!
//! # `204` is a success, not an empty document
//!
//! `kill`, `pause`, `unpause`, and `rename` answer `204` with no body and no
//! `Content-Length`, measured against Docker Engine 29.8.0. The body is read and
//! discarded, never handed to a JSON decoder: a client that decoded every
//! success as JSON would report a successful lifecycle call as a parse failure.
//!
//! # `resize` answers `200` with no body
//!
//! `POST /containers/{id}/resize` is a `200` with an empty body rather than a
//! `204`, so it takes the same path through [`completed`] but for a different
//! reason. Nothing here decides what a status means; that belongs to
//! [`engine_result`](super::engine_result), which is shared with every other
//! operation in the backend.
//!
//! # `attach` reports; `attach_stream` reads
//!
//! `POST /containers/{id}/attach` does not answer with a document. Measured
//! against Docker Engine 29.8.0 with `stream=1`:
//!
//! | Request | Answer |
//! | --- | --- |
//! | no `Connection: Upgrade` header | `200`, `Content-Type: application/vnd.docker.raw-stream`, then the connection carries the raw stream and stays open |
//! | `Connection: Upgrade`, `Upgrade: tcp` | `101 UPGRADED`, then the raw stream |
//!
//! Neither answer has a length, so the body cannot be read as a document: the
//! daemon holds the connection open and writes container output to it until the
//! attach ends. The two operations here answer the two questions a caller can
//! have, and neither hides what it did with the stream.
//!
//! [`attach`] sends the upgrade request and reports what the daemon chose. On a
//! `101` it takes the connection over and returns both halves as
//! [`Attached::Upgraded`] only when
//! [`ContainerAttachOptions::stream`] or [`ContainerAttachOptions::stdin`] is
//! set. On any other accepted answer (normally `200`) it drops the response,
//! which closes the socket and ends the attachment immediately, and reports
//! [`Attached::Started`] when either option is set rather than pretending it
//! read a stream it discarded. With neither option set it reports
//! [`Attached::Ended`] for either answer. That is the `docker start -a` shape of
//! "this container has an output stream and I do not want it".
//!
//! [`attach_stream`] sends the same request and is the read-side counterpart.
//! A `101` answer is still returned as [`AttachedStream::Upgraded`] with both
//! halves, so the upgrade semantics are unchanged. A `200` answer is returned
//! as [`AttachedStream::Streaming`] with the response body as a
//! [`FrameStream`](super::FrameStream), so the caller can read the raw bytes
//! instead of losing them. The bytes are not decoded: a non-TTY container's
//! body is multiplexed stdout/stderr, a TTY container's body is verbatim, and
//! the response's content type does not say which. See [`AttachedStream`] for
//! the framing and for the public [`LogDecoder`](super::LogDecoder) flow that
//! turns the bytes into frames. A `200` has no protocol switch and therefore no
//! write half: this operation does not invent one, and a caller that asked for
//! stdin does not get a usable stdin on that answer. The body is bounded only
//! by the caller's own reading; dropping it closes the connection.
//!
//! # The `stream` and `stdin` flags are always spelled
//!
//! Every flag is sent as `true`/`false` on every call, so a recorded request
//! says what it meant. An omitted flag is the daemon's default, and a recorded
//! `POST /containers/{id}/attach?logs=1` that does not say whether stdout was
//! wanted is not a request anybody can reproduce.

use hyper::Method;

use super::body::{FrameStream, SwitchedConnection, SwitchedReadHalf, SwitchedWriteHalf};
use super::containers::{Query, completed, container_path, with_query};
use super::transport::{RawEngine, RawRequest, engine_result};
use crate::Error;

/// Options for `POST /containers/{id}/kill`.
///
/// The signal is omitted rather than sent empty. An empty `signal=` is not the
/// same as no `signal`: the Engine parses the parameter with
/// `strconv.Atoi` falling back to a signal-name lookup, and an empty value is
/// neither, so it is a `400`. Measured against Docker Engine 29.8.0, the facade's
/// recorded request for a kill with no signal is
/// `POST /containers/c/kill` with no query at all, and the daemon answers `204`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContainerKillOptions {
    /// The signal name or number, such as `SIGKILL` or `9`.
    ///
    /// Omitted when unset, so the daemon applies its own default — `SIGKILL` —
    /// rather than this client's guess.
    pub signal: Option<String>,
}

/// Options for `POST /containers/{id}/resize`.
///
/// The Engine declares `h` and `w` as `uint`; the repository's terminal sizes
/// are `u16` characters, which is the range a terminal can express and the range
/// every other client sends.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContainerResizeOptions {
    /// Terminal height in characters.
    pub height: u16,
    /// Terminal width in characters.
    pub width: u16,
}

/// Options for `POST /containers/{id}/attach`.
///
/// The boolean count is the endpoint's: the Engine declares five stream-selection
/// flags for an attach and a client that offered fewer would be choosing which
/// output the caller can have.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContainerAttachOptions {
    /// Ask the daemon to keep the connection open and stream both output streams.
    ///
    /// With `stream` set the daemon normally answers `101` (upgraded) or `200`
    /// (hijacked). [`attach`] reports it and, on a `101`, hands it back as
    /// [`Attached::Upgraded`]; [`attach_stream`] also returns the `200` body as
    /// a readable stream. Any other accepted answer has no connection or body
    /// to hand back.
    pub stream: bool,
    /// Keep standard input open on the attachment.
    pub stdin: bool,
    /// Include standard output.
    pub stdout: bool,
    /// Include standard error.
    pub stderr: bool,
    /// Replay the container's existing log before streaming new output.
    pub logs: bool,
    /// The detach-key sequence, as the Engine spells it: `ctrl-p,ctrl-q`.
    pub detach_keys: Option<String>,
}

impl Default for ContainerAttachOptions {
    /// Defaults to both output streams without replaying logs.
    ///
    /// `stdout` and `stderr` default to true for the same reason
    /// [`ContainerLogOptions`](super::ContainerLogOptions) defaults them to true:
    /// an attach that returns nothing because nobody set a flag is
    /// indistinguishable from a container that produced no output, and only one
    /// of those is a real answer.
    fn default() -> Self {
        Self {
            stream: false,
            stdin: false,
            stdout: true,
            stderr: true,
            logs: false,
            detach_keys: None,
        }
    }
}

/// What the daemon did with an attach request.
///
/// The distinction is the whole answer. [`Self::Ended`] means the daemon
/// accepted the request and this client closed the connection, so the attachment
/// is over; it is the answer when neither `stream` nor `stdin` was set.
/// [`Self::Started`] means the daemon accepted the request with a status other
/// than the `101` upgrade; this client dropped the response, closing the
/// connection, so no output was read and the answer does not claim any is still
/// arriving. It is the answer when either option was set but the daemon did not
/// answer `101`.
/// [`Self::Upgraded`] means the daemon switched protocols and this client is
/// holding the connection, so the output can be read and input written.
///
/// Reporting which of the three happened is what keeps the second from reading as
/// the third: only the third leaves the caller able to read output or write
/// input, and the second is a discarded response rather than an open stream.
#[derive(Debug)]
pub enum Attached {
    /// The daemon switched protocols and this client holds the connection.
    ///
    /// The two halves are the same socket, split. Dropping both closes it, which
    /// the daemon observes as the attach ending — the same contract the
    /// generated client offers, so a caller cannot tell which transport served it.
    Upgraded {
        /// The status the daemon answered with, `101` when it switched protocols.
        status: hyper::StatusCode,
        /// The read half: the container's multiplexed output frames.
        read: SwitchedReadHalf,
        /// The write half: the caller's input to the container.
        write: SwitchedWriteHalf,
    },
    /// The daemon accepted the request with a status other than the `101`
    /// upgrade, and this client dropped the response.
    ///
    /// Dropping the response closed the connection, so the daemon has already
    /// observed the disconnect. Any output the daemon wrote before that is gone;
    /// the log endpoint is where it can still be read. The accepted status does
    /// not prove the daemon began streaming output.
    Started {
        /// The status the daemon answered with. This is an accepted status
        /// other than the `101` upgrade — normally `200`, the hijacked stdio
        /// path — because a `101` answer is `Upgraded` when either option is set
        /// and `Ended` when neither is.
        status: hyper::StatusCode,
    },
    /// The daemon accepted the request and the attachment is over.
    Ended {
        /// The status the daemon answered with. With neither `stream` nor
        /// `stdin` set, any accepted status, including `101`, is reported here.
        status: hyper::StatusCode,
    },
}

impl Attached {
    /// Returns the status the daemon answered with.
    #[must_use]
    pub const fn status(&self) -> hyper::StatusCode {
        match self {
            Self::Upgraded { status, .. } | Self::Started { status } | Self::Ended { status } => {
                *status
            }
        }
    }

    /// Returns whether this is [`Self::Started`], the accepted non-`101` answer
    /// whose response this client discarded rather than read.
    #[must_use]
    pub const fn is_streaming(&self) -> bool {
        matches!(self, Self::Started { .. })
    }

    /// Takes the connection the daemon switched protocols on, as a read half and
    /// a write half.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon did not switch protocols, which is the
    /// case a caller reaches by asking for a connection the daemon declined to
    /// give.
    pub fn into_connection(self) -> Result<SwitchedConnection, crate::Error> {
        match self {
            Self::Upgraded { read, write, .. } => Ok((read, write)),
            other => Err(crate::Error::transport(format!(
                "the daemon answered {} and did not switch protocols, so there is no \
                 connection to take",
                other.status()
            ))),
        }
    }
}

/// What the daemon did with an attach request whose output the caller wants to
/// read.
///
/// This is the additive read-side counterpart to [`Attached`]. [`Attached`] is
/// public and exhaustive, so adding a variant to it would break every caller
/// that matches on it; this type is separate for exactly that reason. A caller
/// that only wants the status and whether a connection was handed back still
/// uses [`attach`] and [`Attached`].
///
/// # A `200` answer is read-only
///
/// [`Self::Streaming`] is the `200` answer. The daemon did not switch
/// protocols, so there is no write half to return and this type does not
/// pretend there is one. A request that set [`ContainerAttachOptions::stdin`]
/// does not get a usable stdin on this answer.
///
/// # The body's framing depends on the container
///
/// The response's `Content-Type` is `application/vnd.docker.raw-stream` whether
/// or not the container has a TTY, so the header does not say how to read the
/// body:
///
/// - A container created with a TTY writes its output verbatim. Every byte is
///   console output, which
///   [`LogStream::Console`](super::LogStream::Console) names.
/// - A container without a TTY writes the Engine's multiplexed stream: an
///   eight-byte header — stream id (`0` stdin, `1` stdout, `2` stderr), three
///   zero bytes, and a big-endian `u32` payload length — followed by exactly
///   that many payload bytes. Standard output and standard error are
///   interleaved on the one body, so a caller that concatenates the bytes
///   without decoding the header loses which stream each chunk came from.
///
/// `attach_stream` returns those bytes unchanged and decodes neither form. The
/// repository's decoder for this framing is [`LogDecoder`](super::LogDecoder),
/// and its feed path is public: construct it with
/// [`LogDecoder::new`](super::LogDecoder::new) and the container's TTY flag,
/// pass each [`FrameStream::next_data`] chunk to
/// [`LogDecoder::push`](super::LogDecoder::push), and call
/// [`LogDecoder::finish`](super::LogDecoder::finish) when the body ends.
/// `push` returns the frames that chunk completed; `finish` reports a body that
/// ended part-way through a frame. A refusal that a chunk reveals is reported
/// by the next call, after the frames that preceded it, so no output is lost to
/// the error. Call [`LogDecoder::decode`](super::LogDecoder::decode) after each
/// `push` and before awaiting the next chunk, draining it until it returns
/// `None`: otherwise a malformed frame followed by a silent connection would
/// leave the latched refusal unreported until `finish`, which never arrives
/// while the daemon holds the connection open. A decoder that refuses the
/// framing stays refused, and every later `push`, `decode`, or `finish` reports
/// the same error. The caller also has to know whether the container has a TTY,
/// exactly as [`ContainerLogOptions::tty`](super::ContainerLogOptions::tty)
/// requires: the attach response does not report it.
/// [`FrameStream::next_data`] hands over transport chunks, not frames.
///
/// # Cancellation and drop
///
/// There is no cancel call. Dropping [`Self::Streaming`] drops its
/// [`FrameStream`], which drops the response body and aborts its connection
/// driver, so the socket closes and the daemon observes the attachment ending.
/// Dropping [`Self::Upgraded`] drops both halves of the switched connection,
/// which closes the same socket. A caller that keeps only one half alive keeps
/// the connection alive, exactly as with [`Attached::Upgraded`].
///
/// # API compatibility
///
/// This is an addition. [`attach`] and [`Attached`] keep their existing
/// behaviour and their exhaustive variant set, so code that matched on
/// [`Attached`] continues to compile and to see the same answers.
// The `Streaming` variant owns the response, its connection driver, and the
// record buffer, so it is much larger than the two small halves in `Upgraded`.
// Boxing the body would put every `200` answer behind a second allocation for a
// value that is created once and immediately matched, and this enum is not
// stored in a collection. The size difference is real and accepted.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum AttachedStream {
    /// The daemon switched protocols and this client holds the connection.
    ///
    /// The two halves are the same socket, split, and this is the same shape
    /// [`Attached::Upgraded`] returns. It is reached from a `101` answer to the
    /// same request [`attach`] sends.
    Upgraded {
        /// The status the daemon answered with, `101` when it switched
        /// protocols.
        status: hyper::StatusCode,
        /// The read half: the container's output.
        read: SwitchedReadHalf,
        /// The write half: the caller's input to the container.
        write: SwitchedWriteHalf,
    },
    /// The daemon answered `200`; any output it writes is on the response body.
    ///
    /// This variant has no write half. The daemon did not switch protocols, so
    /// there is no connection to write to; the body is read-only.
    Streaming {
        /// The status the daemon answered with, `200` for this variant.
        status: hyper::StatusCode,
        /// The raw output stream, in the container's attach framing. Dropping
        /// it closes the connection. A non-TTY container's body is multiplexed
        /// and a TTY container's body is verbatim; this type does not decode
        /// either. See the type documentation.
        body: FrameStream,
    },
}

impl AttachedStream {
    /// Returns the status the daemon answered with.
    #[must_use]
    pub const fn status(&self) -> hyper::StatusCode {
        match self {
            Self::Upgraded { status, .. } | Self::Streaming { status, .. } => *status,
        }
    }

    /// Returns whether this answer is the read-only `200` body.
    ///
    /// A `false` answer means the daemon switched protocols and both halves are
    /// available from [`Self::into_connection`].
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self, Self::Streaming { .. })
    }

    /// Takes the raw output stream from a `200` answer.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon switched protocols. In that case the
    /// output is on the read half of [`Self::Upgraded`], not on a response
    /// body, and this consumes the value, so the connection is closed rather
    /// than leaked. Use [`Self::into_connection`] for that answer.
    pub fn into_stream(self) -> Result<FrameStream, crate::Error> {
        match self {
            Self::Streaming { body, .. } => Ok(body),
            Self::Upgraded { status, .. } => Err(crate::Error::transport(format!(
                "the daemon answered {status} and switched protocols, so the output is on \
                 the read half of AttachedStream::Upgraded rather than a response body"
            ))),
        }
    }

    /// Takes the connection the daemon switched protocols on, as a read half
    /// and a write half.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon answered `200`. That answer has no
    /// write half, and this consumes the value, so the read-only body is closed
    /// rather than handed back as something it is not. Use
    /// [`Self::into_stream`] for that answer.
    pub fn into_connection(self) -> Result<SwitchedConnection, crate::Error> {
        match self {
            Self::Upgraded { read, write, .. } => Ok((read, write)),
            Self::Streaming { status, .. } => Err(crate::Error::transport(format!(
                "the daemon answered {status} without switching protocols, so there is no \
                 write half; the body is read-only and is returned by \
                 AttachedStream::into_stream"
            ))),
        }
    }
}

/// Sends a signal to a container.
///
/// `POST /containers/{id}/kill` answers `204`, so the status is the whole
/// result. A kill of a container that has already stopped is *not* an error:
/// measured against Docker Engine 29.8.0, killing a stopped container answers
/// `204` with no body, so this call is idempotent and does not need a state
/// check first.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` carrying `cannot kill container: <name>: No such
/// container: <name>`, or a `409` for a container the daemon will not signal —
/// or when a signal name the Engine does not know arrives as a `400`.
pub async fn kill(
    engine: &RawEngine,
    container: &str,
    options: &ContainerKillOptions,
) -> Result<(), Error> {
    completed(engine, kill_request(container, options)?).await
}

/// Builds the `POST /containers/{id}/kill` request.
fn kill_request(container: &str, options: &ContainerKillOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(signal) = &options.signal {
        query.value("signal", signal);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/kill")?),
        query.finish(),
    ))
}

/// Pauses every process in a container.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request. A `409` is the answer for a container that is not running: measured
/// against Docker Engine 29.8.0, pausing a stopped container answers
/// `409 container <id> is not running`.
pub async fn pause(engine: &RawEngine, container: &str) -> Result<(), Error> {
    completed(engine, pause_request(container)?).await
}

/// Builds the `POST /containers/{id}/pause` request.
fn pause_request(container: &str) -> Result<RawRequest, Error> {
    control_request(container, "pause")
}

/// Resumes every paused process in a container.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request, such as a `409` for a container that is not paused.
pub async fn unpause(engine: &RawEngine, container: &str) -> Result<(), Error> {
    completed(engine, unpause_request(container)?).await
}

/// Builds the `POST /containers/{id}/unpause` request.
fn unpause_request(container: &str) -> Result<RawRequest, Error> {
    control_request(container, "unpause")
}

/// Renames a container.
///
/// The name is a query value. The Engine's rename endpoint has no body, so there
/// is nowhere else for it to go, and a rename whose name did not travel is a
/// container the caller can no longer address by the name it asked for.
///
/// The `link` parameter the Engine also accepts is not sent. It is the legacy
/// "rename this link too" flag, it was deprecated in the Engine's own
/// documentation, and the current facade does not send it either. Measured
/// against Docker Engine 29.8.0, `?name=<new>&link=<old>` is accepted with a
/// `204` and renames the container, so omitting it costs nothing here.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request — a `404` for a name that is taken, or a `400` for a name the
/// Engine's `[a-zA-Z0-9][a-zA-Z0-9_.-]` rule rejects.
pub async fn rename(engine: &RawEngine, container: &str, name: &str) -> Result<(), Error> {
    completed(engine, rename_request(container, name)?).await
}

/// Builds the `POST /containers/{id}/rename` request.
fn rename_request(container: &str, name: &str) -> Result<RawRequest, Error> {
    if name.is_empty() {
        return Err(Error::invalid_input(
            "the new container name must not be empty",
        ));
    }
    let mut query = Query::default();
    query.value("name", name);
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/rename")?),
        query.finish(),
    ))
}

/// Resizes a container's pseudo-TTY.
///
/// The daemon ignores the request when the container was created without a TTY,
/// and answers `200` either way, so a successful return is not a statement that
/// the terminal changed size. That is the Engine's behaviour rather than a
/// limitation of this client, and it is recorded here because a caller that
/// resizes and then reads [`ContainerInspect::tty`](super::ContainerInspect::tty)
/// should not be surprised.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the container reference is empty.
pub async fn resize(
    engine: &RawEngine,
    container: &str,
    options: &ContainerResizeOptions,
) -> Result<(), Error> {
    completed(engine, resize_request(container, *options)?).await
}

/// Builds the `POST /containers/{id}/resize` request.
///
/// `h` is sent before `w`, which is the order the Engine's own documentation
/// spells them in and the order the current facade's exec resize produces
/// (measured: `POST /exec/<id>/resize?h=40&w=100`).
fn resize_request(container: &str, options: ContainerResizeOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("h", &options.height.to_string());
    query.value("w", &options.width.to_string());
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/resize")?),
        query.finish(),
    ))
}

/// Starts an attachment to a container's output streams.
///
/// The daemon's answer is not a document, so this reports what it did instead of
/// reading a body. See the module documentation for the measured `200` and `101`
/// answers and for what this does and does not do with the stream.
///
/// The request asks the daemon to switch protocols. A `101` answer is taken
/// over and returned as [`Attached::Upgraded`] only when
/// [`ContainerAttachOptions::stream`] or [`ContainerAttachOptions::stdin`] is
/// set, so the caller can read the output and write input. A daemon that
/// declines the switch normally answers `200` and writes the raw stream on the
/// same connection; when either option is set this function reports that as
/// [`Attached::Started`] and drops the response, so a caller that wants those
/// bytes uses [`attach_stream`] instead. With neither option set it reports
/// [`Attached::Ended`] for either answer. Any other accepted status follows the
/// same `Started`/`Ended` path; only `200` has a documented stream body.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` for a container that does not exist, or a `500` for a
/// container that is not running — or when the container reference is empty.
pub async fn attach(
    engine: &RawEngine,
    container: &str,
    options: &ContainerAttachOptions,
) -> Result<Attached, Error> {
    let response = engine
        .send_upgrading(attach_request(container, options)?)
        .await?;
    let status = response.status;
    if !is_accepted(status) {
        // The failure is the daemon's answer, with its status and message; it is
        // never a body to be read as an attachment.
        return Err(engine_result(response)
            .await
            .expect_err("a rejection status is an error"));
    }
    // A daemon that answered `101` switched protocols and handed the connection
    // over, so this client holds it and can both read the container's output and
    // write the caller's input.
    //
    // The previous code dropped the response here, which closed the connection
    // and let the daemon observe the attach ending — so `attach` reported success
    // and delivered nothing. That is now reported as [`Attached::Started`] only
    // when the caller asked to stream or write; with neither option the answer is
    // [`Attached::Ended`].
    if status == hyper::StatusCode::SWITCHING_PROTOCOLS && (options.stream || options.stdin) {
        let (read, write) = response.into_upgraded().await?;
        return Ok(Attached::Upgraded {
            status,
            read,
            write,
        });
    }
    drop(response);
    Ok(if options.stream || options.stdin {
        Attached::Started { status }
    } else {
        Attached::Ended { status }
    })
}

/// Starts an attachment and returns the switched connection or the `200` body.
///
/// This is the additive read-side counterpart to [`attach`]. It sends the same
/// request, including the upgrade headers, so a daemon that supports the switch
/// still answers `101` and the caller gets both halves, the same
/// [`Attached::Upgraded`] shape [`attach`] returns when it keeps the
/// connection. When the daemon answers `200` instead — the hijacked stdio
/// path, which declares no length and keeps the connection open — the response
/// body is returned as a [`FrameStream`] rather than dropped.
///
/// # The `200` answer is read-only
///
/// A `200` response has no protocol switch and therefore no write half.
/// [`AttachedStream::Streaming`] exposes only the status and the body. A caller
/// that set [`ContainerAttachOptions::stdin`] and receives `Streaming` must not
/// assume its input reached the container: the daemon did not upgrade, and this
/// function sends nothing after the request. Use [`attach`] when the write half
/// is required; it reports [`Attached::Started`] when the daemon accepted
/// without an upgrade rather than pretending a connection exists.
///
/// # The body's framing is not decoded
///
/// A `200` body is the container's output in the Engine's attach framing. A
/// container without a TTY writes the eight-byte multiplexed header documented
/// on [`AttachedStream`] and [`LogDecoder`](super::LogDecoder); a container
/// with a TTY writes its output verbatim. The response's `Content-Type` is the
/// same for both, so the caller must know whether the container has a TTY,
/// exactly as [`ContainerLogOptions::tty`](super::ContainerLogOptions::tty)
/// requires. This function returns the bytes unchanged. To decode them, use
/// the public [`LogDecoder`](super::LogDecoder) flow: construct it with
/// [`LogDecoder::new`](super::LogDecoder::new), feed each `next_data` chunk to
/// [`LogDecoder::push`](super::LogDecoder::push), and call
/// [`LogDecoder::finish`](super::LogDecoder::finish) at end of stream. `push`
/// returns the frames completed by that chunk; `finish` reports a truncated
/// final frame. A refusal that a chunk reveals is reported by the next call,
/// after the frames that preceded it, so process those frames and then drain
/// [`LogDecoder::decode`](super::LogDecoder::decode) before awaiting more data.
/// Skipping that call would hide a malformed frame on a silent connection until
/// `finish`, which never arrives while the daemon keeps the connection open.
///
/// # Examples
///
/// ```no_run
/// use neotales_docker::Error;
/// use neotales_docker::raw::{AttachedStream, LogDecoder};
///
/// # async fn example(attached: AttachedStream) -> Result<(), Error> {
/// let AttachedStream::Streaming { mut body, .. } = attached else {
///     // A 101 answer is a switched connection, not this response body.
///     return Ok(());
/// };
/// // `false` is the container's TTY flag: a non-TTY body is multiplexed.
/// let mut decoder = LogDecoder::new(false);
/// fn show(frame: neotales_docker::raw::LogFrame) {
///     println!("{:?}: {} byte(s)", frame.stream, frame.payload.len());
/// }
/// while let Some(chunk) = body.next_data().await.map_err(Error::from)? {
///     for frame in decoder.push(&chunk)? {
///         show(frame);
///     }
///     // `push` reports a newly latched refusal on the next decoder call.
///     // Drain `decode` before awaiting more data, or a silent stream can
///     // hide the refusal until `finish`, which never arrives.
///     while let Some(frame) = decoder.decode()? {
///         show(frame);
///     }
/// }
/// decoder.finish()?;
/// # Ok(())
/// # }
/// ```
///
/// # Cancellation
///
/// There is no cancel call. Dropping the returned value drops the response and
/// its connection driver, or, for a `101`, both halves of the switched
/// connection, and the socket closes. The daemon observes the attachment
/// ending, and any output it produced after the drop is gone. See
/// [`AttachedStream`] for the per-variant detail.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when it answers an accepted status that is neither `200` nor
/// `101`. A rejection's body is read as the Engine's error document; an
/// unexpected success is reported with its status rather than silently treated
/// as an empty stream.
pub async fn attach_stream(
    engine: &RawEngine,
    container: &str,
    options: &ContainerAttachOptions,
) -> Result<AttachedStream, Error> {
    let response = engine
        .send_upgrading(attach_request(container, options)?)
        .await?;
    let status = response.status;
    if !is_accepted(status) {
        // The failure is the daemon's answer, with its status and message; it is
        // never a body to be read as an attachment.
        return Err(engine_result(response)
            .await
            .expect_err("a rejection status is an error"));
    }
    if status == hyper::StatusCode::SWITCHING_PROTOCOLS {
        let (read, write) = response.into_upgraded().await?;
        return Ok(AttachedStream::Upgraded {
            status,
            read,
            write,
        });
    }
    if status == hyper::StatusCode::OK {
        // The response body is the attachment. `into_frames` keeps the response
        // and its connection driver alive for as long as the caller reads, so
        // this is the body rather than a copy of it, and dropping it is the
        // cancellation mechanism.
        return Ok(AttachedStream::Streaming {
            status,
            body: response.into_frames(),
        });
    }
    Err(Error::engine_api(
        status,
        format!(
            "the daemon answered {status} to an attach, which is neither the 200 raw stream \
             nor a 101 protocol switch; the response body was not read"
        ),
    ))
}

/// Builds the `POST /containers/{id}/attach` request.
fn attach_request(container: &str, options: &ContainerAttachOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    // The order matches the Engine's own parameter order so a recorded request
    // reads the way the documentation for the endpoint does.
    query.flag("stream", options.stream);
    query.flag("stdin", options.stdin);
    query.flag("stdout", options.stdout);
    query.flag("stderr", options.stderr);
    query.flag("logs", options.logs);
    if let Some(keys) = &options.detach_keys {
        query.value("detachKeys", keys);
    }
    Ok(with_query(
        // The two upgrade headers are what makes the `101` answer reachable. A
        // daemon that declines the switch answers `200` and writes the raw
        // stream on the response body instead; `attach` reports that answer and
        // `attach_stream` reads it. Measured against Engine 29.8.0 on a running
        // container, both with and without.
        RawRequest::new(Method::POST, &container_path(container, "/attach")?)
            .with_header(hyper::header::CONNECTION, "Upgrade")
            .with_header(hyper::header::UPGRADE, "tcp"),
        query.finish(),
    ))
}

/// Returns whether a status means the daemon accepted the request.
///
/// `101 Switching Protocols` is an *informational* status, so
/// [`hyper::StatusCode::is_success`] is false for it, and the answer to an
/// attach that the daemon upgraded is exactly that status. Treating a `1xx` as a
/// failure would report a successful upgrade as a rejection, so the acceptance
/// test here is "not a rejection" rather than "a success".
fn is_accepted(status: hyper::StatusCode) -> bool {
    status.is_informational() || status.is_success()
}

/// Builds a `POST /containers/{id}/{action}` request with no query.
///
/// `pause` and `unpause` take no parameters, and their request lines are
/// therefore the shortest in the backend: an empty query is `None` rather than
/// `""`, so the recorded line has no trailing `?`.
fn control_request(container: &str, action: &str) -> Result<RawRequest, Error> {
    let request = RawRequest::new(
        Method::POST,
        &container_path(container, &format!("/{action}"))?,
    );
    Ok(with_query(request, None))
}

#[cfg(test)]
mod tests {
    use super::{
        ContainerAttachOptions, ContainerKillOptions, ContainerResizeOptions, attach_request,
        control_request, kill_request, rename_request, resize_request,
    };
    use crate::raw::{RawEngine, RawTarget};
    use crate::{ApiVersion, ErrorKind};

    /// The API version every request-shape assertion pins.
    ///
    /// Derived from the crate's ceiling. What these assertions are about is
    /// the path and its query encoding, not the number in the prefix, and a
    /// literal here would turn a legitimate ceiling change into failures that
    /// the next person removes rather than reads. The number itself is asserted
    /// once, in `raw::mod::tests::the_prefix_is_the_version_the_crate_claims`.
    const VERSION: ApiVersion = crate::API_VERSION;

    fn engine() -> RawEngine {
        RawEngine::new(
            RawTarget::Unix(std::path::PathBuf::from("/tmp/does-not-matter.sock")),
            VERSION,
        )
    }

    /// Renders the exact request line a request would put on the wire.
    fn request_line(request: &super::RawRequest) -> String {
        let uri = engine().request_uri(request).expect("absolute path");
        format!("{} {uri} HTTP/1.1", request.method)
    }

    #[test]
    fn kill_sends_the_signal_and_omits_it_when_there_is_none() {
        let signalled = kill_request(
            "web 1",
            &ContainerKillOptions {
                signal: Some("SIGKILL".to_owned()),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&signalled),
            crate::raw::at_api_version(
                "POST /v1.API/containers/web%201/kill?signal=SIGKILL HTTP/1.1"
            )
        );
        // An empty `signal=` is not "no signal": the Engine parses the parameter
        // as a number and then as a name, and an empty value is neither. The
        // measured facade request for a kill with no signal carries no query.
        let plain = kill_request("web", &ContainerKillOptions::default()).expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("POST /v1.API/containers/web/kill HTTP/1.1")
        );
    }

    #[test]
    fn pause_and_unpause_send_no_query_at_all() {
        for (request, expected) in [
            (
                super::pause_request("web").expect("request"),
                crate::raw::at_api_version("POST /v1.API/containers/web/pause HTTP/1.1"),
            ),
            (
                super::unpause_request("web").expect("request"),
                crate::raw::at_api_version("POST /v1.API/containers/web/unpause HTTP/1.1"),
            ),
        ] {
            assert_eq!(request_line(&request), expected);
            assert_eq!(request.query, None, "an empty query is not `?`");
        }
    }

    #[test]
    fn rename_puts_the_new_name_in_the_query_and_sends_no_body() {
        let request = rename_request("old", "new name/1").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/containers/old/rename?name=new+name%2F1 HTTP/1.1"
            )
        );
        // The endpoint has no body, so a request that carried one would be
        // inventing a member the Engine does not read.
        assert_eq!(request.body.known_len(), Some(0));
        // The deprecated `link` flag is not sent; see the function's docs.
        assert!(!request.query.expect("a query").contains("link"));
    }

    #[test]
    fn a_rename_to_an_empty_name_is_refused_before_the_socket() {
        // `/containers/x/rename?name=` is a request to rename a container to
        // nothing, and the Engine answers it with a `500` about an empty name.
        let error = rename_request("x", "").expect_err("an empty name");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn resize_sends_the_height_before_the_width() {
        let request = resize_request(
            "web",
            ContainerResizeOptions {
                height: 40,
                width: 100,
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/web/resize?h=40&w=100 HTTP/1.1")
        );
    }

    #[test]
    fn attach_spells_every_flag_so_a_recorded_request_is_reproducible() {
        let request = attach_request(
            "web",
            &ContainerAttachOptions {
                stream: true,
                stdin: true,
                stdout: true,
                stderr: false,
                logs: true,
                detach_keys: Some("ctrl-p,ctrl-q".to_owned()),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/containers/web/attach?stream=true&stdin=true&stdout=true&stderr=false&logs=true&detachKeys=ctrl-p%2Cctrl-q HTTP/1.1"
            )
        );
        // The attach endpoint takes no body, so the request is a bare `POST`
        // with a `Content-Length: 0`. Measured against Docker Engine 29.8.0,
        // which answers exactly that with `200` and the raw stream.
        assert_eq!(request.body.known_len(), Some(0));
    }

    #[test]
    fn an_upgrade_is_an_accepted_status_and_not_a_rejection() {
        // `101` is informational, so `is_success()` is false for it. A backend
        // that used the 2xx test would report a successful upgrade as a failure.
        use hyper::StatusCode;
        assert!(!StatusCode::SWITCHING_PROTOCOLS.is_success());
        assert!(super::is_accepted(StatusCode::SWITCHING_PROTOCOLS));
        assert!(super::is_accepted(StatusCode::OK));
        assert!(!super::is_accepted(StatusCode::NOT_FOUND));
        assert!(!super::is_accepted(StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn an_attach_keeps_both_output_streams_by_default() {
        // An attach that returns nothing because nobody set a flag is
        // indistinguishable from a container that produced no output.
        let options = ContainerAttachOptions::default();
        assert!(options.stdout && options.stderr);
        assert!(!options.stream, "streaming is a decision, not a default");
        assert!(!options.logs);
    }

    #[test]
    fn an_empty_reference_is_refused_by_every_control_operation() {
        assert_eq!(
            kill_request("", &ContainerKillOptions::default())
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            control_request("", "pause")
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            resize_request("", ContainerResizeOptions::default())
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            attach_request("", &ContainerAttachOptions::default())
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_control_request_never_streams_a_body() {
        // Every operation in this module has an empty request body, so the
        // transport sends a `Content-Length: 0` rather than chunked framing.
        for request in [
            super::pause_request("web").expect("request"),
            super::unpause_request("web").expect("request"),
            rename_request("web", "other").expect("request"),
            resize_request("web", ContainerResizeOptions::default()).expect("request"),
            attach_request("web", &ContainerAttachOptions::default()).expect("request"),
        ] {
            assert_eq!(
                request.body.known_len(),
                Some(0),
                "{}",
                request_line(&request)
            );
        }
    }
}
