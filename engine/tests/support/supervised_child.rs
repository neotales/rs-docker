//! Runs a child test worker under a wall-clock bound.
//!
//! Both plugin suites that need process-global environment state (`DOCKER_HOST`)
//! run their worker in a child. A worker that deadlocks would otherwise hang the
//! whole test run, so every path here attempts bounded cleanup:
//!
//! - the child exits in time and its status is returned;
//! - the bound is reached: termination and reaping are attempted under a second
//!   bound, then the test fails;
//! - polling the child fails: termination and reaping are attempted similarly.
//!
//! Process scheduling and uninterruptible kernel sleep cannot be bounded by a
//! userspace supervisor; failure to observe exit is reported rather than hidden
//! behind an unbounded wait. If the kernel does not report process exit in that
//! bound, the helper reports the condition; it cannot guarantee reaping in that
//! case.
#![allow(dead_code)]

use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

/// Runs `command`, waits for it up to `bound`, and reaps it.
pub(super) fn run(mut command: Command, bound: Duration) -> ExitStatus {
    let mut child = command.spawn().expect("spawn the worker");
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) if Instant::now() >= deadline => {
                let cleanup = terminate_and_reap(&mut child, Duration::from_secs(2));
                panic!("the worker exceeded its {bound:?} bound; {cleanup}");
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let cleanup = terminate_and_reap(&mut child, Duration::from_secs(2));
                panic!("could not poll the worker: {error}; {cleanup}");
            }
        }
    }
}

fn terminate_and_reap(child: &mut std::process::Child, bound: Duration) -> String {
    let kill = child.kill();
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return format!("worker terminated and reaped ({status})"),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                return format!(
                    "worker exit was not observed within {bound:?}; kill result: {}",
                    describe_kill(kill)
                );
            }
            Err(error) => {
                return format!(
                    "could not observe worker exit ({error}); kill result: {}",
                    describe_kill(kill)
                );
            }
        }
    }
}

fn describe_kill(result: std::io::Result<()>) -> String {
    match result {
        Ok(()) => "sent".to_owned(),
        Err(error) => format!("failed: {error}"),
    }
}
