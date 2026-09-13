// Copyright 2026 John Wu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Events emitted during firmware flashing and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashEvent<'a> {
    /// Partition flashing has started.
    PartitionStart {
        /// Name of the partition being flashed.
        name: &'a str,
        /// Size of the partition payload in bytes.
        size: u64,
    },
    /// Partition flashing completed successfully.
    PartitionEnd(&'a str),
    /// Partition flashing failed.
    PartitionFail(&'a str),
    /// MD5 verification for a package has started.
    Md5Start {
        /// Name of the package file being verified.
        name: &'a str,
        /// Total payload size to hash in bytes.
        size: u64,
    },
    /// MD5 verification completed successfully.
    Md5End(&'a str),
    /// MD5 verification failed.
    Md5Fail(&'a str),
}

/// A trait for reporting partition flash/upload progress and status messages.
pub trait FlashProgress: Send + Sync {
    /// Sets the total length of the progress (in bytes).
    fn set_length(&self, _len: u64) {}

    /// Increments the progress by the specified number of bytes.
    fn inc(&self, _bytes: u64) {}

    /// Prints a standard log or status message.
    fn println(&self, _msg: &str) {}

    /// Prints a verbose log or status message (implementation decides if it is shown).
    fn println_verbose(&self, _msg: &str) {}

    /// Handles a flashing or verification lifecycle event.
    fn on_event(&self, _event: FlashEvent<'_>) {}
}

impl FlashProgress for () {}

static GLOBAL_PROGRESS: std::sync::RwLock<Option<Box<dyn FlashProgress>>> =
    std::sync::RwLock::new(None);

/// Sets the global progress reporter.
pub fn set_progress(progress: impl FlashProgress + 'static) {
    let mut lock = GLOBAL_PROGRESS.write().unwrap();
    *lock = Some(Box::new(progress));
}

/// Clears the global progress reporter, reverting to no-op.
pub fn clear_progress() {
    let mut lock = GLOBAL_PROGRESS.write().unwrap();
    *lock = None;
}

/// Invokes a closure with a reference to the active global progress reporter,
/// falling back to a no-op reporter if none is configured.
pub(crate) fn with_progress<R>(f: impl FnOnce(&dyn FlashProgress) -> R) -> R {
    if let Ok(guard) = GLOBAL_PROGRESS.read()
        && let Some(p) = guard.as_deref()
    {
        return f(p);
    }
    f(&())
}

/// Sets the total length of the active progress (in bytes).
pub(crate) fn set_length(len: u64) {
    with_progress(|p| p.set_length(len));
}

/// Increments the active progress by the specified number of bytes.
pub(crate) fn inc(bytes: u64) {
    with_progress(|p| p.inc(bytes));
}

/// Prints a standard message through the active progress reporter.
pub(crate) fn println(msg: &str) {
    with_progress(|p| p.println(msg));
}

/// Prints a verbose message through the active progress reporter.
pub(crate) fn println_verbose(msg: &str) {
    with_progress(|p| p.println_verbose(msg));
}

/// Dispatches a flashing lifecycle event through the active progress reporter.
pub(crate) fn on_event(event: FlashEvent<'_>) {
    with_progress(|p| p.on_event(event));
}

#[cfg(test)]
pub(crate) static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
