// Copyright 2026 John "topjohnwu" Wu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Helpers that abstract over differences between native and WASM targets.

use std::future::Future;
use std::time::Duration;

mod sealed {
    pub trait SendSealed {}
    #[cfg(not(target_arch = "wasm32"))]
    impl<T: ?Sized + Send> SendSealed for T {}
    #[cfg(target_arch = "wasm32")]
    impl<T: ?Sized> SendSealed for T {}

    pub trait SyncSealed {}
    #[cfg(not(target_arch = "wasm32"))]
    impl<T: ?Sized + Sync> SyncSealed for T {}
    #[cfg(target_arch = "wasm32")]
    impl<T: ?Sized> SyncSealed for T {}
}

/// Helper trait representing `Send` on non-WASM targets and unbounded on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: sealed::SendSealed + Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: ?Sized + Send> MaybeSend for T {}

/// Helper trait representing `Send` on non-WASM targets and unbounded on WASM.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend: sealed::SendSealed {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// Helper trait representing `Sync` on non-WASM targets and unbounded on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: sealed::SyncSealed + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: ?Sized + Sync> MaybeSync for T {}

/// Helper trait representing `Sync` on non-WASM targets and unbounded on WASM.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync: sealed::SyncSealed {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn sleep(duration: Duration) -> tokio::time::Sleep {
    tokio::time::sleep(duration)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn sleep(duration: Duration) -> futures_timer::Delay {
    futures_timer::Delay::new(duration)
}

/// Cross-target background worker set that spawns onto the active Tokio runtime
/// on native targets and onto the local microtask queue via `spawn_local` on
/// WebAssembly, aborting all live tasks automatically on drop.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct WorkerSet {
    handles: Vec<tokio::task::AbortHandle>,
}

#[cfg(not(target_arch = "wasm32"))]
impl WorkerSet {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            handles: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    pub(crate) fn spawn(&mut self, fut: impl Future<Output = ()> + MaybeSend + 'static) {
        self.handles.push(tokio::spawn(fut).abort_handle());
    }

    pub(crate) fn abort_all(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) struct WorkerSet {
    handles: Vec<futures::future::AbortHandle>,
}

#[cfg(target_arch = "wasm32")]
impl WorkerSet {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            handles: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    pub(crate) fn spawn(&mut self, fut: impl Future<Output = ()> + MaybeSend + 'static) {
        let (abortable, handle) = futures::future::abortable(fut);
        self.handles.push(handle);
        wasm_bindgen_futures::spawn_local(async move {
            let _ = abortable.await;
        });
    }

    pub(crate) fn abort_all(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
        }
    }
}

impl Drop for WorkerSet {
    fn drop(&mut self) {
        self.abort_all();
    }
}
