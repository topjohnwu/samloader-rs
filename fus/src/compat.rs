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
#[cfg(not(target_arch = "wasm32"))]
use std::pin::Pin;
use std::task::Context;
#[cfg(not(target_arch = "wasm32"))]
use std::task::Poll;
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

/// Cross-target async timer future backed by `tokio::time` on native targets
/// and `futures-timer` on WebAssembly.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct Sleep(Option<Pin<Box<tokio::time::Sleep>>>);

#[cfg(not(target_arch = "wasm32"))]
impl Sleep {
    pub(crate) fn new(duration: Duration) -> Self {
        // Skip creating a Tokio timer for zero-length delays so unit tests using
        // `futures::executor::block_on` do not require an active Tokio reactor.
        Self((!duration.is_zero()).then(|| Box::pin(tokio::time::sleep(duration))))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(sleep) = &mut self.0 {
            std::task::ready!(sleep.as_mut().poll(cx));
            self.0 = None;
        }
        Poll::Ready(())
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use futures_timer::Delay as Sleep;

pub(crate) fn sleep(duration: Duration) -> Sleep {
    Sleep::new(duration)
}

/// Cross-target background worker set that spawns onto Tokio on native runtimes
/// (falling back to inline polling when no Tokio runtime is active, e.g. `block_on`
/// unit tests) and onto the local microtask queue via `spawn_local` on WebAssembly,
/// aborting all live tasks automatically on drop.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) enum WorkerSet {
    Tokio {
        rt: tokio::runtime::Handle,
        handles: Vec<tokio::task::AbortHandle>,
    },
    Inline(futures::stream::FuturesUnordered<futures::future::BoxFuture<'static, ()>>),
}

#[cfg(not(target_arch = "wasm32"))]
impl WorkerSet {
    pub(crate) fn new(capacity: usize) -> Self {
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => Self::Tokio {
                rt,
                handles: Vec::with_capacity(capacity),
            },
            Err(_) => Self::Inline(futures::stream::FuturesUnordered::new()),
        }
    }

    pub(crate) fn empty() -> Self {
        Self::Inline(futures::stream::FuturesUnordered::new())
    }

    pub(crate) fn spawn(&mut self, fut: impl Future<Output = ()> + MaybeSend + 'static) {
        match self {
            Self::Tokio { rt, handles } => {
                handles.push(rt.spawn(fut).abort_handle());
            }
            Self::Inline(futures) => {
                futures.push(Box::pin(fut));
            }
        }
    }

    pub(crate) fn poll_inline(&mut self, cx: &mut Context<'_>) {
        if let Self::Inline(futures) = self {
            use futures::stream::StreamExt;
            while let Poll::Ready(Some(())) = futures.poll_next_unpin(cx) {}
        }
    }

    pub(crate) fn abort_all(&mut self) {
        match self {
            Self::Tokio { handles, .. } => {
                for h in handles.drain(..) {
                    h.abort();
                }
            }
            Self::Inline(futures) => {
                futures.clear();
            }
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

    pub(crate) fn poll_inline(&mut self, _cx: &mut Context<'_>) {}

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
