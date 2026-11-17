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
pub(crate) struct Sleep(Option<std::pin::Pin<Box<tokio::time::Sleep>>>);

#[cfg(not(target_arch = "wasm32"))]
impl Sleep {
    pub(crate) fn new(duration: std::time::Duration) -> Self {
        // Skip registering a Tokio timer for zero-length test delays so unit
        // tests using `futures::executor::block_on` do not require a Tokio reactor.
        Self((!duration.is_zero()).then(|| Box::pin(tokio::time::sleep(duration))))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl std::future::Future for Sleep {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if let Some(sleep) = &mut self.0 {
            std::task::ready!(sleep.as_mut().poll(cx));
            self.0 = None;
        }
        std::task::Poll::Ready(())
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use futures_timer::Delay as Sleep;

/// Sleeps for `duration`.
pub(crate) fn sleep(duration: std::time::Duration) -> Sleep {
    Sleep::new(duration)
}
