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
