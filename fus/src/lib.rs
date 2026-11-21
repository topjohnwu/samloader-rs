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

//! Crate for interacting with Samsung Firmware Update Server (FUS) to query
//! and download device firmware binaries.

#![deny(missing_docs)]

mod auth;
#[doc(hidden)]
pub mod compat;
mod data;
mod decoder;
mod decrypt;
mod error;
mod fusclient;
mod http;
mod parallel;
mod stream;
#[cfg(test)]
mod test_util;
mod xml;
mod zip;

// General-purpose data & streaming building blocks
pub use data::DataSource;
pub use parallel::{ParallelDataSource, TransferObserver, TransferWarning};
pub use stream::{Checkpoint, DataStream, OffsetCheckpoint, ResumableAsyncRead, ResumableStream};

// Domain implementers
pub use decoder::ZipCheckpoint;
pub use error::{Error, HttpError, Result};
pub use fusclient::{DownloadSession, FusClient, fetch_history};
pub use xml::{BinaryInform, VersionInfo};
pub use zip::{ZipArchive, ZipEntry, ZipEntryStream};

// Re-export public dependencies to avoid type mismatch and SemVer issues in public APIs.
pub use binrw;
pub use futures;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
