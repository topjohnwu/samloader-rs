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

//! Error types for samloader-fus.

use thiserror::Error;

/// Error types for samloader-fus.
#[derive(Debug, Error)]
pub enum Error {
    /// A network error occurred while communicating with the FUS server.
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// The FUS server returned a non-success status code in its XML response.
    #[error("FUS server error status: {status}")]
    ServerStatus {
        /// The status string returned in `<Results><Status>`.
        status: String,
    },

    /// The server returned malformed XML or was missing expected metadata.
    #[error("Invalid server response: {0}")]
    InvalidResponse(String),
}

/// A specialized Result type for samloader-fus operations.
pub type Result<T> = std::result::Result<T, Error>;
