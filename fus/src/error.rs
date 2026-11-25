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
#[non_exhaustive]
pub enum Error {
    /// An HTTP transport or status error occurred while communicating with the FUS server.
    #[error(transparent)]
    Http(#[from] HttpError),

    /// The FUS server returned a non-success status code in its XML response.
    #[error("FUS server error status: {status}")]
    ServerStatus {
        /// The status string returned in `<Results><Status>`.
        status: String,
    },

    /// No firmware was found on FUS for the requested model and region.
    #[error("No firmware found for {model} ({region}); check the model number and region/CSC code")]
    FirmwareNotFound {
        /// The requested device model.
        model: String,
        /// The requested region / CSC code.
        region: String,
    },

    /// The server returned malformed XML or was missing expected metadata.
    #[error("Invalid server response: {0}")]
    InvalidResponse(String),

    /// The firmware archive is malformed or uses an unsupported ZIP feature.
    #[error("Invalid firmware archive: {0}")]
    InvalidArchive(String),

    /// An I/O error occurred while reading from a [`DataSource`](crate::DataSource).
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// An error from the underlying HTTP transport or an unexpected HTTP status code.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpError {
    /// The server returned an unexpected HTTP status code.
    #[error("HTTP status {0}")]
    Status(u16),

    /// The underlying HTTP client backend reported an error.
    #[error(transparent)]
    Backend(Box<dyn std::error::Error + Send + Sync>),
}

impl HttpError {
    /// Wraps a backend-specific HTTP transport error.
    pub fn backend(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Backend(Box::new(err))
    }
}

/// A specialized Result type for samloader-fus operations.
pub type Result<T> = std::result::Result<T, Error>;
