// Copyright 2026 John "topjohnwu" Wu
// Copyright 2010-2017 Benjamin Dobell, Glass Echidna
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

use super::AlreadyReported;
use crate::cli::VerifyMd5Args;
use crate::print_error;
use crate::progress;
use crate::readahead::ReadaheadFile;
use samloader_odin::{futures::executor::block_on, verify_md5_footer};
use std::error::Error;
use std::fs::File;

/// Verifies the MD5 footers of `.tar.md5` packages.
pub(crate) fn run(args: VerifyMd5Args) -> Result<(), Box<dyn Error>> {
    let mut success = true;
    progress::init(false);
    block_on(async {
        // Verify every file, reporting each failure as it is found
        for file_path in &args.files {
            let file = match File::open(file_path).and_then(ReadaheadFile::new) {
                Ok(f) => f,
                Err(e) => {
                    print_error!("Failed to open file \"{}\": {}", file_path, e);
                    success = false;
                    continue;
                }
            };

            if let Err(e) = verify_md5_footer(file, file_path).await {
                print_error!("MD5 verification failed for \"{}\": {}", file_path, e);
                success = false;
            }
        }
    });
    if success {
        Ok(())
    } else {
        Err(AlreadyReported.into())
    }
}
