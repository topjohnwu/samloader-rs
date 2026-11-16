// Copyright 2026 John "topjohnwu" Wu
// Copyright 2021-2024 Henrik Grimler
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

use crate::cli::CheckUpdateArgs;
use samloader_fus::fetch_history;
use std::error::Error;

/// Prints the firmware versions available for a model and region.
pub(crate) fn run(args: CheckUpdateArgs) -> Result<(), Box<dyn Error>> {
    let info =
        fetch_history(&args.fus.model, &args.fus.region).expect("Failed to fetch version info");

    if args.all {
        println!("Latest Stable Version:");
        println!("{}", info.latest);

        if !info.previous.is_empty() {
            println!();
            println!("Previous Stable Versions (sorted from new to old):");
            for v in &info.previous {
                println!("{}", v);
            }
        }

        if !info.beta.is_empty() {
            println!();
            println!("Beta Versions (sorted from new to old):");
            for v in &info.beta {
                println!("{}", v);
            }
        }
    } else {
        println!("{}", info.latest);
    }
    Ok(())
}
