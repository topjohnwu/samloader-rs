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

use std::env;

/// Declares the cfg `name` and enables it if `enabled` is true.
fn cfg_alias(name: &str, enabled: bool) {
    println!("cargo::rustc-check-cfg=cfg({name})");
    if enabled {
        println!("cargo::rustc-cfg={name}");
    }
}

fn has_feature(name: &str) -> bool {
    let name = name.to_uppercase().replace('-', "_");
    env::var_os(format!("CARGO_FEATURE_{name}")).is_some()
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    // Any backend that communicates with real hardware (i.e. not the mock backend).
    cfg_alias(
        "real_backend",
        has_feature("nusb") || has_feature("rusb") || has_feature("serialport"),
    );
}
