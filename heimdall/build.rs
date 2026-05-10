// Copyright 2026 Google LLC
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

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn try_compile(build: &cc::Build, code: &str, extra_flags: &[&str]) -> bool {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let test_file = out_dir.join("test.cpp");
    std::fs::write(&test_file, code).unwrap();

    let mut cmd = build.get_compiler().to_command();

    // The compiler command from cc might already have some flags.
    // We want to add -c and -o.
    cmd.arg("-c")
        .arg(&test_file)
        .arg("-o")
        .arg(out_dir.join("test.o"));

    for flag in extra_flags {
        cmd.arg(flag);
    }

    // Suppress output
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());

    cmd.status().map(|s| s.success()).unwrap_or(false)
}

fn check_lfs(build: &mut cc::Build) {
    let test_code = r#"
        #include <sys/types.h>
        typedef char my_static_assert[sizeof(off_t) >= 8 ? 1 : -1];
        int main(void) { return 0; }
    "#;

    if try_compile(build, test_code, &[]) {
        return;
    }

    // Try getconf
    let mut extra_flags = Vec::new();
    if let Ok(output) = Command::new("getconf").arg("LFS_CFLAGS").output() {
        let flags_raw = String::from_utf8_lossy(&output.stdout);
        extra_flags.extend(flags_raw.split_whitespace().map(|s| s.to_string()));
    }

    if !extra_flags.is_empty()
        && try_compile(
            build,
            test_code,
            &extra_flags.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        )
    {
        for flag in extra_flags {
            if flag.starts_with("-D") {
                let part = &flag[2..];
                if let Some(pos) = part.find('=') {
                    build.define(&part[..pos], Some(&part[pos + 1..]));
                } else {
                    build.define(part, None);
                }
            } else {
                build.flag(&flag);
            }
        }

        if let Ok(output) = Command::new("getconf").arg("LFS_LIBS").output() {
            let libs_raw = String::from_utf8_lossy(&output.stdout);
            for lib in libs_raw.split_whitespace() {
                if lib.starts_with("-l") {
                    println!("cargo:rustc-link-lib={}", &lib[2..]);
                }
            }
        }

        if let Ok(output) = Command::new("getconf").arg("LFS_LDFLAGS").output() {
            let ldflags_raw = String::from_utf8_lossy(&output.stdout);
            for flag in ldflags_raw.split_whitespace() {
                if flag.starts_with("-L") {
                    println!("cargo:rustc-link-search=native={}", &flag[2..]);
                }
            }
        }
        return;
    }

    if try_compile(build, test_code, &["-D_FILE_OFFSET_BITS=64"]) {
        build.define("_FILE_OFFSET_BITS", Some("64"));
        return;
    }

    if try_compile(build, test_code, &["-D_LARGE_FILES=1"]) {
        build.define("_LARGE_FILES", Some("1"));
        return;
    }
}

fn check_fseeko(build: &mut cc::Build) {
    let test_code = r#"
        #include <stdio.h>
        int main(void) { fseeko(NULL, 0, 0); return 0; }
    "#;

    if try_compile(build, test_code, &[]) {
        return;
    }

    if try_compile(build, test_code, &["-D_LARGEFILE_SOURCE"]) {
        build.define("_LARGEFILE_SOURCE", None);
        return;
    }
}

fn main() {
    let mut build = cxx_build::bridges(["src/bridge.rs", "../libpit/src/lib.rs"]);
    build.cpp(true);
    build.std("c++11");

    // Source files
    let sources = [
        "source/Arguments.cpp",
        "source/BridgeManager.cpp",
        "source/ClosePcScreenAction.cpp",
        "source/DetectAction.cpp",
        "source/DownloadPitAction.cpp",
        "source/FlashAction.cpp",
        "source/HelpAction.cpp",
        "source/InfoAction.cpp",
        "source/Interface.cpp",
        "source/main.cpp",
        "source/PrintPitAction.cpp",
        "source/Utility.cpp",
        "source/VersionAction.cpp",
    ];

    for source in &sources {
        build.file(source);
    }

    build.include("source");
    build.include("../libpit/src");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_os == "linux" {
        build.define("OS_LINUX", None);
    }

    if target_os == "macos" {
        println!("cargo:rustc-link-lib=objc");
        println!("cargo:rustc-link-lib=framework=IOKit");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }

    // libusb
    match pkg_config::Config::new()
        .atleast_version("1.0")
        .probe("libusb-1.0")
    {
        Ok(lib) => {
            for path in lib.include_paths {
                build.include(path);
            }
        }
        Err(e) => {
            panic!("Could not find libusb-1.0: {}", e);
        }
    }

    // LFS and Fseeko
    if target_os != "windows" {
        check_lfs(&mut build);
        check_fseeko(&mut build);
    }

    build.compile("heimdall_cpp");

    for source in &sources {
        println!("cargo:rerun-if-changed={}", source);
    }
    println!("cargo:rerun-if-changed=source/Heimdall.h");
}
