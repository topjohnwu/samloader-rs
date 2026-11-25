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

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command as ProcessCommand};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "samloader-rs automation tasks", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build samloader-web for WebAssembly and generate JS/WASM bindings
    BuildWeb(BuildWebArgs),
    /// Run wasm-bindgen directly using wasm-bindgen-cli-support
    WasmBindgen(WasmBindgenArgs),
}

#[derive(Args, Default)]
struct BuildWebArgs {
    /// Build with release optimizations (default)
    #[arg(long, conflicts_with = "dev")]
    release: bool,

    /// Build in debug/dev profile
    #[arg(long, conflicts_with = "release")]
    dev: bool,

    /// Output directory for generated WebAssembly bindings [default: web/site/pkg]
    #[arg(long)]
    out_dir: Option<PathBuf>,

    /// Keep debug sections in WebAssembly output
    #[arg(long)]
    keep_debug: bool,

    /// Do not emit TypeScript definitions (*.d.ts)
    #[arg(long)]
    no_typescript: bool,

    /// Also stage a deployable copy of the static site (web assets and bindings) into
    /// this directory
    #[arg(long, value_name = "DIR")]
    dist: Option<PathBuf>,

    /// Additional arguments passed directly to `cargo build`
    #[arg(last = true)]
    cargo_args: Vec<String>,
}

#[derive(Args)]
struct WasmBindgenArgs {
    /// Input WebAssembly file
    input: PathBuf,

    /// Output directory for generated bindings [default: web/site/pkg]
    #[arg(long, default_value = "web/site/pkg")]
    out_dir: PathBuf,

    /// Target environment (web, nodejs, bundler, no-modules, deno) [default: web]
    #[arg(long, default_value = "web")]
    target: String,

    /// Keep debug sections in WebAssembly output
    #[arg(long)]
    keep_debug: bool,

    /// Do not emit TypeScript definitions (*.d.ts)
    #[arg(long)]
    no_typescript: bool,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask directory must have a parent")
        .to_path_buf()
}

fn target_dir(workspace_root: &Path) -> PathBuf {
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR") {
        PathBuf::from(target_dir)
    } else {
        workspace_root.join("target")
    }
}

fn run_bindgen(
    input: &Path,
    out_dir: &Path,
    target: &str,
    keep_debug: bool,
    no_typescript: bool,
) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("Failed to create output directory {}", out_dir.display()))?;

    let mut bindgen = wasm_bindgen_cli_support::Bindgen::new();
    bindgen.input_path(input);

    match target {
        "web" => {
            bindgen.web(true)?;
        }
        "nodejs" => {
            bindgen.nodejs(true)?;
        }
        "bundler" => {
            bindgen.bundler(true)?;
        }
        "no-modules" => {
            bindgen.no_modules(true)?;
        }
        "deno" => {
            bindgen.deno(true)?;
        }
        other => anyhow::bail!(
            "Unsupported target: {other}. Expected one of: web, nodejs, bundler, no-modules, deno"
        ),
    }

    bindgen.keep_debug(keep_debug);
    bindgen.typescript(!no_typescript);
    bindgen.omit_default_module_path(false);

    bindgen
        .generate(out_dir)
        .context("Failed to generate wasm-bindgen bindings")?;

    Ok(())
}

/// Static files of the web app, relative to `web/site/`, deployed alongside the bindings.
const WEB_STATIC_FILES: &[&str] = &[
    "index.html",
    "styles.css",
    "manifest.webmanifest",
    "sw.js",
    "samloader-fus-bridge.user.js",
    "favicon.svg",
    "logo.svg",
];
/// Static directories of the web app, relative to `web/site/`.
const WEB_STATIC_DIRS: &[&str] = &["app", "fonts", "icons", "ui", "workers"];

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).with_context(|| format!("Failed to create {}", dst.display()))?;
    for entry in fs::read_dir(src).with_context(|| format!("Failed to read {}", src.display()))? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target).with_context(|| {
                format!(
                    "Failed to copy {} to {}",
                    entry.path().display(),
                    target.display()
                )
            })?;
        }
    }
    Ok(())
}

/// Stages the static web app and its generated bindings into `dist`.
fn stage_dist(root: &Path, pkg_dir: &Path, dist: &Path) -> Result<()> {
    let site = root.join("web").join("site");
    fs::create_dir_all(dist).with_context(|| format!("Failed to create {}", dist.display()))?;
    for file in WEB_STATIC_FILES {
        fs::copy(site.join(file), dist.join(file))
            .with_context(|| format!("Failed to copy web/site/{file}"))?;
    }
    for dir in WEB_STATIC_DIRS {
        copy_dir(&site.join(dir), &dist.join(dir))?;
    }
    copy_dir(pkg_dir, &dist.join("pkg"))
}

fn build_web(args: BuildWebArgs) -> Result<()> {
    let root = workspace_root();
    let is_release = !args.dev;
    let profile = if is_release { "release" } else { "debug" };

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    println!("Building samloader-web for wasm32-unknown-unknown ({profile})...");

    let mut cmd = ProcessCommand::new(&cargo);
    cmd.current_dir(&root);
    cmd.args([
        "build",
        "-p",
        "samloader-web",
        "--target",
        "wasm32-unknown-unknown",
    ]);
    if is_release {
        cmd.arg("--release");
    }
    if !args.cargo_args.is_empty() {
        cmd.args(&args.cargo_args);
    }

    let status = cmd.status().context("Failed to run cargo build")?;
    if !status.success() {
        process::exit(status.code().unwrap_or(1));
    }

    let wasm_file = target_dir(&root)
        .join("wasm32-unknown-unknown")
        .join(profile)
        .join("samloader_web.wasm");

    if !wasm_file.exists() {
        anyhow::bail!(
            "Expected compiled WASM file not found at {}",
            wasm_file.display()
        );
    }

    let out_dir = args
        .out_dir
        .unwrap_or_else(|| root.join("web").join("site").join("pkg"));
    println!(
        "Generating wasm-bindgen bindings into {}...",
        out_dir.display()
    );

    run_bindgen(
        &wasm_file,
        &out_dir,
        "web",
        args.keep_debug,
        args.no_typescript,
    )?;

    if let Some(dist) = &args.dist {
        println!("Staging static site into {}...", dist.display());
        stage_dist(&root, &out_dir, dist)?;
    }

    println!("WASM build complete.");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::BuildWeb(args) => build_web(args),
        Command::WasmBindgen(args) => {
            run_bindgen(
                &args.input,
                &args.out_dir,
                &args.target,
                args.keep_debug,
                args.no_typescript,
            )?;
            println!("wasm-bindgen bindings generated successfully.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn collect_files(root: &Path, dir: &Path, out: &mut BTreeSet<String>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            if entry.file_type()?.is_dir() {
                collect_files(root, &path, out)?;
            } else {
                if name_str.ends_with(".txt") {
                    continue;
                }
                let rel = path
                    .strip_prefix(root)
                    .expect("collected path must be inside site root");
                let rel_posix = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(format!("./{rel_posix}"));
            }
        }
        Ok(())
    }

    #[test]
    fn web_static_assets_exist() {
        let site = workspace_root().join("web").join("site");
        for file in WEB_STATIC_FILES {
            assert!(
                site.join(file).is_file(),
                "missing static file web/site/{file}"
            );
        }
        for dir in WEB_STATIC_DIRS {
            assert!(site.join(dir).is_dir(), "missing static dir web/site/{dir}");
        }
    }

    #[test]
    fn sw_precaches_all_web_assets() {
        let site = workspace_root().join("web").join("site");
        let sw_source = fs::read_to_string(site.join("sw.js")).expect("read web/site/sw.js");
        let start = sw_source
            .find("const PRECACHE_URLS = [")
            .expect("PRECACHE_URLS declaration in sw.js");
        let list_body = &sw_source[start..];
        let end = list_body
            .find("];")
            .expect("closing ]; for PRECACHE_URLS in sw.js");
        let block = &list_body[..end];

        let mut precached = BTreeSet::new();
        let mut rest = block;
        while let Some(q1) = rest.find('"') {
            rest = &rest[q1 + 1..];
            let q2 = rest
                .find('"')
                .expect("unterminated string in PRECACHE_URLS");
            precached.insert(rest[..q2].to_string());
            rest = &rest[q2 + 1..];
        }

        let mut expected = BTreeSet::from([
            "./".to_string(),
            "./pkg/samloader_web.js".to_string(),
            "./pkg/samloader_web_bg.wasm".to_string(),
        ]);
        for file in WEB_STATIC_FILES {
            if *file == "sw.js" || *file == "samloader-fus-bridge.user.js" {
                continue;
            }
            expected.insert(format!("./{file}"));
        }
        for dir in WEB_STATIC_DIRS {
            collect_files(&site, &site.join(dir), &mut expected)
                .expect("collect static directory files");
        }

        let missing: Vec<_> = expected.difference(&precached).collect();
        let extra: Vec<_> = precached.difference(&expected).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "sw.js PRECACHE_URLS out of sync (missing: {missing:?}, extra: {extra:?})"
        );
    }
}
