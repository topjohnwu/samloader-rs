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

    /// Output directory for generated WebAssembly bindings [default: web/pkg]
    #[arg(long)]
    out_dir: Option<PathBuf>,

    /// Keep debug sections in WebAssembly output
    #[arg(long)]
    keep_debug: bool,

    /// Do not emit TypeScript definitions (*.d.ts)
    #[arg(long)]
    no_typescript: bool,

    /// Additional arguments passed directly to `cargo build`
    #[arg(last = true)]
    cargo_args: Vec<String>,
}

#[derive(Args)]
struct WasmBindgenArgs {
    /// Input WebAssembly file
    input: PathBuf,

    /// Output directory for generated bindings [default: web/pkg]
    #[arg(long, default_value = "web/pkg")]
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

    bindgen
        .generate(out_dir)
        .context("Failed to generate wasm-bindgen bindings")?;

    Ok(())
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

    let out_dir = args.out_dir.unwrap_or_else(|| root.join("web").join("pkg"));
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
