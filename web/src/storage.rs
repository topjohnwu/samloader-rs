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

//! Browser storage adapters (OPFS `FileSystemSyncAccessHandle` and File System Access
//! `FileSystemDirectoryHandle`) plus OPFS staging manifest management.

use crate::{js_err_string, js_obj};
use futures::channel::oneshot;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    File, FileSystemCreateWritableOptions, FileSystemDirectoryHandle, FileSystemFileHandle,
    FileSystemGetDirectoryOptions, FileSystemGetFileOptions, FileSystemHandle,
    FileSystemHandleKind, FileSystemReadWriteOptions, FileSystemRemoveOptions,
    FileSystemSyncAccessHandle, FileSystemWritableFileStream, MessageChannel, StorageManager,
    WriteCommandType, WriteParams,
};

const STAGING_DIR_NAME: &str = "samloader-staging";
const MANIFEST_FILE_NAME: &str = "manifest.json";
const FILES_DIR_NAME: &str = "files";
const MOVE_PROBE_SRC: &str = ".samloader-move-probe.tmp";
const MOVE_PROBE_DST: &str = ".samloader-move-probe-dst.tmp";

#[wasm_bindgen]
extern "C" {
    type MovableFileHandle;

    #[wasm_bindgen(method, catch, js_name = move)]
    fn move_to(this: &MovableFileHandle, name: &str) -> Result<js_sys::Promise, JsValue>;
}

fn move_file_js(fh: &FileSystemFileHandle, name: &str) -> Result<js_sys::Promise, JsValue> {
    fh.unchecked_ref::<MovableFileHandle>().move_to(name)
}

// --- JS / Web File System Helpers ---

fn err_str(op: &str, err: JsValue) -> String {
    format!("{op}: {}", js_err_string(&err))
}

fn is_not_found(err: &JsValue) -> bool {
    js_sys::Reflect::get(err, &"name".into())
        .ok()
        .and_then(|v| v.as_string())
        .as_deref()
        == Some("NotFoundError")
}

fn has_method(obj: &JsValue, name: &str) -> bool {
    js_sys::Reflect::get(obj, &JsValue::from_str(name))
        .ok()
        .is_some_and(|v| v.is_instance_of::<js_sys::Function>())
}

fn get_prop_str(obj: &JsValue, key: &str) -> Option<String> {
    js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_string())
}

fn validate_filename(filename: &str) -> Result<(), String> {
    let invalid = filename.is_empty()
        || filename == "."
        || filename == ".."
        || filename.contains(['/', '\\'])
        || filename.bytes().any(|b| b <= 0x1f || b == 0x7f)
        || filename == MOVE_PROBE_SRC
        || filename == MOVE_PROBE_DST
        || filename.ends_with(".part")
        || filename.ends_with(".part.meta")
        || filename.ends_with(".part.lock");
    if invalid {
        return Err(format!("Invalid filename: {filename}"));
    }
    Ok(())
}

fn get_storage_manager() -> Option<StorageManager> {
    let global = js_sys::global();
    let nav = js_sys::Reflect::get(&global, &"navigator".into()).ok()?;
    let storage = js_sys::Reflect::get(&nav, &"storage".into()).ok()?;
    storage.dyn_into::<StorageManager>().ok()
}

async fn get_opfs_root_opt() -> Result<Option<FileSystemDirectoryHandle>, String> {
    let Some(manager) = get_storage_manager() else {
        return Ok(None);
    };
    let dir = JsFuture::from(manager.get_directory())
        .await
        .map_err(|e| err_str("navigator.storage.getDirectory()", e))?;
    Ok(Some(dir.unchecked_into()))
}

async fn get_opfs_root() -> Result<FileSystemDirectoryHandle, String> {
    get_opfs_root_opt().await?.ok_or_else(|| {
        "Origin Private File System (OPFS) is not supported in this context".to_string()
    })
}

async fn get_dir_handle(
    parent: &FileSystemDirectoryHandle,
    name: &str,
    create: bool,
) -> Result<Option<FileSystemDirectoryHandle>, String> {
    let opts = FileSystemGetDirectoryOptions::new();
    opts.set_create(create);
    match JsFuture::from(parent.get_directory_handle_with_options(name, &opts)).await {
        Ok(val) => Ok(Some(val.unchecked_into())),
        Err(err) if !create && is_not_found(&err) => Ok(None),
        Err(err) => Err(err_str(&format!("getDirectoryHandle('{name}')"), err)),
    }
}

async fn get_file_handle(
    dir: &FileSystemDirectoryHandle,
    name: &str,
    create: bool,
) -> Result<Option<FileSystemFileHandle>, String> {
    let opts = FileSystemGetFileOptions::new();
    opts.set_create(create);
    match JsFuture::from(dir.get_file_handle_with_options(name, &opts)).await {
        Ok(val) => Ok(Some(val.unchecked_into())),
        Err(err) if !create && is_not_found(&err) => Ok(None),
        Err(err) => Err(err_str(&format!("getFileHandle('{name}')"), err)),
    }
}

async fn get_file_if_exists(
    dir: &FileSystemDirectoryHandle,
    name: &str,
) -> Result<Option<File>, String> {
    let Some(fh) = get_file_handle(dir, name, false).await? else {
        return Ok(None);
    };
    let file = JsFuture::from(fh.get_file())
        .await
        .map_err(|e| err_str(&format!("getFile('{name}')"), e))?;
    Ok(Some(file.unchecked_into()))
}

async fn file_exists(dir: &FileSystemDirectoryHandle, name: &str) -> Result<bool, String> {
    Ok(get_file_handle(dir, name, false).await?.is_some())
}

async fn remove_entry_if_exists(
    dir: &FileSystemDirectoryHandle,
    name: &str,
    recursive: bool,
) -> Result<(), String> {
    let opts = FileSystemRemoveOptions::new();
    opts.set_recursive(recursive);
    match JsFuture::from(dir.remove_entry_with_options(name, &opts)).await {
        Ok(_) => Ok(()),
        Err(err) if is_not_found(&err) => Ok(()),
        Err(err) => Err(err_str(&format!("removeEntry('{name}')"), err)),
    }
}

async fn read_file_bytes(file: &File) -> Result<Vec<u8>, String> {
    let ab = JsFuture::from(file.array_buffer())
        .await
        .map_err(|e| err_str("File.arrayBuffer()", e))?;
    Ok(js_sys::Uint8Array::new(&ab).to_vec())
}

async fn create_writable(
    fh: &FileSystemFileHandle,
    keep_existing_data: bool,
) -> Result<FileSystemWritableFileStream, String> {
    let opts = FileSystemCreateWritableOptions::new();
    opts.set_keep_existing_data(keep_existing_data);
    let val = JsFuture::from(fh.create_writable_with_options(&opts))
        .await
        .map_err(|e| err_str("createWritable()", e))?;
    Ok(val.unchecked_into())
}

async fn close_writable(w: FileSystemWritableFileStream) -> Result<(), String> {
    if let Err(err) = JsFuture::from(w.close()).await {
        let _ = JsFuture::from(w.abort()).await;
        return Err(err_str("writable.close()", err));
    }
    Ok(())
}

async fn write_bytes_writable(fh: &FileSystemFileHandle, bytes: &[u8]) -> Result<(), String> {
    let w = create_writable(fh, false).await?;
    let js_arr = js_sys::Uint8Array::from(bytes);
    let write_res = match w.write_with_js_u8_array(&js_arr) {
        Ok(promise) => JsFuture::from(promise).await,
        Err(e) => Err(e),
    };
    if let Err(err) = write_res {
        let _ = JsFuture::from(w.abort()).await;
        return Err(err_str("writable.write()", err));
    }
    close_writable(w).await
}

fn write_sync_all(
    handle: &FileSystemSyncAccessHandle,
    bytes: &[u8],
    offset: u64,
) -> Result<(), String> {
    let mut pos = 0usize;
    let opts = FileSystemReadWriteOptions::new();
    while pos < bytes.len() {
        opts.set_at((offset + pos as u64) as f64);
        let written = handle
            .write_with_u8_array_and_options(&bytes[pos..], &opts)
            .map_err(|e| err_str("SyncAccessHandle.write()", e))? as usize;
        if written == 0 {
            return Err(format!(
                "Short OPFS write at offset {}",
                offset + pos as u64
            ));
        }
        pos += written;
    }
    Ok(())
}

fn read_sync_all(
    handle: &FileSystemSyncAccessHandle,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let total = handle
        .get_size()
        .map_err(|e| err_str("SyncAccessHandle.getSize()", e))? as u64;
    if offset >= total {
        return Ok(Vec::new());
    }
    let to_read = (len as u64).min(total - offset) as usize;
    let mut buf = vec![0u8; to_read];
    let mut pos = 0usize;
    let opts = FileSystemReadWriteOptions::new();
    while pos < to_read {
        opts.set_at((offset + pos as u64) as f64);
        let n = handle
            .read_with_u8_array_and_options(&mut buf[pos..], &opts)
            .map_err(|e| err_str("SyncAccessHandle.read()", e))? as usize;
        if n == 0 {
            break;
        }
        pos += n;
    }
    buf.truncate(pos);
    Ok(buf)
}

async fn probe_directory_move_support(dir: &FileSystemDirectoryHandle) -> bool {
    let _ = remove_entry_if_exists(dir, MOVE_PROBE_SRC, false).await;
    let _ = remove_entry_if_exists(dir, MOVE_PROBE_DST, false).await;

    let supported = async {
        let Some(probe) = get_file_handle(dir, MOVE_PROBE_SRC, true)
            .await
            .ok()
            .flatten()
        else {
            return false;
        };
        if !has_method(probe.as_ref(), "move") {
            return false;
        }
        match move_file_js(&probe, MOVE_PROBE_DST) {
            Ok(promise) => JsFuture::from(promise).await.is_ok(),
            Err(_) => false,
        }
    }
    .await;

    let _ = remove_entry_if_exists(dir, MOVE_PROBE_SRC, false).await;
    let _ = remove_entry_if_exists(dir, MOVE_PROBE_DST, false).await;
    supported
}

async fn move_file_replacing(
    dir: &FileSystemDirectoryHandle,
    fh: &FileSystemFileHandle,
    target_name: &str,
) -> Result<(), String> {
    let first = match move_file_js(fh, target_name) {
        Ok(p) => JsFuture::from(p).await,
        Err(e) => Err(e),
    };
    if first.is_ok() {
        return Ok(());
    }
    remove_entry_if_exists(dir, target_name, false).await?;
    let promise = move_file_js(fh, target_name).map_err(|e| err_str("FileHandle.move()", e))?;
    JsFuture::from(promise)
        .await
        .map_err(|e| err_str("FileHandle.move()", e))?;
    Ok(())
}

// --- OPFS Manifest ---

#[derive(Clone, Debug)]
pub(crate) struct OpfsFileEntry {
    pub name: String,
    pub component: Option<String>,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct OpfsBuildMeta {
    pub build_key: String,
    pub model: String,
    pub region: String,
    pub version: String,
    pub decrypted_filename: String,
    pub fingerprint_hex: String,
}

#[derive(Clone, Debug)]
struct OpfsManifest {
    meta: OpfsBuildMeta,
    complete: bool,
    files: Vec<OpfsFileEntry>,
}

impl OpfsManifest {
    fn to_js(&self, total_bytes: Option<u64>) -> JsValue {
        let files_js = js_sys::Array::new();
        for f in &self.files {
            let component = match &f.component {
                Some(c) => JsValue::from_str(c),
                None => JsValue::NULL,
            };
            files_js.push(&js_obj! {
                "name" => f.name.as_str(),
                "component" => component,
                "size" => f.size as f64,
            });
        }
        let obj = js_obj! {
            "buildKey" => self.meta.build_key.as_str(),
            "model" => self.meta.model.as_str(),
            "region" => self.meta.region.as_str(),
            "version" => self.meta.version.as_str(),
            "decryptedFilename" => self.meta.decrypted_filename.as_str(),
            "fingerprintHex" => self.meta.fingerprint_hex.as_str(),
            "complete" => self.complete,
            "files" => files_js,
        };
        if let Some(bytes) = total_bytes {
            let _ = js_sys::Reflect::set(&obj, &"totalBytes".into(), &(bytes as f64).into());
        }
        obj
    }

    fn from_json(raw: &str) -> Option<Self> {
        let val = js_sys::JSON::parse(raw).ok()?;
        if val.is_null() || !val.is_object() {
            return None;
        }
        let build_key = get_prop_str(&val, "buildKey")?;
        let complete = js_sys::Reflect::get(&val, &"complete".into())
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut files = Vec::new();
        if let Ok(arr_val) = js_sys::Reflect::get(&val, &"files".into())
            && let Ok(arr) = arr_val.dyn_into::<js_sys::Array>()
        {
            for item in arr.iter() {
                if let Some(name) = get_prop_str(&item, "name") {
                    let component = get_prop_str(&item, "component");
                    let size = js_sys::Reflect::get(&item, &"size".into())
                        .ok()
                        .and_then(|v| v.as_f64())
                        .filter(|n| n.is_finite() && *n >= 0.0)
                        .unwrap_or(0.0) as u64;
                    files.push(OpfsFileEntry {
                        name,
                        component,
                        size,
                    });
                }
            }
        }
        Some(Self {
            meta: OpfsBuildMeta {
                build_key,
                model: get_prop_str(&val, "model").unwrap_or_default(),
                region: get_prop_str(&val, "region").unwrap_or_default(),
                version: get_prop_str(&val, "version").unwrap_or_default(),
                decrypted_filename: get_prop_str(&val, "decryptedFilename").unwrap_or_default(),
                fingerprint_hex: get_prop_str(&val, "fingerprintHex").unwrap_or_default(),
            },
            complete,
            files,
        })
    }
}

async fn read_manifest(
    staging_dir: &FileSystemDirectoryHandle,
) -> Result<Option<OpfsManifest>, String> {
    let Some(file) = get_file_if_exists(staging_dir, MANIFEST_FILE_NAME).await? else {
        return Ok(None);
    };
    let bytes = read_file_bytes(&file).await?;
    let Ok(raw) = String::from_utf8(bytes) else {
        return Ok(None);
    };
    Ok(OpfsManifest::from_json(&raw))
}

async fn write_manifest(
    staging_dir: &FileSystemDirectoryHandle,
    manifest: &OpfsManifest,
) -> Result<(), String> {
    let text = js_sys::JSON::stringify(&manifest.to_js(None))
        .map_err(|e| err_str("JSON.stringify(manifest)", e))?
        .as_string()
        .ok_or_else(|| "JSON.stringify(manifest) did not return a string".to_string())?;
    let fh = get_file_handle(staging_dir, MANIFEST_FILE_NAME, true)
        .await?
        .ok_or_else(|| "Failed to create manifest file handle".to_string())?;

    if has_method(fh.as_ref(), "createSyncAccessHandle") {
        let sync_val = JsFuture::from(fh.create_sync_access_handle())
            .await
            .map_err(|e| err_str("manifest createSyncAccessHandle()", e))?;
        let sync_handle: FileSystemSyncAccessHandle = sync_val.unchecked_into();
        let res = (|| {
            sync_handle
                .truncate_with_f64(0.0)
                .map_err(|e| err_str("manifest truncate()", e))?;
            write_sync_all(&sync_handle, text.as_bytes(), 0)?;
            sync_handle
                .flush()
                .map_err(|e| err_str("manifest flush()", e))
        })();
        sync_handle.close();
        return res;
    }

    if has_method(fh.as_ref(), "createWritable") {
        return write_bytes_writable(&fh, text.as_bytes()).await;
    }

    Err("OPFS manifest write requires createSyncAccessHandle or createWritable".to_string())
}

pub(crate) async fn prepare_opfs_build(meta: &OpfsBuildMeta) -> Result<(), String> {
    if meta.build_key.is_empty() {
        return Err("prepare_opfs_build requires a non-empty buildKey".to_string());
    }
    let root = get_opfs_root().await?;
    let staging_dir = get_dir_handle(&root, STAGING_DIR_NAME, true)
        .await?
        .ok_or_else(|| "Failed to open OPFS staging directory".to_string())?;
    let existing = read_manifest(&staging_dir).await?;
    let same_build = existing
        .as_ref()
        .is_some_and(|m| m.meta.build_key == meta.build_key);

    if !same_build {
        remove_entry_if_exists(&staging_dir, FILES_DIR_NAME, true).await?;
    }
    let _ = get_dir_handle(&staging_dir, FILES_DIR_NAME, true).await?;

    let pick = |new: &str, old: Option<&str>| {
        if !new.is_empty() {
            new.to_string()
        } else {
            old.unwrap_or_default().to_string()
        }
    };
    let old_meta = existing.as_ref().map(|m| &m.meta);
    let next_manifest = OpfsManifest {
        meta: OpfsBuildMeta {
            build_key: meta.build_key.clone(),
            model: pick(&meta.model, old_meta.map(|m| m.model.as_str())),
            region: pick(&meta.region, old_meta.map(|m| m.region.as_str())),
            version: pick(&meta.version, old_meta.map(|m| m.version.as_str())),
            decrypted_filename: pick(
                &meta.decrypted_filename,
                old_meta.map(|m| m.decrypted_filename.as_str()),
            ),
            fingerprint_hex: pick(
                &meta.fingerprint_hex,
                old_meta.map(|m| m.fingerprint_hex.as_str()),
            ),
        },
        complete: false,
        files: if same_build {
            existing.map(|m| m.files).unwrap_or_default()
        } else {
            Vec::new()
        },
    };
    write_manifest(&staging_dir, &next_manifest).await
}

pub(crate) async fn mark_opfs_build_complete(
    build_key: &str,
    files: &[OpfsFileEntry],
) -> Result<(), String> {
    let root = get_opfs_root().await?;
    let staging_dir = get_dir_handle(&root, STAGING_DIR_NAME, true)
        .await?
        .ok_or_else(|| "Failed to open OPFS staging directory".to_string())?;
    let mut manifest = read_manifest(&staging_dir)
        .await?
        .filter(|m| m.meta.build_key == build_key)
        .ok_or_else(|| "OPFS staging manifest does not match buildKey".to_string())?;
    manifest.complete = true;
    manifest.files = files.to_vec();
    write_manifest(&staging_dir, &manifest).await
}

// --- Exported OPFS Cache Management API ---

/// Reads the OPFS staging manifest and sums the actual byte sizes of files in `files/`
/// (including active `.part` files). Returns `null` if OPFS is unavailable or empty.
#[wasm_bindgen]
pub async fn opfs_cache_info() -> Result<JsValue, JsValue> {
    let Some(root) = get_opfs_root_opt()
        .await
        .map_err(|e| JsValue::from_str(&e))?
    else {
        return Ok(JsValue::NULL);
    };
    let Some(staging_dir) = get_dir_handle(&root, STAGING_DIR_NAME, false)
        .await
        .map_err(|e| JsValue::from_str(&e))?
    else {
        return Ok(JsValue::NULL);
    };

    let manifest = read_manifest(&staging_dir)
        .await
        .map_err(|e| JsValue::from_str(&e))?;

    let mut total_bytes = 0u64;
    let mut has_files = false;
    if let Some(files_dir) = get_dir_handle(&staging_dir, FILES_DIR_NAME, false)
        .await
        .map_err(|e| JsValue::from_str(&e))?
    {
        let iter = files_dir.entries();
        loop {
            let promise = iter
                .next()
                .map_err(|e| JsValue::from_str(&js_err_string(&e)))?;
            let step = JsFuture::from(promise)
                .await
                .map_err(|e| JsValue::from_str(&js_err_string(&e)))?;
            if js_sys::Reflect::get(&step, &"done".into())
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
            {
                break;
            }
            let Ok(pair_val) = js_sys::Reflect::get(&step, &"value".into()) else {
                continue;
            };
            let Ok(pair) = pair_val.dyn_into::<js_sys::Array>() else {
                continue;
            };
            let Some(name) = pair.get(0).as_string() else {
                continue;
            };
            let handle: FileSystemHandle = pair.get(1).unchecked_into();
            if handle.kind() != FileSystemHandleKind::File {
                continue;
            }
            has_files = true;
            if name.ends_with(".part.meta") || name.ends_with(".part.lock") {
                continue;
            }
            let fh: FileSystemFileHandle = handle.unchecked_into();
            if let Ok(file_val) = JsFuture::from(fh.get_file()).await {
                let file: File = file_val.unchecked_into();
                total_bytes = total_bytes.saturating_add(file.size() as u64);
            }
        }
    }

    match manifest {
        Some(m) => Ok(m.to_js(Some(total_bytes))),
        None if !has_files && total_bytes == 0 => Ok(JsValue::NULL),
        None => Ok(js_obj! {
            "buildKey" => "",
            "model" => "",
            "region" => "",
            "version" => "Unindexed cached files",
            "decryptedFilename" => "",
            "fingerprintHex" => "",
            "totalBytes" => total_bytes as f64,
            "complete" => false,
            "files" => js_sys::Array::new(),
        }),
    }
}

/// Opens seekable `File` handles for every completed file in the staged OPFS build `build_key`.
#[wasm_bindgen]
pub async fn opfs_build_files(build_key: String) -> Result<JsValue, JsValue> {
    let root = get_opfs_root().await.map_err(|e| JsValue::from_str(&e))?;
    let staging_dir = get_dir_handle(&root, STAGING_DIR_NAME, false)
        .await
        .map_err(|e| JsValue::from_str(&e))?
        .ok_or_else(|| JsValue::from_str("OPFS staging directory not found"))?;
    let manifest = read_manifest(&staging_dir)
        .await
        .map_err(|e| JsValue::from_str(&e))?
        .filter(|m| m.meta.build_key == build_key)
        .ok_or_else(|| {
            JsValue::from_str("OPFS staging manifest does not match requested buildKey")
        })?;
    if !manifest.complete {
        return Err(JsValue::from_str("OPFS build is not complete"));
    }

    let files_dir = get_dir_handle(&staging_dir, FILES_DIR_NAME, false)
        .await
        .map_err(|e| JsValue::from_str(&e))?
        .ok_or_else(|| JsValue::from_str("OPFS files directory not found"))?;

    let results = js_sys::Array::new();
    for entry in &manifest.files {
        validate_filename(&entry.name).map_err(|e| JsValue::from_str(&e))?;
        let fh = get_file_handle(&files_dir, &entry.name, false)
            .await
            .map_err(|e| JsValue::from_str(&e))?
            .ok_or_else(|| JsValue::from_str(&format!("Cached file '{}' not found", entry.name)))?;
        let file: File = JsFuture::from(fh.get_file())
            .await
            .map_err(|e| JsValue::from_str(&err_str("getFile()", e)))?
            .unchecked_into();
        let component = match &entry.component {
            Some(c) => JsValue::from_str(c),
            None => JsValue::NULL,
        };
        results.push(&js_obj! {
            "name" => entry.name.as_str(),
            "component" => component,
            "file" => file,
        });
    }
    Ok(results.into())
}

/// Recursively deletes the `samloader-staging/` directory in OPFS.
#[wasm_bindgen]
pub async fn clear_opfs_cache() -> Result<(), JsValue> {
    let Some(root) = get_opfs_root_opt()
        .await
        .map_err(|e| JsValue::from_str(&e))?
    else {
        return Ok(());
    };
    remove_entry_if_exists(&root, STAGING_DIR_NAME, true)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

// --- Macrotask Yielder (prevents tight OPFS DEFLATE bursts from starving MessagePort / CANCEL) ---

struct MacrotaskYielder {
    channel: MessageChannel,
    pending: Rc<RefCell<Option<oneshot::Sender<()>>>>,
    _closure: Closure<dyn FnMut()>,
}

impl MacrotaskYielder {
    fn new() -> Result<Self, String> {
        let channel = MessageChannel::new().map_err(|e| err_str("MessageChannel::new()", e))?;
        let pending: Rc<RefCell<Option<oneshot::Sender<()>>>> = Rc::new(RefCell::new(None));
        let pending_cb = Rc::clone(&pending);
        let closure = Closure::<dyn FnMut()>::new(move || {
            if let Some(tx) = pending_cb.borrow_mut().take() {
                let _ = tx.send(());
            }
        });
        channel
            .port1()
            .set_onmessage(Some(closure.as_ref().unchecked_ref()));
        channel.port1().start();
        Ok(Self {
            channel,
            pending,
            _closure: closure,
        })
    }

    async fn yield_now(&self) {
        let (tx, rx) = oneshot::channel();
        *self.pending.borrow_mut() = Some(tx);
        if self.channel.port2().post_message(&JsValue::NULL).is_err() {
            let _ = self.pending.borrow_mut().take();
            return;
        }
        let _ = rx.await;
    }
}

impl Drop for MacrotaskYielder {
    fn drop(&mut self) {
        let _ = self.pending.borrow_mut().take();
        self.channel.port1().set_onmessage(None);
        self.channel.port1().close();
        self.channel.port2().close();
    }
}

// --- Download Storage Backends ---

pub(crate) enum DownloadTarget {
    Opfs {
        build_key: String,
        meta: OpfsBuildMeta,
    },
    Directory(FileSystemDirectoryHandle),
}

impl DownloadTarget {
    pub(crate) fn from_js(val: &JsValue) -> Result<Self, String> {
        if val.is_null() || !val.is_object() {
            return Err("Missing download storage target".to_string());
        }
        let kind = get_prop_str(val, "kind").unwrap_or_default();
        match kind.as_str() {
            "opfs" => {
                let build_key = get_prop_str(val, "buildKey")
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "OPFS storage target requires buildKey".to_string())?;
                let meta_val = js_sys::Reflect::get(val, &"meta".into())
                    .ok()
                    .filter(|v| !v.is_null() && v.is_object());
                let meta = OpfsBuildMeta {
                    build_key: build_key.clone(),
                    model: meta_val
                        .as_ref()
                        .and_then(|m| get_prop_str(m, "model"))
                        .unwrap_or_default(),
                    region: meta_val
                        .as_ref()
                        .and_then(|m| get_prop_str(m, "region"))
                        .unwrap_or_default(),
                    version: meta_val
                        .as_ref()
                        .and_then(|m| get_prop_str(m, "version"))
                        .unwrap_or_default(),
                    decrypted_filename: meta_val
                        .as_ref()
                        .and_then(|m| get_prop_str(m, "decryptedFilename"))
                        .unwrap_or_default(),
                    fingerprint_hex: meta_val
                        .as_ref()
                        .and_then(|m| get_prop_str(m, "fingerprintHex"))
                        .unwrap_or_default(),
                };
                Ok(Self::Opfs { build_key, meta })
            }
            "directory" => {
                let handle = js_sys::Reflect::get(val, &"dirHandle".into())
                    .map_err(|e| err_str("target.dirHandle", e))?
                    .dyn_into::<FileSystemDirectoryHandle>()
                    .map_err(|_| {
                        "Directory storage target requires a valid FileSystemDirectoryHandle"
                            .to_string()
                    })?;
                Ok(Self::Directory(handle))
            }
            other => Err(format!("Unsupported storage target kind: {other}")),
        }
    }
}

pub(crate) enum DownloadStorage {
    Opfs {
        files_dir: FileSystemDirectoryHandle,
        supports_move: Cell<Option<bool>>,
    },
    Directory {
        dir: FileSystemDirectoryHandle,
        supports_move: Cell<Option<bool>>,
    },
}

struct OpenedPartDir {
    dir: FileSystemDirectoryHandle,
    data_handle: FileSystemFileHandle,
    filename: String,
    meta_name: String,
    lock_name: String,
    use_move: bool,
    has_resumable_part: bool,
}

async fn dir_is_complete(
    dir: &FileSystemDirectoryHandle,
    filename: &str,
    min_size: u64,
    max_size: u64,
) -> Result<bool, String> {
    validate_filename(filename)?;
    if file_exists(dir, &format!("{filename}.part")).await?
        || file_exists(dir, &format!("{filename}.part.meta")).await?
        || file_exists(dir, &format!("{filename}.part.lock")).await?
    {
        return Ok(false);
    }
    let Some(file) = get_file_if_exists(dir, filename).await? else {
        return Ok(false);
    };
    let size = file.size() as u64;
    Ok(size >= min_size && size <= max_size)
}

async fn dir_open_part(
    dir: &FileSystemDirectoryHandle,
    supports_move: &Cell<Option<bool>>,
    filename: &str,
    force: bool,
) -> Result<OpenedPartDir, String> {
    validate_filename(filename)?;
    let part_name = format!("{filename}.part");
    let meta_name = format!("{filename}.part.meta");
    let lock_name = format!("{filename}.part.lock");

    let has_part = file_exists(dir, &part_name).await?;
    let has_lock = file_exists(dir, &lock_name).await?;

    let use_move = if !force && has_part {
        true
    } else if !force && has_lock {
        false
    } else if let Some(cached) = supports_move.get() {
        cached
    } else {
        let probed = probe_directory_move_support(dir).await;
        supports_move.set(Some(probed));
        probed
    };

    let has_resumable_part = !force && if use_move { has_part } else { has_lock };

    if force {
        remove_entry_if_exists(dir, &part_name, false).await?;
        remove_entry_if_exists(dir, &meta_name, false).await?;
        remove_entry_if_exists(dir, &lock_name, false).await?;
    } else if !has_resumable_part {
        remove_entry_if_exists(dir, &meta_name, false).await?;
    }

    if !use_move {
        let _ = get_file_handle(dir, &lock_name, true).await?;
    }

    let data_name = if use_move { &part_name } else { filename };
    let data_handle = get_file_handle(dir, data_name, true)
        .await?
        .ok_or_else(|| format!("Failed to open data file handle '{data_name}'"))?;

    Ok(OpenedPartDir {
        dir: dir.clone(),
        data_handle,
        filename: filename.to_string(),
        meta_name,
        lock_name,
        use_move,
        has_resumable_part,
    })
}

async fn finalize_part_dir(part_dir: &OpenedPartDir) -> Result<(), String> {
    if part_dir.use_move {
        move_file_replacing(&part_dir.dir, &part_dir.data_handle, &part_dir.filename).await?;
    }
    remove_entry_if_exists(&part_dir.dir, &part_dir.meta_name, false).await?;
    remove_entry_if_exists(&part_dir.dir, &part_dir.lock_name, false).await?;
    Ok(())
}

impl DownloadStorage {
    pub(crate) async fn open(target: &DownloadTarget) -> Result<Self, String> {
        match target {
            DownloadTarget::Opfs { build_key, .. } => {
                let root = get_opfs_root().await?;
                let staging_dir = get_dir_handle(&root, STAGING_DIR_NAME, true)
                    .await?
                    .ok_or_else(|| "Failed to open OPFS staging directory".to_string())?;
                let manifest = read_manifest(&staging_dir).await?;
                if !manifest
                    .as_ref()
                    .is_some_and(|m| m.meta.build_key == *build_key)
                {
                    return Err("OPFS staging manifest missing or buildKey mismatch".to_string());
                }
                let files_dir = get_dir_handle(&staging_dir, FILES_DIR_NAME, true)
                    .await?
                    .ok_or_else(|| "Failed to open OPFS files directory".to_string())?;
                Ok(Self::Opfs {
                    files_dir,
                    supports_move: Cell::new(None),
                })
            }
            DownloadTarget::Directory(dir) => Ok(Self::Directory {
                dir: dir.clone(),
                supports_move: Cell::new(None),
            }),
        }
    }

    pub(crate) async fn is_complete(
        &self,
        filename: &str,
        min_size: u64,
        max_size: u64,
    ) -> Result<bool, String> {
        match self {
            Self::Opfs { files_dir, .. } => {
                dir_is_complete(files_dir, filename, min_size, max_size).await
            }
            Self::Directory { dir, .. } => dir_is_complete(dir, filename, min_size, max_size).await,
        }
    }

    pub(crate) async fn open_part(
        &self,
        filename: &str,
        force: bool,
    ) -> Result<PartHandle, String> {
        match self {
            Self::Opfs {
                files_dir,
                supports_move,
            } => {
                let part_dir = dir_open_part(files_dir, supports_move, filename, force).await?;
                if !has_method(part_dir.data_handle.as_ref(), "createSyncAccessHandle") {
                    return Err(
                        "FileSystemFileHandle.createSyncAccessHandle() must run in a Web Worker"
                            .to_string(),
                    );
                }
                let sync_handle: FileSystemSyncAccessHandle =
                    JsFuture::from(part_dir.data_handle.create_sync_access_handle())
                        .await
                        .map_err(|e| err_str("createSyncAccessHandle()", e))?
                        .unchecked_into();

                if !part_dir.use_move
                    && !part_dir.has_resumable_part
                    && let Err(e) = (|| {
                        sync_handle
                            .truncate_with_f64(0.0)
                            .map_err(|e| err_str("OPFS truncate(0)", e))?;
                        sync_handle.flush().map_err(|e| err_str("OPFS flush()", e))
                    })()
                {
                    sync_handle.close();
                    return Err(e);
                }

                Ok(PartHandle::Opfs(OpfsPartHandle {
                    part_dir,
                    sync_handle,
                    meta_sync: None,
                    yielder: None,
                }))
            }
            Self::Directory { dir, supports_move } => {
                let part_dir = dir_open_part(dir, supports_move, filename, force).await?;
                if !part_dir.use_move && !part_dir.has_resumable_part {
                    let w = create_writable(&part_dir.data_handle, false).await?;
                    close_writable(w).await?;
                }
                Ok(PartHandle::Directory(DirectoryPartHandle {
                    part_dir,
                    writable: None,
                    pending_meta: None,
                }))
            }
        }
    }
}

pub(crate) struct OpfsPartHandle {
    part_dir: OpenedPartDir,
    sync_handle: FileSystemSyncAccessHandle,
    meta_sync: Option<FileSystemSyncAccessHandle>,
    yielder: Option<MacrotaskYielder>,
}

impl OpfsPartHandle {
    fn close_meta_sync(&mut self) {
        if let Some(active) = self.meta_sync.take() {
            active.close();
        }
    }
}

pub(crate) struct DirectoryPartHandle {
    part_dir: OpenedPartDir,
    writable: Option<FileSystemWritableFileStream>,
    pending_meta: Option<Vec<u8>>,
}

impl DirectoryPartHandle {
    async fn ensure_writable(&mut self) -> Result<&FileSystemWritableFileStream, String> {
        if self.writable.is_none() {
            self.writable = Some(create_writable(&self.part_dir.data_handle, true).await?);
        }
        Ok(self.writable.as_ref().expect("writable just initialized"))
    }

    async fn flush_writable(&mut self) -> Result<(), String> {
        if let Some(active) = self.writable.take() {
            close_writable(active).await?;
        }
        Ok(())
    }
}

pub(crate) enum PartHandle {
    Opfs(OpfsPartHandle),
    Directory(DirectoryPartHandle),
}

impl PartHandle {
    pub(crate) async fn size(&mut self) -> Result<u64, String> {
        match self {
            Self::Opfs(h) => Ok(h
                .sync_handle
                .get_size()
                .map_err(|e| err_str("SyncAccessHandle.getSize()", e))?
                as u64),
            Self::Directory(h) => {
                h.flush_writable().await?;
                let file: File = JsFuture::from(h.part_dir.data_handle.get_file())
                    .await
                    .map_err(|e| err_str("getFile()", e))?
                    .unchecked_into();
                Ok(file.size() as u64)
            }
        }
    }

    pub(crate) async fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, String> {
        match self {
            Self::Opfs(h) => read_sync_all(&h.sync_handle, offset, len),
            Self::Directory(h) => {
                h.flush_writable().await?;
                if len == 0 {
                    return Ok(Vec::new());
                }
                let file: File = JsFuture::from(h.part_dir.data_handle.get_file())
                    .await
                    .map_err(|e| err_str("getFile()", e))?
                    .unchecked_into();
                let total = file.size() as u64;
                if offset >= total {
                    return Ok(Vec::new());
                }
                let end = total.min(offset.saturating_add(len as u64));
                let slice = file
                    .slice_with_f64_and_f64(offset as f64, end as f64)
                    .map_err(|e| err_str("File.slice()", e))?;
                let ab = JsFuture::from(slice.array_buffer())
                    .await
                    .map_err(|e| err_str("Blob.arrayBuffer()", e))?;
                Ok(js_sys::Uint8Array::new(&ab).to_vec())
            }
        }
    }

    pub(crate) async fn read_meta(&mut self) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::Opfs(h) => {
                if let Some(meta_sync) = &h.meta_sync {
                    let total = meta_sync
                        .get_size()
                        .map_err(|e| err_str("meta getSize()", e))?
                        as usize;
                    return Ok(Some(read_sync_all(meta_sync, 0, total)?));
                }
                let Some(file) = get_file_if_exists(&h.part_dir.dir, &h.part_dir.meta_name).await?
                else {
                    return Ok(None);
                };
                Ok(Some(read_file_bytes(&file).await?))
            }
            Self::Directory(h) => {
                if let Some(pending) = &h.pending_meta {
                    return Ok(Some(pending.clone()));
                }
                let Some(file) = get_file_if_exists(&h.part_dir.dir, &h.part_dir.meta_name).await?
                else {
                    return Ok(None);
                };
                Ok(Some(read_file_bytes(&file).await?))
            }
        }
    }

    pub(crate) async fn truncate(&mut self, new_size: u64) -> Result<(), String> {
        match self {
            Self::Opfs(h) => {
                h.sync_handle
                    .truncate_with_f64(new_size as f64)
                    .map_err(|e| err_str("SyncAccessHandle.truncate()", e))?;
                if new_size == 0 {
                    h.close_meta_sync();
                    remove_entry_if_exists(&h.part_dir.dir, &h.part_dir.meta_name, false).await?;
                }
                Ok(())
            }
            Self::Directory(h) => {
                h.pending_meta = None;
                h.flush_writable().await?;
                let w = create_writable(&h.part_dir.data_handle, new_size > 0).await?;
                let res = match w.truncate_with_f64(new_size as f64) {
                    Ok(p) => JsFuture::from(p).await,
                    Err(e) => Err(e),
                };
                if let Err(err) = res {
                    let _ = JsFuture::from(w.abort()).await;
                    return Err(err_str("writable.truncate()", err));
                }
                close_writable(w).await?;
                if new_size == 0 {
                    remove_entry_if_exists(&h.part_dir.dir, &h.part_dir.meta_name, false).await?;
                }
                Ok(())
            }
        }
    }

    pub(crate) async fn write(&mut self, offset: u64, chunk: &[u8]) -> Result<(), String> {
        if chunk.is_empty() {
            return Ok(());
        }
        match self {
            Self::Opfs(h) => {
                // Zero-copy write directly from WASM linear memory into OPFS SyncAccessHandle.
                write_sync_all(&h.sync_handle, chunk, offset)?;
                // Yield a 0ms macrotask so tight DEFLATE bursts never starve incoming FUS
                // MessagePort chunks or CANCEL messages in download_worker.js.
                if h.yielder.is_none() {
                    h.yielder = Some(MacrotaskYielder::new()?);
                }
                if let Some(yielder) = &h.yielder {
                    yielder.yield_now().await;
                }
                Ok(())
            }
            Self::Directory(h) => {
                let active = h.ensure_writable().await?;
                write_positioned_writable(active, offset, chunk).await
            }
        }
    }

    pub(crate) async fn save_meta(&mut self, meta_bytes: &[u8]) -> Result<(), String> {
        match self {
            Self::Opfs(h) => {
                let verbose = crate::progress::is_verbose();
                let start_ms = if verbose { js_sys::Date::now() } else { 0.0 };
                // Flush data blocks before advancing the persisted checkpoint sidecar.
                h.sync_handle
                    .flush()
                    .map_err(|e| err_str("OPFS data flush()", e))?;
                if h.meta_sync.is_none() {
                    let meta_fh = get_file_handle(&h.part_dir.dir, &h.part_dir.meta_name, true)
                        .await?
                        .ok_or_else(|| {
                            "Failed to open OPFS checkpoint metadata file".to_string()
                        })?;
                    let meta_sync: FileSystemSyncAccessHandle =
                        JsFuture::from(meta_fh.create_sync_access_handle())
                            .await
                            .map_err(|e| err_str("meta createSyncAccessHandle()", e))?
                            .unchecked_into();
                    h.meta_sync = Some(meta_sync);
                }
                let meta_sync = h.meta_sync.as_ref().expect("meta_sync initialized");
                meta_sync
                    .truncate_with_f64(0.0)
                    .map_err(|e| err_str("meta truncate(0)", e))?;
                write_sync_all(meta_sync, meta_bytes, 0)?;
                meta_sync.flush().map_err(|e| err_str("meta flush()", e))?;
                if verbose {
                    let elapsed = js_sys::Date::now() - start_ms;
                    if elapsed >= 200.0 {
                        crate::progress::append_log(&format!(
                            "[Writer] OPFS checkpoint flush took {}ms",
                            elapsed.round() as u64
                        ));
                    }
                }
                Ok(())
            }
            Self::Directory(h) => {
                // FileSystemWritableFileStream writes to a .crswap file; closing & reopening
                // mid-transfer forces Chromium to copy the entire .part file into a new .crswap,
                // causing multi-second stalls on multi-GB files. Keep the stream open and commit
                // the latest checkpoint atomically in close() on cancellation/error.
                h.pending_meta = Some(meta_bytes.to_vec());
                Ok(())
            }
        }
    }

    pub(crate) async fn finalize(self) -> Result<(), String> {
        match self {
            Self::Opfs(mut h) => {
                h.yielder = None;
                h.close_meta_sync();
                let flush_res = h
                    .sync_handle
                    .flush()
                    .map_err(|e| err_str("OPFS finalize flush()", e));
                h.sync_handle.close();
                flush_res?;
                finalize_part_dir(&h.part_dir).await
            }
            Self::Directory(mut h) => {
                h.pending_meta = None;
                h.flush_writable().await?;
                finalize_part_dir(&h.part_dir).await
            }
        }
    }

    pub(crate) async fn close(self) {
        match self {
            Self::Opfs(mut h) => {
                h.yielder = None;
                let _ = h.sync_handle.flush();
                h.close_meta_sync();
                h.sync_handle.close();
            }
            Self::Directory(mut h) => {
                let flushed = h.flush_writable().await.is_ok();
                if flushed
                    && let Some(meta) = h.pending_meta.take()
                    && let Ok(Some(mh)) =
                        get_file_handle(&h.part_dir.dir, &h.part_dir.meta_name, true).await
                {
                    let _ = write_bytes_writable(&mh, &meta).await;
                }
            }
        }
    }
}

async fn write_positioned_writable(
    w: &FileSystemWritableFileStream,
    offset: u64,
    chunk: &[u8],
) -> Result<(), String> {
    // Copy into a JS-owned Uint8Array so WASM memory views never outlive `.await`.
    let js_arr = js_sys::Uint8Array::from(chunk);
    let params = WriteParams::new(WriteCommandType::Write);
    params.set_position_opt_f64(Some(offset as f64));
    params.set_data_opt_u8_array(Some(&js_arr));
    let promise = w
        .write_with_write_params(&params)
        .map_err(|e| err_str("writable.write()", e))?;
    JsFuture::from(promise)
        .await
        .map_err(|e| err_str("writable.write()", e))?;
    Ok(())
}
