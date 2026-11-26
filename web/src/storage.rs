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
//! `FileSystemDirectoryHandle`).

use crate::js_err_string;
use futures::channel::oneshot;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    File, FileSystemCreateWritableOptions, FileSystemDirectoryHandle, FileSystemFileHandle,
    FileSystemGetFileOptions, FileSystemReadWriteOptions, FileSystemRemoveOptions,
    FileSystemSyncAccessHandle, FileSystemWritableFileStream, MessageChannel, WriteCommandType,
    WriteParams,
};

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
        || filename.ends_with(".part")
        || filename.ends_with(".part.meta");
    if invalid {
        return Err(format!("Invalid filename: {filename}"));
    }
    Ok(())
}

async fn get_file_opt(
    dir: &FileSystemDirectoryHandle,
    name: &str,
) -> Result<Option<FileSystemFileHandle>, String> {
    let opts = FileSystemGetFileOptions::new();
    opts.set_create(false);
    match JsFuture::from(dir.get_file_handle_with_options(name, &opts)).await {
        Ok(val) => Ok(Some(val.unchecked_into())),
        Err(err) if is_not_found(&err) => Ok(None),
        Err(err) => Err(err_str(&format!("getFileHandle('{name}')"), err)),
    }
}

async fn ensure_file(
    dir: &FileSystemDirectoryHandle,
    name: &str,
) -> Result<FileSystemFileHandle, String> {
    let opts = FileSystemGetFileOptions::new();
    opts.set_create(true);
    let val = JsFuture::from(dir.get_file_handle_with_options(name, &opts))
        .await
        .map_err(|e| err_str(&format!("getFileHandle('{name}')"), e))?;
    Ok(val.unchecked_into())
}

async fn get_file_if_exists(
    dir: &FileSystemDirectoryHandle,
    name: &str,
) -> Result<Option<File>, String> {
    let Some(fh) = get_file_opt(dir, name).await? else {
        return Ok(None);
    };
    let file = JsFuture::from(fh.get_file())
        .await
        .map_err(|e| err_str(&format!("getFile('{name}')"), e))?;
    Ok(Some(file.unchecked_into()))
}

async fn file_exists(dir: &FileSystemDirectoryHandle, name: &str) -> Result<bool, String> {
    Ok(get_file_opt(dir, name).await?.is_some())
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

async fn abort_writable(w: FileSystemWritableFileStream) {
    let _ = JsFuture::from(w.abort()).await;
}

async fn close_writable(w: FileSystemWritableFileStream) -> Result<(), String> {
    if let Err(err) = JsFuture::from(w.close()).await {
        abort_writable(w).await;
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
        abort_writable(w).await;
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
    Opfs(FileSystemDirectoryHandle),
    Directory(FileSystemDirectoryHandle),
}

impl DownloadTarget {
    pub(crate) fn from_js(val: &JsValue) -> Result<Self, String> {
        if val.is_null() || !val.is_object() {
            return Err("Missing download storage target".to_string());
        }
        let kind = get_prop_str(val, "kind").unwrap_or_default();
        let handle = js_sys::Reflect::get(val, &"dirHandle".into())
            .map_err(|e| err_str("target.dirHandle", e))?
            .dyn_into::<FileSystemDirectoryHandle>()
            .map_err(|_| "Storage target requires a valid FileSystemDirectoryHandle".to_string())?;
        match kind.as_str() {
            "opfs" => Ok(Self::Opfs(handle)),
            "directory" => Ok(Self::Directory(handle)),
            other => Err(format!("Unsupported storage target kind: {other}")),
        }
    }
}

pub(crate) enum DownloadStorage {
    Opfs(FileSystemDirectoryHandle),
    Directory(FileSystemDirectoryHandle),
}

struct OpenedPartDir {
    dir: FileSystemDirectoryHandle,
    data_handle: FileSystemFileHandle,
    filename: String,
    meta_name: String,
}

async fn dir_is_complete(
    dir: &FileSystemDirectoryHandle,
    filename: &str,
    min_size: u64,
    max_size: u64,
    uses_part_file: bool,
) -> Result<Option<u64>, String> {
    validate_filename(filename)?;
    if (uses_part_file && file_exists(dir, &format!("{filename}.part")).await?)
        || file_exists(dir, &format!("{filename}.part.meta")).await?
    {
        return Ok(None);
    }
    let Some(file) = get_file_if_exists(dir, filename).await? else {
        return Ok(None);
    };
    let size = file.size() as u64;
    Ok((size >= min_size && size <= max_size).then_some(size))
}

async fn dir_open_part(
    dir: &FileSystemDirectoryHandle,
    filename: &str,
    force: bool,
    uses_part_file: bool,
) -> Result<(OpenedPartDir, bool), String> {
    validate_filename(filename)?;
    let data_name = if uses_part_file {
        format!("{filename}.part")
    } else {
        filename.to_string()
    };
    let meta_name = format!("{filename}.part.meta");

    let had_prior_file = if force {
        remove_entry_if_exists(dir, &data_name, false).await?;
        remove_entry_if_exists(dir, &meta_name, false).await?;
        false
    } else {
        let existed = file_exists(dir, &data_name).await?;
        if !existed {
            remove_entry_if_exists(dir, &meta_name, false).await?;
        }
        existed
    };

    let data_handle = ensure_file(dir, &data_name).await?;

    Ok((
        OpenedPartDir {
            dir: dir.clone(),
            data_handle,
            filename: filename.to_string(),
            meta_name,
        },
        had_prior_file,
    ))
}

async fn finalize_opfs_part(part_dir: &OpenedPartDir) -> Result<(), String> {
    move_file_replacing(&part_dir.dir, &part_dir.data_handle, &part_dir.filename).await?;
    remove_entry_if_exists(&part_dir.dir, &part_dir.meta_name, false).await?;
    Ok(())
}

impl DownloadStorage {
    pub(crate) fn open(target: &DownloadTarget) -> Self {
        match target {
            DownloadTarget::Opfs(dir) => Self::Opfs(dir.clone()),
            DownloadTarget::Directory(dir) => Self::Directory(dir.clone()),
        }
    }

    pub(crate) async fn is_complete(
        &self,
        filename: &str,
        min_size: u64,
        max_size: u64,
    ) -> Result<Option<u64>, String> {
        match self {
            Self::Opfs(dir) => dir_is_complete(dir, filename, min_size, max_size, true).await,
            Self::Directory(dir) => dir_is_complete(dir, filename, min_size, max_size, false).await,
        }
    }

    pub(crate) async fn open_part(
        &self,
        filename: &str,
        force: bool,
    ) -> Result<PartHandle, String> {
        match self {
            Self::Opfs(files_dir) => {
                let (part_dir, _) = dir_open_part(files_dir, filename, force, true).await?;
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

                Ok(PartHandle::Opfs(OpfsPartHandle {
                    part_dir,
                    sync_handle,
                    meta_sync: None,
                    yielder: None,
                }))
            }
            Self::Directory(dir) => {
                let (part_dir, had_prior_file) = dir_open_part(dir, filename, force, false).await?;
                Ok(PartHandle::Directory(DirectoryPartHandle {
                    part_dir,
                    had_prior_file,
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
    had_prior_file: bool,
    writable: Option<FileSystemWritableFileStream>,
    pending_meta: Option<Vec<u8>>,
}

impl DirectoryPartHandle {
    async fn ensure_writable(
        &mut self,
        keep_existing_data: bool,
    ) -> Result<&FileSystemWritableFileStream, String> {
        if self.writable.is_none() {
            self.writable =
                Some(create_writable(&self.part_dir.data_handle, keep_existing_data).await?);
        }
        Ok(self.writable.as_ref().expect("writable just initialized"))
    }

    async fn flush_writable(&mut self) -> Result<(), String> {
        if let Some(active) = self.writable.take() {
            close_writable(active).await?;
        }
        Ok(())
    }

    async fn abort_writable(&mut self) {
        if let Some(active) = self.writable.take() {
            abort_writable(active).await;
        }
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
                    abort_writable(w).await;
                    return Err(err_str("writable.truncate()", err));
                }
                close_writable(w).await?;
                if new_size == 0 {
                    h.had_prior_file = false;
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
                // MessagePort chunks or CANCEL messages in site/workers/download.js.
                if h.yielder.is_none() {
                    h.yielder = Some(MacrotaskYielder::new()?);
                }
                if let Some(yielder) = &h.yielder {
                    yielder.yield_now().await;
                }
                Ok(())
            }
            Self::Directory(h) => {
                let active = h.ensure_writable(offset > 0).await?;
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
                    let meta_fh = ensure_file(&h.part_dir.dir, &h.part_dir.meta_name).await?;
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
                        crate::progress::emit_log(&format!(
                            "[Writer] OPFS checkpoint flush took {}ms",
                            elapsed.round() as u64
                        ));
                    }
                }
                Ok(())
            }
            Self::Directory(h) => {
                // FileSystemWritableFileStream writes to a swap file; closing & reopening
                // mid-transfer forces Chromium to copy the partial file into a new swap file,
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
                finalize_opfs_part(&h.part_dir).await
            }
            Self::Directory(mut h) => {
                // Directory handles write directly to `{filename}` via WritableFileStream's swap
                // file because Android SAF `content://` URIs reject `FileHandle.move()`.
                h.pending_meta = None;
                h.flush_writable().await?;
                remove_entry_if_exists(&h.part_dir.dir, &h.part_dir.meta_name, false).await?;
                Ok(())
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
                if let Some(meta) = h.pending_meta.take() {
                    let flushed = h.flush_writable().await.is_ok();
                    if flushed {
                        if let Ok(mh) = ensure_file(&h.part_dir.dir, &h.part_dir.meta_name).await {
                            let _ = write_bytes_writable(&mh, &meta).await;
                        }
                    } else if !h.had_prior_file {
                        let _ =
                            remove_entry_if_exists(&h.part_dir.dir, &h.part_dir.filename, false)
                                .await;
                    }
                } else {
                    h.abort_writable().await;
                    if !h.had_prior_file {
                        let _ =
                            remove_entry_if_exists(&h.part_dir.dir, &h.part_dir.filename, false)
                                .await;
                    }
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
