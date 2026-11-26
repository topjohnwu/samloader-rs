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

// OPFS staging manifest management and cache inspection.

const STAGING_DIR_NAME = "samloader-staging";
const MANIFEST_FILE_NAME = "manifest.json";
const FILES_DIR_NAME = "files";

function validateFilename(filename) {
  if (
    typeof filename !== "string" ||
    filename.length === 0 ||
    filename === "." ||
    filename === ".." ||
    filename.includes("/") ||
    filename.includes("\\") ||
    filename.endsWith(".part") ||
    filename.endsWith(".part.meta")
  ) {
    throw new Error(`Invalid filename: ${filename}`);
  }
  for (let i = 0; i < filename.length; i++) {
    const code = filename.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      throw new Error(`Invalid filename: ${filename}`);
    }
  }
}

async function getOpfsRootOpt() {
  if (typeof navigator === "undefined" || typeof navigator.storage?.getDirectory !== "function") {
    return null;
  }
  return await navigator.storage.getDirectory();
}

async function getOpfsRoot() {
  const root = await getOpfsRootOpt();
  if (!root) {
    throw new Error("Origin Private File System (OPFS) is not supported in this context");
  }
  return root;
}

async function getDirOpt(parent, name) {
  try {
    return await parent.getDirectoryHandle(name, { create: false });
  } catch (err) {
    if (err?.name === "NotFoundError") return null;
    throw err;
  }
}

async function getFileOpt(dir, name) {
  try {
    return await dir.getFileHandle(name, { create: false });
  } catch (err) {
    if (err?.name === "NotFoundError") return null;
    throw err;
  }
}

async function removeEntryIfExists(dir, name, recursive = false) {
  try {
    await dir.removeEntry(name, { recursive });
  } catch (err) {
    if (err?.name !== "NotFoundError") throw err;
  }
}

function normalizeManifest(val) {
  if (!val || typeof val !== "object" || typeof val.buildKey !== "string") {
    return null;
  }
  const files = [];
  if (Array.isArray(val.files)) {
    for (const item of val.files) {
      if (item && typeof item.name === "string") {
        const size = Number(item.size);
        files.push({
          name: item.name,
          component: typeof item.component === "string" ? item.component : null,
          size: Number.isFinite(size) && size >= 0 ? size : 0,
        });
      }
    }
  }
  return {
    buildKey: val.buildKey,
    model: typeof val.model === "string" ? val.model : "",
    region: typeof val.region === "string" ? val.region : "",
    version: typeof val.version === "string" ? val.version : "",
    decryptedFilename: typeof val.decryptedFilename === "string" ? val.decryptedFilename : "",
    fingerprintHex: typeof val.fingerprintHex === "string" ? val.fingerprintHex : "",
    complete: Boolean(val.complete),
    files,
  };
}

async function readManifest(stagingDir) {
  const fh = await getFileOpt(stagingDir, MANIFEST_FILE_NAME);
  if (!fh) return null;
  try {
    const file = await fh.getFile();
    const text = await file.text();
    return normalizeManifest(JSON.parse(text));
  } catch {
    return null;
  }
}

async function writeManifest(stagingDir, manifest) {
  const fh = await stagingDir.getFileHandle(MANIFEST_FILE_NAME, { create: true });
  if (typeof fh.createSyncAccessHandle !== "function") {
    throw new Error("OPFS manifest write must run in a Web Worker");
  }
  const bytes = new TextEncoder().encode(JSON.stringify(manifest));
  const sync = await fh.createSyncAccessHandle();
  try {
    sync.truncate(0);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const written = sync.write(bytes.subarray(offset), { at: offset });
      if (!(written > 0)) {
        throw new Error(`Short OPFS manifest write at offset ${offset}`);
      }
      offset += written;
    }
    sync.flush();
  } finally {
    sync.close();
  }
}

/**
 * Reads the OPFS staging manifest and sums the byte sizes of cached files.
 * @returns {Promise<{ buildKey: string, model: string, region: string, version: string, decryptedFilename: string, fingerprintHex: string, totalBytes: number, complete: boolean, files: { name: string, component: string | null, size: number }[] } | null>}
 */
export async function getOpfsCacheInfo() {
  const root = await getOpfsRootOpt();
  if (!root) return null;
  const stagingDir = await getDirOpt(root, STAGING_DIR_NAME);
  if (!stagingDir) return null;

  const manifest = await readManifest(stagingDir);
  let totalBytes = 0;
  let hasFiles = false;

  const filesDir = await getDirOpt(stagingDir, FILES_DIR_NAME);
  if (filesDir) {
    for await (const [name, handle] of filesDir.entries()) {
      if (handle.kind !== "file") continue;
      hasFiles = true;
      if (name.endsWith(".part.meta")) continue;
      try {
        const file = await handle.getFile();
        totalBytes += file.size;
      } catch {
        // Ignore transient file read errors during enumeration
      }
    }
  }

  if (manifest) {
    return { ...manifest, totalBytes };
  }
  if (!hasFiles && totalBytes === 0) {
    return null;
  }
  return {
    buildKey: "",
    model: "",
    region: "",
    version: "Unindexed cached files",
    decryptedFilename: "",
    fingerprintHex: "",
    totalBytes,
    complete: false,
    files: [],
  };
}

/**
 * Opens seekable `File` handles for every completed file in the staged OPFS build `buildKey`.
 * @param {string} buildKey
 * @returns {Promise<{ name: string, component: string | null, file: File }[]>}
 */
export async function getOpfsBuildFiles(buildKey) {
  const root = await getOpfsRoot();
  const stagingDir = await getDirOpt(root, STAGING_DIR_NAME);
  if (!stagingDir) {
    throw new Error("OPFS staging directory not found");
  }
  const manifest = await readManifest(stagingDir);
  if (!manifest || manifest.buildKey !== buildKey) {
    throw new Error("OPFS staging manifest does not match requested buildKey");
  }
  if (!manifest.complete) {
    throw new Error("OPFS build is not complete");
  }
  const filesDir = await getDirOpt(stagingDir, FILES_DIR_NAME);
  if (!filesDir) {
    throw new Error("OPFS files directory not found");
  }

  const results = [];
  for (const entry of manifest.files) {
    validateFilename(entry.name);
    const fh = await getFileOpt(filesDir, entry.name);
    if (!fh) {
      throw new Error(`Cached file '${entry.name}' not found`);
    }
    const file = await fh.getFile();
    results.push({
      name: entry.name,
      component: entry.component ?? null,
      file,
    });
  }
  return results;
}

/**
 * Recursively deletes the `samloader-staging/` directory in OPFS.
 */
export async function clearOpfsCache() {
  const root = await getOpfsRootOpt();
  if (!root) return;
  await removeEntryIfExists(root, STAGING_DIR_NAME, true);
}

/**
 * Prepares `samloader-staging/` for `meta.buildKey`, clearing stale files if the build changed,
 * and returns the `files/` `FileSystemDirectoryHandle`. Must be called in a Web Worker.
 * @param {{ buildKey: string, model?: string, region?: string, version?: string, decryptedFilename?: string, fingerprintHex?: string }} meta
 * @returns {Promise<FileSystemDirectoryHandle>}
 */
export async function prepareOpfsBuild(meta) {
  if (!meta?.buildKey) {
    throw new Error("prepareOpfsBuild requires a non-empty buildKey");
  }
  const root = await getOpfsRoot();
  const stagingDir = await root.getDirectoryHandle(STAGING_DIR_NAME, { create: true });
  const existing = await readManifest(stagingDir);
  const sameBuild = existing?.buildKey === meta.buildKey;

  if (!sameBuild) {
    await removeEntryIfExists(stagingDir, FILES_DIR_NAME, true);
  }
  const filesDir = await stagingDir.getDirectoryHandle(FILES_DIR_NAME, { create: true });

  const pick = (nextVal, oldVal) => (nextVal ? String(nextVal) : String(oldVal || ""));
  const nextManifest = {
    buildKey: meta.buildKey,
    model: pick(meta.model, existing?.model),
    region: pick(meta.region, existing?.region),
    version: pick(meta.version, existing?.version),
    decryptedFilename: pick(meta.decryptedFilename, existing?.decryptedFilename),
    fingerprintHex: pick(meta.fingerprintHex, existing?.fingerprintHex),
    complete: false,
    files: sameBuild ? existing.files : [],
  };
  await writeManifest(stagingDir, nextManifest);
  return filesDir;
}

/**
 * Marks `buildKey` complete in `samloader-staging/manifest.json`. Must be called in a Web Worker.
 * @param {string} buildKey
 * @param {{ name: string, component: string | null, size: number }[]} files
 */
export async function markOpfsBuildComplete(buildKey, files) {
  const root = await getOpfsRoot();
  const stagingDir = await root.getDirectoryHandle(STAGING_DIR_NAME, { create: true });
  const manifest = await readManifest(stagingDir);
  if (!manifest || manifest.buildKey !== buildKey) {
    throw new Error("OPFS staging manifest does not match buildKey");
  }
  manifest.complete = true;
  manifest.files = Array.isArray(files) ? files : [];
  await writeManifest(stagingDir, manifest);
}
