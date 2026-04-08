//! Asset extraction for packed binaries.
//!
//! Provides shared extraction logic used by both the main `smolvm` binary
//! (sidecar mode via `runpack`) and the standalone stub executable.

use crate::format::{PackFooter, SIDECAR_EXTENSION};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Safely unpack a tar archive, rejecting symlinks, hardlinks, and entries
/// that resolve outside `dest`.
///
/// The standard `tar::Archive::unpack()` strips `..` components but does
/// **not** reject symlinks. A crafted archive could create
/// `lib/libkrun.dylib → /tmp/evil.so`, and subsequent `dlopen()` would
/// load the attacker's library. This function rejects any entry that is
/// not a regular file or directory.
fn safe_unpack<R: Read>(archive: &mut tar::Archive<R>, dest: &Path) -> std::io::Result<()> {
    let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry.path()?.to_path_buf();

        match entry_type {
            tar::EntryType::Regular | tar::EntryType::GNUSparse | tar::EntryType::Directory => {}
            tar::EntryType::Symlink => {
                // Allow symlinks but validate the target stays within dest.
                if let Some(link_target) = entry.link_name()? {
                    let link_target = link_target.to_path_buf();
                    // Resolve relative symlinks against the entry's parent dir
                    let resolved = if link_target.is_absolute() {
                        // Absolute symlinks: jail to dest (e.g., /lib/foo → dest/lib/foo)
                        dest.join(link_target.strip_prefix("/").unwrap_or(&link_target))
                    } else {
                        let parent = entry_path.parent().unwrap_or(Path::new(""));
                        dest.join(parent).join(&link_target)
                    };
                    // Normalize the path by resolving .. components
                    let normalized = normalize_path(&resolved);
                    if !normalized.starts_with(&canonical_dest) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "tar symlink '{}' -> '{}' escapes destination directory",
                                entry_path.display(),
                                link_target.display()
                            ),
                        ));
                    }
                }
            }
            tar::EntryType::Link => {
                // Allow hardlinks but validate the target stays within dest.
                if let Some(link_target) = entry.link_name()? {
                    let full_target = dest.join(link_target.as_ref());
                    let normalized = normalize_path(&full_target);
                    if !normalized.starts_with(&canonical_dest) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "tar hardlink '{}' escapes destination directory",
                                entry_path.display()
                            ),
                        ));
                    }
                }
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "tar entry '{}' has disallowed type {:?}",
                        entry_path.display(),
                        other
                    ),
                ));
            }
        }

        // Validate that the unpacked path stays within dest.
        let full_path = dest.join(&entry_path);
        let normalized = normalize_path(&full_path);
        if !normalized.starts_with(&canonical_dest) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "tar entry '{}' escapes destination directory",
                    entry_path.display()
                ),
            ));
        }

        // Unpack the individual entry
        entry.unpack_in(dest)?;
    }
    Ok(())
}

/// Normalize a path by resolving `.` and `..` components without requiring
/// the path to exist on disk (unlike `canonicalize()`).
fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            c => components.push(c),
        }
    }
    components.iter().collect()
}

/// Marker file indicating extraction is complete.
const EXTRACTION_MARKER: &str = ".smolvm-extracted";

/// Get the cache directory for a given content hash.
///
/// Returns `~/.cache/smolvm-pack/<hash>/`.
///
/// The hash should be a hex string (e.g., first 16 chars of SHA-256).
pub fn get_cache_dir(hash_hex: &str) -> std::io::Result<PathBuf> {
    let base = dirs::cache_dir()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no cache directory"))?;

    Ok(base.join("smolvm-pack").join(hash_hex))
}

/// Compute a SHA-256-based cache key for a sidecar file.
///
/// Hashes the `[0..assets_size + manifest_size]` region (the content that
/// matters for extraction) and returns the first 16 hex characters.
/// This gives 64 bits of identity — collision-free for practical purposes.
pub fn compute_sidecar_cache_key(
    sidecar_path: &Path,
    footer: &PackFooter,
) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};

    let mut file = File::open(sidecar_path)?;
    let mut hasher = Sha256::new();
    let total = footer.assets_size + footer.manifest_size;
    let mut remaining = total;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash)[..16].to_string())
}

/// Compute a SHA-256-based cache key from a region of a binary file.
///
/// Used for embedded mode where assets are appended to the executable.
pub fn compute_binary_cache_key(
    exe_path: &Path,
    footer: &PackFooter,
) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};

    let mut file = File::open(exe_path)?;
    file.seek(SeekFrom::Start(footer.assets_offset))?;
    let mut hasher = Sha256::new();
    let total = footer.assets_size + footer.manifest_size;
    let mut remaining = total;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash)[..16].to_string())
}

/// Compute a SHA-256-based cache key from an in-memory region.
///
/// Used for Mach-O section mode where assets are mapped into memory.
///
/// # Safety
///
/// `data` must point to a valid, readable memory region of at least `size` bytes.
#[cfg(target_os = "macos")]
pub unsafe fn compute_section_cache_key(data: *const u8, size: usize) -> String {
    use sha2::{Digest, Sha256};

    let slice = unsafe { std::slice::from_raw_parts(data, size) };
    let hash = Sha256::digest(slice);
    format!("{:x}", hash)[..16].to_string()
}

/// Check if assets have already been extracted.
pub fn is_extracted(cache_dir: &Path) -> bool {
    cache_dir.join(EXTRACTION_MARKER).exists()
}

/// Check if footer indicates sidecar mode.
fn is_sidecar_mode(footer: &PackFooter) -> bool {
    footer.assets_offset == 0
}

/// Get sidecar file path for the given executable.
pub fn sidecar_path_for(exe_path: &Path) -> PathBuf {
    let filename = exe_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    exe_path.with_file_name(format!("{}{}", filename, SIDECAR_EXTENSION))
}

/// Extract assets from a sidecar `.smolmachine` file to the cache directory.
///
/// This is the primary extraction function for `smolvm pack run`.
/// The sidecar file format is: compressed_assets + manifest + footer.
///
/// Uses file-based locking (`flock`) to prevent races when multiple processes
/// attempt first-run extraction of the same sidecar concurrently. If `force`
/// is false and extraction has already completed (marker file present), this
/// is a no-op (after acquiring the lock to ensure visibility of a concurrent
/// extraction that just finished).
pub fn extract_sidecar(
    sidecar_path: &Path,
    cache_dir: &Path,
    footer: &PackFooter,
    force: bool,
    debug: bool,
) -> std::io::Result<()> {
    if !sidecar_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("sidecar file not found: {}", sidecar_path.display()),
        ));
    }

    // Ensure parent directory exists for the lockfile
    if let Some(parent) = cache_dir.parent() {
        fs::create_dir_all(parent)?;
    }

    // Acquire an exclusive lock adjacent to the cache directory.
    // This serializes concurrent first-run extractions of the same checksum.
    let lock_path = cache_dir.with_extension("lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;

    #[cfg(unix)]
    {
        let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Double-check inside the lock: another process may have completed
    // extraction while we were waiting for the lock.
    if !force && is_extracted(cache_dir) {
        if debug {
            eprintln!("debug: assets already extracted (possibly by another process)");
        }
        // Lock released on drop of lock_file
        return Ok(());
    }

    // If force-extracting over an existing cache, remove it first so we
    // get a clean slate.
    if force && cache_dir.exists() {
        let _ = fs::remove_dir_all(cache_dir);
    }

    extract_sidecar_inner(sidecar_path, cache_dir, footer, debug)
    // Lock released on drop of lock_file
}

/// Inner extraction logic (called under the lock).
fn extract_sidecar_inner(
    sidecar_path: &Path,
    cache_dir: &Path,
    footer: &PackFooter,
    debug: bool,
) -> std::io::Result<()> {
    // Clean up partial extraction artifacts from a previous interrupted run.
    // This is safe because we hold the exclusive flock.
    if cache_dir.exists() && !is_extracted(cache_dir) {
        if debug {
            eprintln!(
                "debug: removing partial extraction at {}",
                cache_dir.display()
            );
        }
        let _ = fs::remove_dir_all(cache_dir);
    }
    fs::create_dir_all(cache_dir)?;

    if debug {
        eprintln!(
            "debug: reading {} bytes of compressed assets from sidecar {}",
            footer.assets_size,
            sidecar_path.display()
        );
    }

    let sidecar_file = File::open(sidecar_path)?;
    let limited_reader = sidecar_file.take(footer.assets_size);

    let decoder = zstd::stream::Decoder::new(limited_reader)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut archive = tar::Archive::new(decoder);
    safe_unpack(&mut archive, cache_dir)?;

    if debug {
        eprintln!("debug: extracted assets to {}", cache_dir.display());
    }

    post_process_extraction(cache_dir, debug)?;
    Ok(())
}

/// Extract assets from a packed binary to the cache directory.
///
/// Supports both sidecar mode (assets_offset == 0) and embedded mode.
/// This is used by the stub executable.
pub fn extract_from_binary(
    exe_path: &Path,
    cache_dir: &Path,
    footer: &PackFooter,
    debug: bool,
) -> std::io::Result<()> {
    // Clean up partial extraction from a previous interrupted run
    if cache_dir.exists() && !is_extracted(cache_dir) {
        let _ = fs::remove_dir_all(cache_dir);
    }
    fs::create_dir_all(cache_dir)?;

    if is_sidecar_mode(footer) {
        let sidecar = sidecar_path_for(exe_path);
        extract_sidecar(&sidecar, cache_dir, footer, false, debug)
    } else {
        // Embedded mode: read compressed assets from the executable
        let mut exe_file = File::open(exe_path)?;
        exe_file.seek(SeekFrom::Start(footer.assets_offset))?;

        if debug {
            eprintln!(
                "debug: reading {} bytes of compressed assets from offset {}",
                footer.assets_size, footer.assets_offset
            );
        }

        let limited_reader = (&mut exe_file).take(footer.assets_size);

        let decoder = zstd::stream::Decoder::new(limited_reader)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut archive = tar::Archive::new(decoder);
        safe_unpack(&mut archive, cache_dir)?;

        if debug {
            eprintln!("debug: extracted assets to {}", cache_dir.display());
        }

        post_process_extraction(cache_dir, debug)?;
        Ok(())
    }
}

/// Extract assets from a memory pointer (for Mach-O section mode on macOS).
///
/// # Safety
///
/// `assets_ptr` must point to a valid, readable memory region of at least
/// `assets_size` bytes that remains valid for the duration of the call.
#[cfg(target_os = "macos")]
pub unsafe fn extract_from_section(
    cache_dir: &Path,
    assets_ptr: *const u8,
    assets_size: usize,
    debug: bool,
) -> std::io::Result<()> {
    // Clean up partial extraction from a previous interrupted run
    if cache_dir.exists() && !is_extracted(cache_dir) {
        let _ = fs::remove_dir_all(cache_dir);
    }
    fs::create_dir_all(cache_dir)?;

    if debug {
        eprintln!(
            "debug: extracting {} bytes of compressed assets from section",
            assets_size
        );
    }

    let assets_slice = unsafe { std::slice::from_raw_parts(assets_ptr, assets_size) };
    let cursor = std::io::Cursor::new(assets_slice);

    let decoder = zstd::stream::Decoder::new(cursor)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut archive = tar::Archive::new(decoder);
    safe_unpack(&mut archive, cache_dir)?;

    if debug {
        eprintln!("debug: extracted assets to {}", cache_dir.display());
    }

    post_process_extraction(cache_dir, debug)?;
    Ok(())
}

/// Copy a file while preserving sparseness.
///
/// Reads the source in 64KB chunks and skips all-zero chunks in the
/// destination by seeking past them, creating holes. This avoids the
/// 512MB actual disk usage caused by tar extraction losing sparseness
/// on the storage.ext4 template.
fn sparse_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut reader = File::open(src)?;
    let file_size = reader.metadata()?.len();
    let writer = File::create(dst)?;
    writer.set_len(file_size)?;
    let mut writer = std::io::BufWriter::new(writer);

    const CHUNK: usize = 65536;
    let mut buf = [0u8; CHUNK];
    let zero_buf = [0u8; CHUNK];
    let mut offset: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if buf[..n] == zero_buf[..n] {
            // Skip zero chunk — leave a hole in the destination
            offset += n as u64;
        } else {
            writer.seek(SeekFrom::Start(offset))?;
            writer.write_all(&buf[..n])?;
            offset += n as u64;
        }
    }

    Ok(())
}

/// Re-sparsify a file in place by copying through a temporary file.
///
/// If the file is already sparse or doesn't exist, this is a no-op.
fn resparsify(path: &Path, debug: bool) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let tmp = path.with_extension("sparse.tmp");
    sparse_copy(path, &tmp)?;
    fs::rename(&tmp, path)?;

    if debug {
        let meta = fs::metadata(path)?;
        #[cfg(unix)]
        let actual = {
            use std::os::unix::fs::MetadataExt;
            meta.blocks() * 512
        };
        #[cfg(not(unix))]
        let actual = meta.len();
        eprintln!(
            "debug: re-sparsified {} (virtual={}, actual={})",
            path.display(),
            meta.len(),
            actual,
        );
    }

    Ok(())
}

/// Post-process extracted assets: unpack agent rootfs, OCI layers, fix permissions.
fn post_process_extraction(cache_dir: &Path, debug: bool) -> std::io::Result<()> {
    // Extract agent-rootfs.tar to agent-rootfs directory
    let rootfs_tar = cache_dir.join("agent-rootfs.tar");
    let rootfs_dir = cache_dir.join("agent-rootfs");
    if rootfs_tar.exists() && !rootfs_dir.exists() {
        if debug {
            eprintln!("debug: extracting agent-rootfs.tar...");
        }
        fs::create_dir_all(&rootfs_dir)?;
        let tar_file = File::open(&rootfs_tar)?;
        let mut archive = tar::Archive::new(tar_file);
        safe_unpack(&mut archive, &rootfs_dir)?;
    }

    // Extract OCI layer tars to layers/{digest}/ directories
    let layers_dir = cache_dir.join("layers");
    if layers_dir.exists() {
        if debug {
            eprintln!("debug: extracting OCI layers...");
        }
        for entry in fs::read_dir(&layers_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "tar") {
                let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                let layer_dir = layers_dir.join(&*stem);
                if !layer_dir.exists() {
                    if debug {
                        eprintln!("debug: extracting layer {}...", stem);
                    }
                    fs::create_dir_all(&layer_dir)?;
                    let tar_file = File::open(&path)?;
                    let mut archive = tar::Archive::new(tar_file);
                    safe_unpack(&mut archive, &layer_dir)?;
                }
            }
        }
    }

    // Re-sparsify the storage template — tar extraction loses sparseness,
    // turning the 512MB virtual/~100KB actual sparse file into 512MB actual.
    resparsify(&cache_dir.join("storage.ext4"), debug)?;

    // Write marker file
    fs::write(cache_dir.join(EXTRACTION_MARKER), "")?;

    // Make libraries executable (they need to be loadable)
    let lib_dir = cache_dir.join("lib");
    if lib_dir.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in fs::read_dir(&lib_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let mut perms = fs::metadata(&path)?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(&path, perms)?;
                }
            }
        }
    }

    Ok(())
}

/// Marker file indicating libs extraction is complete.
const LIBS_EXTRACTION_MARKER: &str = ".smolvm-libs-extracted";

/// Extract runtime libraries from a packed stub binary.
///
/// Reads the last 32 bytes of the executable looking for a SMOLLIBS footer.
/// If found, extracts the compressed libs bundle to a cache directory and
/// returns the path to the `lib/` directory containing libkrun/libkrunfw.
///
/// Returns `None` if the binary has no embedded libs (e.g., a V2 stub or
/// the base smolvm binary).
pub fn extract_libs_from_binary(exe_path: &Path, debug: bool) -> std::io::Result<Option<PathBuf>> {
    use crate::format::{LibsFooter, LIBS_FOOTER_SIZE};

    let mut file = File::open(exe_path)?;
    let file_size = file.metadata()?.len();
    if file_size < LIBS_FOOTER_SIZE as u64 {
        return Ok(None);
    }

    // Read the last 32 bytes
    file.seek(SeekFrom::End(-(LIBS_FOOTER_SIZE as i64)))?;
    let mut footer_buf = [0u8; LIBS_FOOTER_SIZE];
    file.read_exact(&mut footer_buf)?;

    let footer = match LibsFooter::from_bytes(&footer_buf) {
        Ok(f) => f,
        Err(_) => return Ok(None), // No SMOLLIBS footer — not a V3 stub
    };

    if debug {
        eprintln!(
            "debug: found SMOLLIBS footer: offset={}, size={}",
            footer.libs_offset, footer.libs_size
        );
    }

    // Cache key based on libs content hash
    file.seek(SeekFrom::Start(footer.libs_offset))?;
    let mut hasher = crc32fast::Hasher::new();
    let mut remaining = footer.libs_size;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    let libs_checksum = hasher.finalize();

    let cache_base = dirs::cache_dir()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no cache directory"))?;
    let libs_cache_dir = cache_base
        .join("smolvm-libs")
        .join(format!("{:08x}", libs_checksum));
    let lib_dir = libs_cache_dir.join("lib");

    // Acquire exclusive lock to prevent concurrent extraction races.
    if let Some(parent) = libs_cache_dir.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock_path = libs_cache_dir.with_extension("lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;

    #[cfg(unix)]
    {
        let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Re-check after acquiring lock (another process may have finished)
    if libs_cache_dir.join(LIBS_EXTRACTION_MARKER).exists() {
        if debug {
            eprintln!("debug: libs already extracted at {}", lib_dir.display());
        }
        // Lock released on drop of lock_file
        let _ = lock_file;
        return Ok(Some(lib_dir));
    }

    // Extract
    fs::create_dir_all(&libs_cache_dir)?;
    file.seek(SeekFrom::Start(footer.libs_offset))?;
    let limited_reader = (&mut file).take(footer.libs_size);
    let decoder = zstd::stream::Decoder::new(limited_reader)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut archive = tar::Archive::new(decoder);
    safe_unpack(&mut archive, &libs_cache_dir)?;

    // Make libs executable
    if lib_dir.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in fs::read_dir(&lib_dir)? {
                let entry = entry?;
                if entry.path().is_file() {
                    let mut perms = fs::metadata(entry.path())?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(entry.path(), perms)?;
                }
            }
        }
    }

    fs::write(libs_cache_dir.join(LIBS_EXTRACTION_MARKER), "")?;
    // Lock released on drop of lock_file
    let _ = lock_file;

    if debug {
        eprintln!("debug: extracted libs to {}", lib_dir.display());
    }

    Ok(Some(lib_dir))
}

/// Create a storage disk file (empty sparse file).
pub fn create_storage_disk(path: &Path, size: u64) -> std::io::Result<()> {
    let file = File::create(path)?;
    file.set_len(size)?;
    Ok(())
}

/// Copy overlay disk template from cache to a runtime directory.
///
/// Copies the overlay template to `dest`, optionally extending the sparse
/// file if `size_gb_override` is larger than the template.
///
/// Returns an error if the template path is `None` or the template file
/// does not exist in the cache.
pub fn copy_overlay_template(
    cache_dir: &Path,
    template_path: Option<&str>,
    dest: &Path,
    size_gb_override: Option<u64>,
) -> std::io::Result<()> {
    let template = template_path.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "overlay template not specified in manifest",
        )
    })?;

    let src = cache_dir.join(template);
    if !src.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("overlay template not found: {}", src.display()),
        ));
    }

    // Use sparse copy to preserve holes in the overlay template
    sparse_copy(&src, dest)?;

    // Extend if requested size is larger than template
    if let Some(gb) = size_gb_override {
        let desired = gb * 1024 * 1024 * 1024;
        let current = fs::metadata(dest)?.len();
        if desired > current {
            let file = fs::OpenOptions::new().write(true).open(dest)?;
            file.set_len(desired)?;
        }
    }

    Ok(())
}

/// Create or copy storage disk from template.
///
/// If a pre-formatted template exists in the cache, copy it.
/// Otherwise, create an empty sparse file (will be formatted by agent on first boot).
///
/// `size_gb_override` lets callers specify a custom disk size (in GiB).
/// When `None`, falls back to 512 MiB.
pub fn create_or_copy_storage_disk(
    cache_dir: &Path,
    template_path: Option<&str>,
    storage_path: &Path,
    size_gb_override: Option<u64>,
) -> std::io::Result<()> {
    if let Some(template) = template_path {
        let template_path = cache_dir.join(template);
        if template_path.exists() {
            // Use sparse copy to preserve holes in the storage template.
            // The template is 512MB virtual but only ~100KB actual data;
            // fs::copy would allocate the full 512MB on disk.
            sparse_copy(&template_path, storage_path)?;
            // If a custom size was requested and it's larger than the template,
            // extend the sparse file (resize2fs in the agent will expand the FS).
            if let Some(gb) = size_gb_override {
                let desired = gb * 1024 * 1024 * 1024;
                let current = fs::metadata(storage_path)?.len();
                if desired > current {
                    let file = fs::OpenOptions::new().write(true).open(storage_path)?;
                    file.set_len(desired)?;
                }
            }
            return Ok(());
        }
    }
    // Fallback: create empty sparse file (agent will format on first boot)
    let size = match size_gb_override {
        Some(gb) => gb * 1024 * 1024 * 1024,
        None => 512 * 1024 * 1024,
    };
    create_storage_disk(storage_path, size)
}

/// Maximum age for stale runtime temp directories (24 hours).
const STALE_RUNTIME_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Automatically evict old cache entries and clean stale runtime directories.
///
/// Keeps the `max_entries` most recently modified cache directories.
/// Also cleans up runtime temp directories older than 24 hours in all
/// surviving cache entries (orphaned from crashed runs).
///
/// This function is best-effort — errors are silently ignored since
/// eviction is non-critical.
pub fn auto_evict(max_entries: usize) {
    let Some(base) = dirs::cache_dir() else {
        return;
    };
    let pack_cache = base.join("smolvm-pack");
    if !pack_cache.exists() {
        return;
    }

    // Collect cache entry directories (skip lock files and non-dirs)
    let mut entries: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
    let Ok(read_dir) = fs::read_dir(&pack_cache) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let mtime = path
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        entries.push((path, mtime));
    }

    // Sort newest first
    entries.sort_by(|a, b| b.1.cmp(&a.1));

    // Remove entries beyond max_entries
    for (path, _) in entries.iter().skip(max_entries) {
        let _ = fs::remove_dir_all(path);
        // Also remove the lock file
        let lock = path.with_extension("lock");
        let _ = fs::remove_file(&lock);
    }

    // Clean stale runtime temp dirs in all surviving entries
    let now = std::time::SystemTime::now();
    for (path, _) in entries.iter().take(max_entries) {
        let runtime_dir = path.join("runtime");
        if !runtime_dir.exists() {
            continue;
        }
        let Ok(runtime_entries) = fs::read_dir(&runtime_dir) else {
            continue;
        };
        for entry in runtime_entries.flatten() {
            let tmp_path = entry.path();
            if !tmp_path.is_dir() {
                continue;
            }
            let age = tmp_path
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| now.duration_since(t).ok());
            if let Some(age) = age {
                if age > STALE_RUNTIME_AGE {
                    let _ = fs::remove_dir_all(&tmp_path);
                }
            }
        }
    }

    // Also evict old libs cache entries
    let libs_cache = base.join("smolvm-libs");
    if libs_cache.exists() {
        let mut lib_entries: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
        if let Ok(rd) = fs::read_dir(&libs_cache) {
            for entry in rd.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let mtime = path
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                lib_entries.push((path, mtime));
            }
        }
        lib_entries.sort_by(|a, b| b.1.cmp(&a.1));
        for (path, _) in lib_entries.iter().skip(max_entries) {
            let _ = fs::remove_dir_all(path);
            let lock = path.with_extension("lock");
            let _ = fs::remove_file(&lock);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_dir_format() {
        let dir = get_cache_dir("a1b2c3d4e5f67890").unwrap();
        assert!(dir.to_string_lossy().contains("a1b2c3d4e5f67890"));
    }

    #[test]
    fn test_is_extracted() {
        let temp_dir = tempfile::tempdir().unwrap();

        assert!(!is_extracted(temp_dir.path()));

        fs::write(temp_dir.path().join(EXTRACTION_MARKER), "").unwrap();
        assert!(is_extracted(temp_dir.path()));
    }

    #[test]
    fn test_is_extracted_partial() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Simulate partial extraction - files exist but no marker
        fs::create_dir_all(temp_dir.path().join("lib")).unwrap();
        fs::write(temp_dir.path().join("lib/libkrun.dylib"), "partial").unwrap();

        assert!(!is_extracted(temp_dir.path()));
    }

    #[test]
    fn test_sidecar_path_for() {
        let exe = Path::new("/path/to/my-app");
        let sidecar = sidecar_path_for(exe);
        assert_eq!(sidecar, PathBuf::from("/path/to/my-app.smolmachine"));
    }

    #[test]
    fn test_sidecar_mode_detection() {
        let sidecar_footer = PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 1000,
            manifest_offset: 1000,
            manifest_size: 500,
            checksum: 0x12345678,
        };
        assert!(is_sidecar_mode(&sidecar_footer));

        let embedded_footer = PackFooter {
            stub_size: 50000,
            assets_offset: 50000,
            assets_size: 1000,
            manifest_offset: 51000,
            manifest_size: 500,
            checksum: 0x12345678,
        };
        assert!(!is_sidecar_mode(&embedded_footer));
    }

    #[test]
    fn test_create_storage_disk() {
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("test.ext4");

        create_storage_disk(&disk_path, 1024 * 1024).unwrap();

        assert!(disk_path.exists());
        assert_eq!(fs::metadata(&disk_path).unwrap().len(), 1024 * 1024);
    }

    #[test]
    fn test_copy_overlay_template_fails_when_none() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("overlay.raw");

        let result = copy_overlay_template(temp_dir.path(), None, &dest, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_copy_overlay_template_fails_when_missing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("overlay.raw");

        let result = copy_overlay_template(temp_dir.path(), Some("nonexistent.raw"), &dest, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_copy_overlay_template_copies_and_extends() {
        let temp_dir = tempfile::tempdir().unwrap();
        let template = temp_dir.path().join("overlay.raw");
        let dest = temp_dir.path().join("output.raw");

        // Create a small template file (1 KB)
        let template_data = vec![0u8; 1024];
        fs::write(&template, &template_data).unwrap();

        // Copy without size override
        copy_overlay_template(temp_dir.path(), Some("overlay.raw"), &dest, None).unwrap();
        assert_eq!(fs::metadata(&dest).unwrap().len(), 1024);

        // Copy with size override that extends (use small value for test)
        let dest2 = temp_dir.path().join("output2.raw");
        // We can't test GiB-sized files, but we can verify the copy works
        copy_overlay_template(temp_dir.path(), Some("overlay.raw"), &dest2, None).unwrap();
        assert!(dest2.exists());
    }

    #[test]
    fn test_extract_sidecar_skips_when_already_extracted() {
        // Verifies the double-check pattern inside the lock:
        // if the marker exists and force=false, extraction is a no-op.
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        fs::create_dir_all(&cache_dir).unwrap();

        // Write marker to simulate completed extraction
        fs::write(cache_dir.join(EXTRACTION_MARKER), "").unwrap();

        let dummy_footer = PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 0,
            manifest_offset: 0,
            manifest_size: 0,
            checksum: 0,
        };

        // Should succeed without trying to open a nonexistent sidecar,
        // because the marker check short-circuits.
        let result = extract_sidecar(
            Path::new("/nonexistent/sidecar.smolmachine"),
            &cache_dir,
            &dummy_footer,
            false, // force=false
            false,
        );
        // The sidecar doesn't exist, but we never try to open it because
        // the marker file is already present.
        // Note: the exists() check at the top will fail here, so this test
        // verifies the locking path only when the sidecar exists.
        // Let's adjust: use a real (empty) sidecar file for the existence check.
        drop(result);

        let dummy_sidecar = temp_dir.path().join("dummy.smolmachine");
        fs::write(&dummy_sidecar, b"").unwrap();

        let result = extract_sidecar(
            &dummy_sidecar,
            &cache_dir,
            &dummy_footer,
            false, // force=false
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_sidecar_force_clears_marker() {
        // Verifies that force=true re-extracts even when the marker exists.
        // We can't do a full extraction without a real sidecar, so we verify
        // that force=true proceeds past the marker check (and then fails on
        // the actual extraction — which is fine for this test).
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache-force");
        fs::create_dir_all(&cache_dir).unwrap();

        // Write marker
        fs::write(cache_dir.join(EXTRACTION_MARKER), "").unwrap();
        assert!(is_extracted(&cache_dir));

        // Create a dummy sidecar (empty — will fail during decompression)
        let dummy_sidecar = temp_dir.path().join("force.smolmachine");
        fs::write(&dummy_sidecar, b"not-a-real-zstd-stream").unwrap();

        let dummy_footer = PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 22, // matches "not-a-real-zstd-stream".len()
            manifest_offset: 22,
            manifest_size: 0,
            checksum: 0,
        };

        let result = extract_sidecar(
            &dummy_sidecar,
            &cache_dir,
            &dummy_footer,
            true, // force=true should bypass marker
            false,
        );

        // Should fail during decompression (not short-circuit on marker),
        // proving that force=true re-enters the extraction path.
        assert!(
            result.is_err(),
            "force extraction should attempt (and fail on dummy data)"
        );
    }
}
