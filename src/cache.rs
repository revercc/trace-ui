use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use sha2::{Sha256, Digest};
use memmap2::Mmap;
use crate::flat::archives::{Phase2Archive, ScanArchive};
use crate::flat::line_index::LineIndexArchive;
use crate::taint::strings::StringIndex;

const MAGIC: &[u8; 8] = b"TCACHE03";
const MAGIC_V4: &[u8; 8] = b"TCACHE04";
const HEAD_SIZE: usize = 1024 * 1024; // 1MB
const HEADER_LEN_V4: usize = 64;

static CACHE_DIR_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

pub fn set_cache_dir_override(path: Option<PathBuf>) {
    *CACHE_DIR_OVERRIDE.write().unwrap() = path;
}

pub fn cache_dir() -> Option<PathBuf> {
    if let Ok(guard) = CACHE_DIR_OVERRIDE.read() {
        if let Some(ref p) = *guard {
            return Some(p.clone());
        }
    }
    dirs::data_dir().map(|d| d.join("trace-ui").join("cache"))
}

fn cache_path(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}.bin", hash, suffix)))
}

/// Cache path with explicit extension (no automatic `.bin` suffix).
fn cache_path_ext(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}", hash, suffix)))
}

fn head_hash(data: &[u8]) -> [u8; 32] {
    let end = data.len().min(HEAD_SIZE);
    let mut hasher = Sha256::new();
    hasher.update(&data[..end]);
    hasher.finalize().into()
}

fn validate_header(buf: &[u8], data: &[u8]) -> bool {
    if buf.len() < 48 || &buf[0..8] != MAGIC {
        return false;
    }
    let stored_size = u64::from_le_bytes(buf[8..16].try_into().unwrap_or_default());
    if stored_size != data.len() as u64 {
        return false;
    }
    let cached_hash: [u8; 32] = match buf[16..48].try_into() {
        Ok(h) => h,
        Err(_) => return false,
    };
    cached_hash == head_hash(data)
}

fn validate_header_from_reader(reader: &mut impl Read, data: &[u8]) -> bool {
    let mut header = [0u8; 48];
    if reader.read_exact(&mut header).is_err() {
        return false;
    }
    validate_header(&header, data)
}

fn write_header(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(&head_hash(data));
}

// ── 通用加载/保存 (bincode, legacy) ──

fn load_cached<T: serde::de::DeserializeOwned>(file_path: &str, data: &[u8], suffix: &str) -> Option<T> {
    let path = cache_path(file_path, suffix)?;
    let file = std::fs::File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    if !validate_header_from_reader(&mut reader, data) { return None; }
    bincode::deserialize_from(reader).ok()
}

fn save_cached<T: serde::Serialize>(file_path: &str, data: &[u8], suffix: &str, value: &T) {
    let Some(path) = cache_path(file_path, suffix) else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut writer = BufWriter::new(file);
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    if writer.write_all(&header).is_err() { return; }
    if bincode::serialize_into(&mut writer, value).is_err() { return; }
    let _ = writer.flush();
}

// ── rkyv 通用加载/保存 ──

fn save_rkyv_cached<T>(file_path: &str, data: &[u8], suffix: &str, value: &T)
where
    T: for<'a> rkyv::Serialize<rkyv::api::high::HighSerializer<rkyv::util::AlignedVec, rkyv::ser::allocator::ArenaHandle<'a>, rkyv::rancor::Error>>,
{
    let Some(path) = cache_path_ext(file_path, suffix) else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let bytes = match rkyv::to_bytes::<rkyv::rancor::Error>(value) {
        Ok(b) => b,
        Err(_) => return,
    };

    let file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut writer = BufWriter::new(file);

    // Write 64-byte V4 header
    let mut header = Vec::with_capacity(HEADER_LEN_V4);
    header.extend_from_slice(MAGIC_V4);
    header.extend_from_slice(&(data.len() as u64).to_le_bytes());
    header.extend_from_slice(&head_hash(data));
    header.resize(HEADER_LEN_V4, 0); // pad to 64 bytes

    if writer.write_all(&header).is_err() { return; }
    if writer.write_all(&bytes).is_err() { return; }
    let _ = writer.flush();
}

fn load_rkyv_mmap(file_path: &str, data: &[u8], suffix: &str) -> Option<Arc<Mmap>> {
    let path = cache_path_ext(file_path, suffix)?;
    let file = std::fs::File::open(&path).ok()?;
    let mmap = unsafe { Mmap::map(&file) }.ok()?;

    // Validate V4 header
    if mmap.len() < HEADER_LEN_V4 { return None; }
    if &mmap[0..8] != MAGIC_V4 { return None; }
    let stored_size = u64::from_le_bytes(mmap[8..16].try_into().ok()?);
    if stored_size != data.len() as u64 { return None; }
    let cached_hash: [u8; 32] = mmap[16..48].try_into().ok()?;
    if cached_hash != head_hash(data) { return None; }

    Some(Arc::new(mmap))
}

// ── Phase2 rkyv 缓存 ──

pub fn save_phase2_rkyv(file_path: &str, data: &[u8], archive: &Phase2Archive) {
    save_rkyv_cached(file_path, data, ".p2.rkyv", archive);
}

pub fn load_phase2_rkyv(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    load_rkyv_mmap(file_path, data, ".p2.rkyv")
}

// ── Scan rkyv 缓存 ──

pub fn save_scan_rkyv(file_path: &str, data: &[u8], archive: &ScanArchive) {
    save_rkyv_cached(file_path, data, ".scan.rkyv", archive);
}

pub fn load_scan_rkyv(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    load_rkyv_mmap(file_path, data, ".scan.rkyv")
}

// ── LineIndex rkyv 缓存 ──

pub fn save_lidx_rkyv(file_path: &str, data: &[u8], archive: &LineIndexArchive) {
    save_rkyv_cached(file_path, data, ".lidx.rkyv", archive);
}

pub fn load_lidx_rkyv(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    load_rkyv_mmap(file_path, data, ".lidx.rkyv")
}

// ── StringIndex bincode 缓存 ──

pub fn save_string_cache(file_path: &str, data: &[u8], index: &StringIndex) {
    save_cached(file_path, data, ".strings", index);
}

pub fn load_string_cache(file_path: &str, data: &[u8]) -> Option<StringIndex> {
    load_cached(file_path, data, ".strings")
}

/// 删除指定文件的所有缓存（新 rkyv + 旧 bincode）
pub fn delete_cache(file_path: &str) {
    // New rkyv suffixes
    for suffix in [".p2.rkyv", ".scan.rkyv", ".lidx.rkyv", ".strings.bin"] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // Old bincode suffixes (cleanup)
    for suffix in ["", "-scan", "-lidx"] {
        if let Some(p) = cache_path(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub fn get_cache_info() -> (String, u64) {
    let dir = cache_dir().unwrap_or_default();
    let path_str = dir.to_string_lossy().to_string();
    let size = dir_size(&dir);
    (path_str, size)
}

pub fn clear_all_cache() -> (u32, u64) {
    let Some(dir) = cache_dir() else { return (0, 0) };
    let mut count = 0u32;
    let mut total_size = 0u64;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if ext == Some("bin") || ext == Some("rkyv") {
                if let Ok(meta) = path.metadata() {
                    total_size += meta.len();
                }
                if std::fs::remove_file(&path).is_ok() {
                    count += 1;
                }
            }
        }
    }
    (count, total_size)
}

fn dir_size(path: &PathBuf) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else { return 0 };
    entries.flatten()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}
