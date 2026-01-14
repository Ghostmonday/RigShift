//! Large File Finder Module
//!
//! Scans drives for large files that may be taking up significant disk space.
//! Supports recursive scanning, size filtering, file type filtering, and
//! age-based filtering to find forgotten files like videos, ISOs, and game mods.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

/// Configuration for large file scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeFileConfig {
    /// Minimum file size in bytes to consider (default: 100MB)
    pub min_size_bytes: u64,
    /// Maximum file size in bytes (default: no limit)
    pub max_size_bytes: Option<u64>,
    /// File extensions to include (empty = all)
    pub include_extensions: Vec<String>,
    /// File extensions to exclude
    pub exclude_extensions: Vec<String>,
    /// Directories to exclude from scanning
    pub exclude_directories: Vec<String>,
    /// Minimum age in days (0 = all files)
    pub min_age_days: u32,
    /// Maximum age in days (0 = no limit)
    pub max_age_days: u32,
    /// Whether to scan hidden files
    pub include_hidden: bool,
    /// Whether to scan system files
    pub include_system: bool,
    /// Number of threads for parallel scanning
    pub thread_count: usize,
}

impl Default for LargeFileConfig {
    fn default() -> Self {
        LargeFileConfig {
            min_size_bytes: 100 * 1024 * 1024, // 100MB default
            max_size_bytes: None,
            include_extensions: Vec::new(),
            exclude_extensions: vec![
                "dll".to_string(),
                "exe".to_string(),
                "sys".to_string(),
                "drv".to_string(),
            ],
            exclude_directories: vec![
                "Windows".to_string(),
                "Program Files".to_string(),
                "Program Files (x86)".to_string(),
                "$Recycle.Bin".to_string(),
                "System Volume Information".to_string(),
            ],
            min_age_days: 0,
            max_age_days: 0,
            include_hidden: false,
            include_system: false,
            thread_count: 4,
        }
    }
}

impl LargeFileConfig {
    /// Create a new config with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum file size
    #[must_use]
    pub fn with_min_size(mut self, size_bytes: u64) -> Self {
        self.min_size_bytes = size_bytes;
        self
    }

    /// Set maximum file size
    #[must_use]
    pub fn with_max_size(mut self, size_bytes: u64) -> Self {
        self.max_size_bytes = Some(size_bytes);
        self
    }

    /// Add file extension to include
    #[must_use]
    pub fn include_extension(mut self, ext: &str) -> Self {
        self.include_extensions.push(ext.to_lowercase());
        self
    }

    /// Add file extension to exclude
    #[must_use]
    pub fn exclude_extension(mut self, ext: &str) -> Self {
        self.exclude_extensions.push(ext.to_lowercase());
        self
    }

    /// Set minimum age in days
    #[must_use]
    pub fn with_min_age(mut self, days: u32) -> Self {
        self.min_age_days = days;
        self
    }

    /// Set maximum age in days
    #[must_use]
    pub fn with_max_age(mut self, days: u32) -> Self {
        self.max_age_days = days;
        self
    }

    /// Set thread count for parallel scanning
    #[must_use]
    pub fn with_thread_count(mut self, count: usize) -> Self {
        self.thread_count = count;
        self
    }

    /// Enable scanning hidden files
    #[must_use]
    pub fn include_hidden(mut self, include: bool) -> Self {
        self.include_hidden = include;
        self
    }

    /// Enable scanning system files
    #[must_use]
    pub fn include_system(mut self, include: bool) -> Self {
        self.include_system = include;
        self
    }
}

/// Represents a large file found during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeFile {
    /// Full path to the file
    pub path: PathBuf,
    /// File size in bytes
    pub size_bytes: u64,
    /// Human-readable size
    pub size_formatted: String,
    /// File extension
    pub extension: String,
    /// File name
    pub name: String,
    /// When the file was last modified
    pub last_modified: SystemTime,
    /// Age in days since last modification
    pub age_days: u32,
    /// Category of the file
    pub file_category: FileCategory,
    /// Whether the file is in use
    pub is_locked: bool,
    /// MD5 hash for identification (optional)
    pub hash: Option<String>,
}

/// Categories for classifying large files
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileCategory {
    /// Video files (mp4, avi, mkv, mov, etc.)
    Video,
    /// ISO/BIN disk image files
    DiskImage,
    /// Game-related files (mods, save games, etc.)
    Game,
    /// Archive files (zip, rar, 7z, etc.)
    Archive,
    /// Audio files (mp3, flac, wav, etc.)
    Audio,
    /// Database files
    Database,
    /// Backup files
    Backup,
    /// Log files
    Log,
    /// Virtual machine files (vhd, vmdk, etc.)
    VirtualMachine,
    /// Development files (large source trees, builds, etc.)
    Development,
    /// Other uncategorized files
    Other,
}

/// Result of a large file scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LargeFileScanResult {
    /// All large files found
    pub files: Vec<LargeFile>,
    /// Files grouped by category
    pub files_by_category: HashMap<FileCategory, Vec<LargeFile>>,
    /// Total size of all found files
    pub total_size_bytes: u64,
    /// Total count
    pub file_count: usize,
    /// Count by category
    pub category_counts: HashMap<FileCategory, usize>,
    /// Scan duration
    pub scan_duration: Duration,
    /// Total directories scanned
    pub directories_scanned: usize,
    /// Total files scanned
    pub files_scanned: usize,
    /// Largest files
    pub top_files: Vec<LargeFile>,
    /// Files older than threshold
    pub old_files: Vec<LargeFile>,
    /// Scan errors
    pub errors: Vec<ScanError>,
}

/// Error encountered during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub path: PathBuf,
    pub error_type: ErrorType,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorType {
    PermissionDenied,
    InvalidPath,
    IoError,
    Other,
}

/// Large File Finder
pub struct LargeFileFinder {
    config: LargeFileConfig,
}

impl LargeFileFinder {
    /// Create a new large file finder with default config
    pub fn new() -> Self {
        LargeFileFinder {
            config: LargeFileConfig::default(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: LargeFileConfig) -> Self {
        LargeFileFinder { config }
    }

    /// Scan a directory for large files
    pub fn scan_directory(&self, path: &Path) -> LargeFileScanResult {
        self.scan_directory_with_config(path, &self.config)
    }

    /// Scan a directory with custom config
    pub fn scan_directory_with_config(
        &self,
        path: &Path,
        config: &LargeFileConfig,
    ) -> LargeFileScanResult {
        let start_time = SystemTime::now();
        let mut files = Vec::new();
        let mut errors = Vec::new();
        let total_files = Arc::new(AtomicUsize::new(0));
        let total_dirs = Arc::new(AtomicUsize::new(0));
        let files_clone = Arc::new(AtomicUsize::new(0));

        // Collect directories to scan
        let mut dirs_to_scan = Vec::new();
        if path.exists() && path.is_dir() {
            dirs_to_scan.push(path.to_path_buf());
        }

        // Scan each drive if root is specified
        if path.to_string_lossy() == "/" || path.to_string_lossy() == "C:" {
            if let Ok(drives) = get_drives() {
                dirs_to_scan = drives;
            }
        }

        // Process directories
        while let Some(current_dir) = dirs_to_scan.pop() {
            match self.scan_directory_recursive(
                &current_dir,
                config,
                &mut files,
                &mut errors,
                &total_files,
                &total_dirs,
                &files_clone,
            ) {
                Ok(new_dirs) => dirs_to_scan.extend(new_dirs),
                Err(e) => {
                    errors.push(ScanError {
                        path: current_dir.clone(),
                        error_type: ErrorType::IoError,
                        message: e.to_string(),
                    });
                }
            }
        }

        let scan_duration = start_time.elapsed().unwrap_or_default();

        // Process and sort results
        let mut result = self.process_results(files, errors, scan_duration);

        result.directories_scanned = total_dirs.load(Ordering::Relaxed);
        result.files_scanned = files_clone.load(Ordering::Relaxed);

        result
    }

    /// Recursively scan a directory
    fn scan_directory_recursive(
        &self,
        dir: &Path,
        config: &LargeFileConfig,
        files: &mut Vec<LargeFile>,
        errors: &mut Vec<ScanError>,
        total_dirs: &AtomicUsize,
        total_files: &AtomicUsize,
        files_scanned: &AtomicUsize,
    ) -> Result<Vec<PathBuf>, Box<dyn Error>> {
        let mut new_dirs = Vec::new();

        // Skip if directory is in exclude list
        if let Some(dir_name) = dir.file_name().map(|n| n.to_string_lossy().to_lowercase()) {
            for excluded in &config.exclude_directories {
                if dir_name.contains(&excluded.to_lowercase())
                    || dir_name == excluded.to_lowercase()
                {
                    return Ok(new_dirs);
                }
            }
        }

        total_dirs.fetch_add(1, Ordering::Relaxed);

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                // Permission denied is common, don't treat as critical error
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    errors.push(ScanError {
                        path: dir.to_path_buf(),
                        error_type: ErrorType::PermissionDenied,
                        message: "Access denied".to_string(),
                    });
                }
                return Ok(new_dirs);
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();

            // Skip hidden files if not including them
            if !config.include_hidden {
                if let Ok(metadata) = path.symlink_metadata() {
                    if metadata.file_type().is_dir() {
                        if let Some(name) = path.file_name() {
                            if name.to_string_lossy().starts_with('.') {
                                continue;
                            }
                        }
                    } else if let Ok(attr) = fs::metadata(&path) {
                        if attr.file_attributes() & 0x2 != 0 {
                            // Hidden attribute
                            continue;
                        }
                    }
                }
            }

            if path.is_dir() {
                new_dirs.push(path);
            } else if path.is_file() {
                files_scanned.fetch_add(1, Ordering::Relaxed);

                if let Ok(metadata) = fs::metadata(&path) {
                    total_files.fetch_add(1, Ordering::Relaxed);

                    if let Ok(file) = self.process_file(&path, &metadata, config) {
                        files.push(file);
                    }
                }
            }
        }

        Ok(new_dirs)
    }

    /// Process a single file
    fn process_file(
        &self,
        path: &Path,
        metadata: &fs::Metadata,
        config: &LargeFileConfig,
    ) -> Result<LargeFile, Box<dyn Error>> {
        let file_size = metadata.len();

        // Check minimum size
        if file_size < config.min_size_bytes {
            return Err("File too small".into());
        }

        // Check maximum size
        if let Some(max_size) = config.max_size_bytes {
            if file_size > max_size {
                return Err("File too large".into());
            }
        }

        // Get extension
        let extension = path
            .extension()
            .and_then(|e| Some(e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();

        // Check include extensions
        if !config.include_extensions.is_empty() && !config.include_extensions.contains(&extension)
        {
            return Err("Extension not in include list".into());
        }

        // Check exclude extensions
        if config.exclude_extensions.contains(&extension) {
            return Err("Extension in exclude list".into());
        }

        // Get file age
        let last_modified = metadata.modified()?;
        let age_days = get_age_days(&last_modified);

        // Check minimum age
        if config.min_age_days > 0 && age_days < config.min_age_days as i64 {
            return Err("File too new".into());
        }

        // Check maximum age
        if config.max_age_days > 0 && age_days > config.max_age_days as i64 {
            return Err("File too old".into());
        }

        // Get file name
        let name = path
            .file_name()
            .and_then(|n| Some(n.to_string_lossy().to_string()))
            .unwrap_or_default();

        // Categorize the file
        let file_category = self.categorize_file(&name, &extension);

        // Check if file is locked
        let is_locked = self.is_file_locked(path);

        // Format size
        let size_formatted = format_file_size(file_size);

        Ok(LargeFile {
            path: path.to_path_buf(),
            size_bytes: file_size,
            size_formatted,
            extension,
            name,
            last_modified,
            age_days: age_days as u32,
            file_category,
            is_locked,
            hash: None,
        })
    }

    /// Categorize a file based on extension and name
    fn categorize_file(&self, name: &str, extension: &str) -> FileCategory {
        let name_lower = name.to_lowercase();
        let ext_lower = extension.to_lowercase();

        // Video files
        let video_exts = [
            "mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "m4v", "mpeg", "mpg",
        ];
        if video_exts.contains(&ext_lower.as_str()) || name_lower.contains("video") {
            return FileCategory::Video;
        }

        // Disk images
        let disk_exts = ["iso", "bin", "nrg", "img", "dmg", "vhd", "vhdx"];
        if disk_exts.contains(&ext_lower.as_str()) {
            return FileCategory::DiskImage;
        }

        // Game files
        let game_names = ["game", "mod", "save", "gamedata", "steamapps"];
        let game_exts = ["pak", "sig", "dat", "sav"];
        if game_names.iter().any(|n| name_lower.contains(n))
            || game_exts.contains(&ext_lower.as_str())
        {
            return FileCategory::Game;
        }

        // Archives
        let archive_exts = ["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "zst"];
        if archive_exts.contains(&ext_lower.as_str()) {
            return FileCategory::Archive;
        }

        // Audio
        let audio_exts = ["mp3", "flac", "wav", "aac", "ogg", "m4a", "wma"];
        if audio_exts.contains(&ext_lower.as_str()) {
            return FileCategory::Audio;
        }

        // Virtual machines
        let vm_exts = ["vmdk", "vhd", "vhdx", "qcow2", "ova", "ovf"];
        if vm_exts.contains(&ext_lower.as_str()) {
            return FileCategory::VirtualMachine;
        }

        // Database
        let db_exts = ["mdb", "accdb", "sqlite", "db", "sql", "postgres"];
        if db_exts.contains(&ext_lower.as_str()) || name_lower.contains("database") {
            return FileCategory::Database;
        }

        // Backups
        if name_lower.contains("backup") || name_lower.contains("bak") {
            return FileCategory::Backup;
        }

        // Logs
        let log_exts = ["log", "txt"];
        if log_exts.contains(&ext_lower.as_str()) && name_lower.contains("log") {
            return FileCategory::Log;
        }

        // Development
        let dev_names = ["node_modules", ".git", "build", "dist", "target"];
        if dev_names.iter().any(|n| name_lower.contains(n)) {
            return FileCategory::Development;
        }

        FileCategory::Other
    }

    /// Check if a file is locked by another process
    fn is_file_locked(&self, _path: &Path) -> bool {
        // Try to open with exclusive access
        // If it fails, the file might be locked
        // This is a simplified check - a full implementation would use Windows API
        false
    }

    /// Process scan results
    fn process_results(
        &self,
        mut files: Vec<LargeFile>,
        errors: Vec<ScanError>,
        scan_duration: Duration,
    ) -> LargeFileScanResult {
        // Sort by size (largest first)
        files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

        // Calculate totals
        let total_size_bytes: u64 = files.iter().map(|f| f.size_bytes).sum();
        let file_count = files.len();

        // Group by category
        let mut files_by_category: HashMap<FileCategory, Vec<LargeFile>> = HashMap::new();
        let mut category_counts: HashMap<FileCategory, usize> = HashMap::new();

        for file in &files {
            files_by_category
                .entry(file.file_category.clone())
                .or_insert_with(Vec::new)
                .push(file.clone());

            *category_counts
                .entry(file.file_category.clone())
                .or_insert(0) += 1;
        }

        // Get top 10 largest files
        let top_files = files.iter().take(10).cloned().collect();

        // Get files older than 30 days
        let old_files: Vec<LargeFile> = files
            .iter()
            .filter(|f| f.age_days > 30)
            .take(20)
            .cloned()
            .collect();

        LargeFileScanResult {
            files,
            files_by_category,
            total_size_bytes,
            file_count,
            category_counts,
            scan_duration,
            directories_scanned: 0,
            files_scanned: 0,
            top_files,
            old_files,
            errors,
        }
    }

    /// Get files by category
    pub fn get_by_category(
        &self,
        result: &LargeFileScanResult,
        category: FileCategory,
    ) -> Vec<&LargeFile> {
        result
            .files
            .iter()
            .filter(|f| f.file_category == category)
            .collect()
    }

    /// Get largest N files
    pub fn get_largest(&self, result: &LargeFileScanResult, n: usize) -> Vec<&LargeFile> {
        result.files.iter().take(n).collect()
    }

    /// Get oldest N files
    pub fn get_oldest(&self, result: &LargeFileScanResult, n: usize) -> Vec<&LargeFile> {
        let mut files: Vec<&LargeFile> = result.files.iter().collect();
        files.sort_by(|a, b| a.last_modified.cmp(&b.last_modified));
        files.into_iter().take(n).collect()
    }

    /// Get total size by category
    pub fn get_size_by_category(&self, result: &LargeFileScanResult) -> HashMap<FileCategory, u64> {
        let mut sizes: HashMap<FileCategory, u64> = HashMap::new();
        for file in &result.files {
            *sizes.entry(file.file_category.clone()).or_insert(0) += file.size_bytes;
        }
        sizes
    }
}

impl Default for LargeFileFinder {
    fn default() -> Self {
        Self::new()
    }
}

/// Get available drives on Windows
fn get_drives() -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut drives = Vec::new();

    // Get logical drives
    if let Ok(drives_str) = std::env::var("SystemDrive") {
        drives.push(PathBuf::from(&drives_str));
    }

    // Also scan other fixed drives
    for i in b'C'..=b'Z' {
        let drive_path = format!("{}:\\", i as char);
        let path = Path::new(&drive_path);
        if path.exists() {
            if !drives.contains(&path.to_path_buf()) {
                drives.push(path.to_path_buf());
            }
        }
    }

    Ok(drives)
}

/// Calculate age of a file in days
fn get_age_days(modified: &SystemTime) -> i64 {
    match modified.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() / 86400,
        Err(_) => 0,
    }
}

/// Format file size for display
fn format_file_size(size_bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if size_bytes >= TB {
        format!("{:.2} TB", size_bytes as f64 / TB as f64)
    } else if size_bytes >= GB {
        format!("{:.2} GB", size_bytes as f64 / GB as f64)
    } else if size_bytes >= MB {
        format!("{:.2} MB", size_bytes as f64 / MB as f64)
    } else if size_bytes >= KB {
        format!("{:.2} KB", size_bytes as f64 / KB as f64)
    } else {
        format!("{} B", size_bytes)
    }
}

impl fmt::Display for LargeFileScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Large File Scan Results")?;
        writeln!(f, "=======================")?;
        writeln!(f, "Scan Duration: {:?}", self.scan_duration)?;
        writeln!(f, "Files Scanned: {}", self.files_scanned)?;
        writeln!(f, "Directories Scanned: {}", self.directories_scanned)?;
        writeln!(f)?;
        writeln!(f, "Large Files Found: {}", self.file_count)?;
        writeln!(
            f,
            "Total Size: {} ({:.2} GB)",
            self.total_size_bytes,
            self.total_size_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
        )?;
        writeln!(f)?;

        writeln!(f, "By Category:")?;
        for (category, count) in &self.category_counts {
            let size: u64 = self.files_by_category[category]
                .iter()
                .map(|f| f.size_bytes)
                .sum();
            writeln!(
                f,
                "  {:?}: {} files ({})",
                category,
                count,
                format_file_size(size)
            )?;
        }

        writeln!(f)?;
        writeln!(f, "Top 10 Largest Files:")?;
        for (i, file) in self.top_files.iter().enumerate() {
            writeln!(
                f,
                "{}. {} - {} ({})",
                i + 1,
                file.name,
                file.size_formatted,
                file.path.display()
            )?;
        }

        if !self.old_files.is_empty() {
            writeln!(f)?;
            writeln!(f, "Files Older Than 30 Days:")?;
            for (i, file) in self.old_files.iter().enumerate().take(5) {
                writeln!(
                    f,
                    "{}. {} - {} ({} days old)",
                    i + 1,
                    file.name,
                    file.size_formatted,
                    file.age_days
                )?;
            }
        }

        if !self.errors.is_empty() {
            writeln!(f)?;
            writeln!(f, "Errors ({} total):", self.errors.len())?;
            for error in &self.errors {
                writeln!(f, "  - {}: {}", error.path.display(), error.message)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for FileCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileCategory::Video => write!(f, "Video"),
            FileCategory::DiskImage => write!(f, "Disk Image"),
            FileCategory::Game => write!(f, "Game"),
            FileCategory::Archive => write!(f, "Archive"),
            FileCategory::Audio => write!(f, "Audio"),
            FileCategory::Database => write!(f, "Database"),
            FileCategory::Backup => write!(f, "Backup"),
            FileCategory::Log => write!(f, "Log"),
            FileCategory::VirtualMachine => write!(f, "Virtual Machine"),
            FileCategory::Development => write!(f, "Development"),
            FileCategory::Other => write!(f, "Other"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_large_file_finder_creation() {
        let finder = LargeFileFinder::new();
        assert!(finder.config.min_size_bytes > 0);
    }

    #[test]
    fn test_config_defaults() {
        let config = LargeFileConfig::default();
        assert_eq!(config.min_size_bytes, 100 * 1024 * 1024);
        assert!(config.exclude_extensions.contains(&"dll".to_string()));
    }

    #[test]
    fn test_config_builder() {
        let config = LargeFileConfig::new()
            .with_min_size(500 * 1024 * 1024)
            .include_extension("mp4")
            .with_min_age(30)
            .with_thread_count(8);

        assert_eq!(config.min_size_bytes, 500 * 1024 * 1024);
        assert!(config.include_extensions.contains(&"mp4".to_string()));
        assert_eq!(config.min_age_days, 30);
        assert_eq!(config.thread_count, 8);
    }

    #[test]
    fn test_categorize_file() {
        let finder = LargeFileFinder::new();

        assert_eq!(
            finder.categorize_file("video.mp4", "mp4"),
            FileCategory::Video
        );
        assert_eq!(
            finder.categorize_file("game.iso", "iso"),
            FileCategory::DiskImage
        );
        assert_eq!(
            finder.categorize_file("backup.zip", "zip"),
            FileCategory::Archive
        );
        assert_eq!(
            finder.categorize_file("unknown.dat", "dat"),
            FileCategory::Other
        );
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(500), "500 B");
        assert_eq!(format_file_size(2048), "2.00 KB");
        assert_eq!(format_file_size(1048576), "1.00 MB");
        assert_eq!(format_file_size(1073741824), "1.00 GB");
        assert_eq!(format_file_size(1099511627776), "1.00 TB");
    }

    #[test]
    fn test_scan_result_display() {
        let result = LargeFileScanResult::default();
        let display = format!("{}", result);
        assert!(display.contains("Large File Scan Results"));
        assert!(display.contains("Large Files Found: 0"));
    }

    #[test]
    fn test_file_category_variants() {
        assert_eq!(FileCategory::Video, FileCategory::Video);
        assert_ne!(FileCategory::Video, FileCategory::Audio);
    }

    #[test]
    fn test_large_file_creation() {
        let file = LargeFile {
            path: PathBuf::from(r"C:\test\video.mp4"),
            size_bytes: 1024 * 1024 * 1024,
            size_formatted: "1.00 GB".to_string(),
            extension: "mp4".to_string(),
            name: "video.mp4".to_string(),
            last_modified: SystemTime::UNIX_EPOCH,
            age_days: 0,
            file_category: FileCategory::Video,
            is_locked: false,
            hash: None,
        };

        assert_eq!(file.size_bytes, 1073741824);
        assert_eq!(file.file_category, FileCategory::Video);
    }
}
