//! Scanner module for finding files to clean
//! Searches for temporary files and browser caches on Windows

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Represents a file found during scanning that can be cleaned
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Path to the file
    pub file_path: PathBuf,
    /// Size of the file in bytes
    pub file_size: u64,
    /// Type/category of the file
    pub file_type: FileType,
}

/// Type of file for categorization
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileType {
    /// Windows temporary files
    Temp,
    /// Chrome browser cache
    ChromeCache,
    /// Microsoft Edge browser cache
    EdgeCache,
    /// Firefox browser cache
    FirefoxCache,
}

/// Scanner configuration and execution
#[derive(Debug, Default)]
pub struct Scanner {
    /// Whether to include temp files
    pub include_temp: bool,
    /// Whether to include Chrome cache
    pub include_chrome: bool,
    /// Whether to include Edge cache
    pub include_edge: bool,
    /// Whether to include Firefox cache
    pub include_firefox: bool,
}

impl Scanner {
    /// Create a new scanner with default settings (all enabled)
    pub fn new() -> Self {
        Self {
            include_temp: true,
            include_chrome: true,
            include_edge: true,
            include_firefox: true,
        }
    }

    /// Enable scanning for temp files
    #[must_use]
    pub fn with_temp(mut self, enabled: bool) -> Self {
        self.include_temp = enabled;
        self
    }

    /// Enable scanning for Chrome cache
    #[must_use]
    pub fn with_chrome(mut self, enabled: bool) -> Self {
        self.include_chrome = enabled;
        self
    }

    /// Enable scanning for Edge cache
    #[must_use]
    pub fn with_edge(mut self, enabled: bool) -> Self {
        self.include_edge = enabled;
        self
    }

    /// Enable scanning for Firefox cache
    #[must_use]
    pub fn with_firefox(mut self, enabled: bool) -> Self {
        self.include_firefox = enabled;
        self
    }

    /// Run the scan and return all found files
    pub fn scan(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        if self.include_temp {
            results.extend(self.scan_temp_files(&mut seen));
        }
        if self.include_chrome {
            results.extend(self.scan_chrome_cache(&mut seen));
        }
        if self.include_edge {
            results.extend(self.scan_edge_cache(&mut seen));
        }
        if self.include_firefox {
            results.extend(self.scan_firefox_cache(&mut seen));
        }

        results
    }

    /// Scan Windows temp directory
    fn scan_temp_files(&self, seen: &mut HashSet<PathBuf>) -> Vec<ScanResult> {
        let mut results = Vec::new();

        if let Ok(temp_path) = std::env::var("TEMP") {
            self.scan_directory(Path::new(&temp_path), FileType::Temp, seen, &mut results);
        }

        // Also check Windows temp directory
        let windows_temp = Path::new(r"C:\Windows\Temp");
        self.scan_directory(windows_temp, FileType::Temp, seen, &mut results);

        results
    }

    /// Scan Chrome cache directories
    fn scan_chrome_cache(&self, seen: &mut HashSet<PathBuf>) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // Chrome local app data path
        if let Ok(app_data) = std::env::var("LOCALAPPDATA") {
            let chrome_path = Path::new(&app_data).join(r"Google\Chrome\User Data\Default\Cache");
            self.scan_directory(&chrome_path, FileType::ChromeCache, seen, &mut results);

            // Also scan Cache2 for newer Chrome versions
            let cache2_path = Path::new(&app_data).join(r"Google\Chrome\User Data\Default\Cache2");
            self.scan_directory(&cache2_path, FileType::ChromeCache, seen, &mut results);

            // Chrome media cache
            let media_cache =
                Path::new(&app_data).join(r"Google\Chrome\User Data\Default\Media Cache");
            self.scan_directory(&media_cache, FileType::ChromeCache, seen, &mut results);
        }

        results
    }

    /// Scan Edge cache directories
    fn scan_edge_cache(&self, seen: &mut HashSet<PathBuf>) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // Edge local app data path
        if let Ok(app_data) = std::env::var("LOCALAPPDATA") {
            let edge_path = Path::new(&app_data).join(r"Microsoft\Edge\User Data\Default\Cache");
            self.scan_directory(&edge_path, FileType::EdgeCache, seen, &mut results);

            // Edge cache2
            let cache2_path = Path::new(&app_data).join(r"Microsoft\Edge\User Data\Default\Cache2");
            self.scan_directory(&cache2_path, FileType::EdgeCache, seen, &mut results);

            // Edge media cache
            let media_cache =
                Path::new(&app_data).join(r"Microsoft\Edge\User Data\Default\Media Cache");
            self.scan_directory(&media_cache, FileType::EdgeCache, seen, &mut results);
        }

        results
    }

    /// Scan Firefox cache directories
    fn scan_firefox_cache(&self, seen: &mut HashSet<PathBuf>) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // Firefox cache location
        if let Ok(app_data) = std::env::var("LOCALAPPDATA") {
            let firefox_path = Path::new(&app_data).join(r"Mozilla\Firefox\Profiles");
            if firefox_path.exists() {
                if let Ok(entries) = fs::read_dir(&firefox_path) {
                    for entry in entries.flatten() {
                        let profile_path = entry.path().join("cache2");
                        self.scan_directory(
                            &profile_path,
                            FileType::FirefoxCache,
                            seen,
                            &mut results,
                        );

                        // Also check for startup cache
                        let startup_cache = entry.path().join("startupCache");
                        self.scan_directory(
                            &startup_cache,
                            FileType::FirefoxCache,
                            seen,
                            &mut results,
                        );
                    }
                }
            }
        }

        results
    }

    /// Recursively scan a directory for files
    fn scan_directory(
        &self,
        dir: &Path,
        file_type: FileType,
        seen: &mut HashSet<PathBuf>,
        results: &mut Vec<ScanResult>,
    ) {
        if !dir.exists() || !dir.is_dir() {
            return;
        }

        let mut dirs_to_scan = Vec::new();

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    // Skip hidden/system directories
                    if let Some(name) = path.file_name() {
                        let name_str = name.to_string_lossy();
                        if !name_str.starts_with('.') && name_str != "System Volume Information" {
                            dirs_to_scan.push(path);
                        }
                    }
                } else if path.is_file() {
                    // Deduplicate by canonical path
                    if let Ok(canonical) = path.canonicalize() {
                        if !seen.contains(&canonical) {
                            seen.insert(canonical.clone());

                            if let Ok(metadata) = fs::metadata(&path) {
                                results.push(ScanResult {
                                    file_path: canonical,
                                    file_size: metadata.len(),
                                    file_type: file_type.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Recursively scan subdirectories
        for subdir in dirs_to_scan {
            self.scan_directory(&subdir, file_type.clone(), seen, results);
        }
    }

    /// Get total size of files in bytes
    pub fn calculate_total_size(results: &[ScanResult]) -> u64 {
        results.iter().map(|r| r.file_size).sum()
    }
}

impl ScanResult {
    /// Creates a new scan result
    pub fn new(path: PathBuf, size: u64, file_type: FileType) -> Self {
        ScanResult {
            file_path: path,
            file_size: size,
            file_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_scan_result_creation() {
        let result = ScanResult::new(PathBuf::from(r"C:\test\file.txt"), 1024, FileType::Temp);
        assert_eq!(result.file_size, 1024);
        assert_eq!(result.file_type, FileType::Temp);
    }

    #[test]
    fn test_scanner_default() {
        let scanner = Scanner::new();
        assert!(scanner.include_temp);
        assert!(scanner.include_chrome);
        assert!(scanner.include_edge);
        assert!(scanner.include_firefox);
    }

    #[test]
    fn test_scanner_with_options() {
        let scanner = Scanner::new()
            .with_temp(false)
            .with_chrome(false)
            .with_edge(true)
            .with_firefox(true);

        assert!(!scanner.include_temp);
        assert!(!scanner.include_chrome);
        assert!(scanner.include_edge);
        assert!(scanner.include_firefox);
    }

    #[test]
    fn test_calculate_total_size() {
        let results = vec![
            ScanResult::new(PathBuf::from("a.txt"), 100, FileType::Temp),
            ScanResult::new(PathBuf::from("b.txt"), 200, FileType::ChromeCache),
            ScanResult::new(PathBuf::from("c.txt"), 300, FileType::EdgeCache),
        ];

        assert_eq!(Scanner::calculate_total_size(&results), 600);
    }

    #[test]
    fn test_file_type_equality() {
        assert_eq!(FileType::ChromeCache, FileType::ChromeCache);
        assert_ne!(FileType::ChromeCache, FileType::EdgeCache);
    }
}
