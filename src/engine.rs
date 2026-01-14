//! Engine module for executing file operations with rollback support
//! Handles apply, undo, and dry-run operations

use std::fs;
use std::io;
use std::path::Path;

use super::checkpoint::{Checkpoint, CheckpointManager};
use super::scanner::{FileType, ScanResult};

/// Result of an apply operation
#[derive(Debug, Default)]
pub struct ApplyResult {
    /// Number of files deleted
    pub files_deleted: usize,
    /// Number of files skipped
    pub files_skipped: usize,
    /// Total bytes freed
    pub bytes_freed: u64,
    /// Path to checkpoint file
    pub checkpoint_path: Option<String>,
    /// List of errors
    pub errors: Vec<String>,
}

impl ApplyResult {
    /// Creates a new empty apply result
    pub fn new() -> Self {
        ApplyResult {
            files_deleted: 0,
            files_skipped: 0,
            bytes_freed: 0,
            checkpoint_path: None,
            errors: Vec::new(),
        }
    }

    /// Returns true if any errors occurred
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Adds an error message
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }
}

/// Result of an undo operation
#[derive(Debug, Default)]
pub struct UndoResult {
    /// Number of files restored
    pub files_restored: usize,
    /// Number of bytes restored
    pub bytes_restored: u64,
    /// Path to checkpoint file
    pub checkpoint_path: String,
    /// List of errors
    pub errors: Vec<String>,
}

impl UndoResult {
    /// Creates a new empty undo result
    pub fn new() -> Self {
        UndoResult {
            files_restored: 0,
            bytes_restored: 0,
            checkpoint_path: String::new(),
            errors: Vec::new(),
        }
    }

    /// Returns true if any errors occurred
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Adds an error message
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }
}

/// Status information for a checkpoint
#[derive(Debug, Clone)]
pub struct CheckpointStatus {
    /// Path to checkpoint file
    pub path: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Number of files in checkpoint
    pub file_count: usize,
    /// Total size of files
    pub total_size: u64,
    /// Description
    pub description: String,
}

/// Overall system status
#[derive(Debug, Default)]
pub struct StatusResult {
    /// Latest checkpoint info
    pub last_checkpoint: Option<CheckpointStatus>,
    /// Number of available checkpoints
    pub available_checkpoints: usize,
    /// System information
    pub system_info: SystemInfo,
}

/// System information
#[derive(Debug, Default)]
pub struct SystemInfo {
    /// Whether temp directory exists
    pub temp_dir_exists: bool,
    /// Number of temp files
    pub temp_files_count: usize,
    /// Whether Chrome cache exists
    pub chrome_cache_exists: bool,
    /// Whether Edge cache exists
    pub edge_cache_exists: bool,
    /// Whether Firefox cache exists
    pub firefox_cache_exists: bool,
}

/// Engine for executing file operations
pub struct Engine {
    /// Checkpoint manager instance
    checkpoint_manager: CheckpointManager,
    /// Whether dry-run mode is enabled
    dry_run: bool,
}

impl Engine {
    /// Creates a new engine instance
    pub fn new() -> io::Result<Self> {
        let checkpoint_manager = CheckpointManager::new()?;
        Ok(Engine {
            checkpoint_manager,
            dry_run: false,
        })
    }

    /// Applies cleanup by deleting files from the scan result
    pub fn apply(&mut self, scan_result: &[ScanResult], _dry_run: bool) -> ApplyResult {
        let mut result = ApplyResult::new();

        if scan_result.is_empty() {
            return result;
        }

        // Create checkpoint before deletion
        let mut checkpoint = Checkpoint::new("Pre-cleanup checkpoint".to_string());

        for file in scan_result {
            let category = match file.file_type {
                FileType::Temp => "temp",
                FileType::ChromeCache => "chrome_cache",
                FileType::EdgeCache => "edge_cache",
                FileType::FirefoxCache => "firefox_cache",
            };

            let modified = fs::metadata(&file.file_path)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

            checkpoint.add_file(&file.file_path, file.file_size, modified, category);
        }

        // Save checkpoint
        match self.checkpoint_manager.save(&checkpoint) {
            Ok(path) => {
                result.checkpoint_path = Some(path.to_string_lossy().to_string());
            }
            Err(e) => {
                result.add_error(format!("Failed to save checkpoint: {}", e));
            }
        }

        // Delete files
        for file in scan_result {
            if self.dry_run {
                result.files_skipped += 1;
                result.bytes_freed += file.file_size;
            } else {
                match self.delete_file(&file.file_path) {
                    Ok(()) => {
                        result.files_deleted += 1;
                        result.bytes_freed += file.file_size;
                    }
                    Err(e) => {
                        result.add_error(format!(
                            "Failed to delete {}: {}",
                            file.file_path.display(),
                            e
                        ));
                    }
                }
            }
        }

        result
    }

    /// Deletes a single file
    fn delete_file(&self, path: &Path) -> io::Result<()> {
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Undo a previous cleanup operation
    pub fn undo(&mut self, checkpoint_path: Option<&Path>, _dry_run: bool) -> UndoResult {
        let mut result = UndoResult::new();

        let path = match checkpoint_path {
            Some(p) => p.to_path_buf(),
            None => match self.checkpoint_manager.get_latest_checkpoint() {
                Ok(Some(p)) => p,
                Ok(None) => {
                    result.add_error("No checkpoints found".to_string());
                    return result;
                }
                Err(e) => {
                    result.add_error(format!("Failed to find checkpoint: {}", e));
                    return result;
                }
            },
        };

        result.checkpoint_path = path.to_string_lossy().to_string();

        let checkpoint = match self.checkpoint_manager.load(&path) {
            Ok(cp) => cp,
            Err(e) => {
                result.add_error(format!("Failed to load checkpoint: {}", e));
                return result;
            }
        };

        match self.checkpoint_manager.restore(&checkpoint, self.dry_run) {
            Ok(restore_result) => {
                result.files_restored = restore_result.files_restored;
                result.bytes_restored = restore_result.size_restored;

                for error in restore_result.errors {
                    result.add_error(error);
                }

                if !result.has_errors() && !self.dry_run {
                    if let Err(e) = self.checkpoint_manager.delete(&path) {
                        result.add_error(format!("Failed to delete checkpoint: {}", e));
                    }
                }
            }
            Err(e) => {
                result.add_error(format!("Failed to restore: {}", e));
            }
        }

        result
    }

    /// Gets the status of available checkpoints
    pub fn status(&mut self) -> StatusResult {
        let mut status = StatusResult::default();

        status.system_info = self.get_system_info();

        match self.checkpoint_manager.list_checkpoints() {
            Ok(checkpoints) => {
                status.available_checkpoints = checkpoints.len();

                if let Some(latest) = checkpoints.first() {
                    if let Ok(cp) = self.checkpoint_manager.load(latest) {
                        status.last_checkpoint = Some(CheckpointStatus {
                            path: latest.to_string_lossy().to_string(),
                            created_at: cp.timestamp,
                            file_count: cp.len(),
                            total_size: cp.total_size(),
                            description: cp.description,
                        });
                    }
                }
            }
            Err(_) => {}
        }

        status
    }

    /// Gets system information
    fn get_system_info(&self) -> SystemInfo {
        let mut info = SystemInfo::default();

        let temp_path = std::env::temp_dir();
        info.temp_dir_exists = temp_path.exists();

        if info.temp_dir_exists {
            info.temp_files_count = count_files_in_directory(&temp_path);
        }

        if let Some(app_data) = std::env::var_os("LOCALAPPDATA") {
            let base = Path::new(&app_data);
            info.chrome_cache_exists = base.join(r"Google\Chrome\User Data\Default\Cache").exists();
            info.edge_cache_exists = base
                .join(r"Microsoft\Edge\User Data\Default\Cache")
                .exists();
        }

        if let Some(app_data) = std::env::var_os("APPDATA") {
            info.firefox_cache_exists = Path::new(&app_data)
                .join(r"Mozilla\Firefox\Profiles")
                .exists();
        }

        info
    }

    /// Lists all available checkpoints
    pub fn list_checkpoints(&self) -> io::Result<Vec<CheckpointStatus>> {
        let mut statuses = Vec::new();
        let checkpoints = self.checkpoint_manager.list_checkpoints()?;

        for path in checkpoints {
            if let Ok(cp) = self.checkpoint_manager.load(&path) {
                statuses.push(CheckpointStatus {
                    path: path.to_string_lossy().to_string(),
                    created_at: cp.timestamp,
                    file_count: cp.len(),
                    total_size: cp.total_size(),
                    description: cp.description,
                });
            }
        }

        Ok(statuses)
    }

    /// Gets the path to the latest checkpoint
    pub fn get_latest_checkpoint(&self) -> io::Result<Option<std::path::PathBuf>> {
        self.checkpoint_manager.get_latest_checkpoint()
    }

    /// Gets the checkpoint manager for direct access
    pub fn checkpoint_manager(&self) -> &CheckpointManager {
        &self.checkpoint_manager
    }

    /// Sets the dry-run mode
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }
}

/// Counts files in a directory
fn count_files_in_directory(path: &Path) -> usize {
    if !path.exists() || !path.is_dir() {
        return 0;
    }

    let mut count = 0;

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.path().is_file() {
                count += 1;
            }
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_result_creation() {
        let result = ApplyResult::new();
        assert_eq!(result.files_deleted, 0);
        assert!(!result.has_errors());
    }

    #[test]
    fn test_undo_result_creation() {
        let result = UndoResult::new();
        assert_eq!(result.files_restored, 0);
        assert!(!result.has_errors());
    }

    #[test]
    fn test_checkpoint_status_creation() {
        let status = CheckpointStatus {
            path: r"C:\test\checkpoint.json".to_string(),
            created_at: 1234567890,
            file_count: 10,
            total_size: 10240,
            description: "Test checkpoint".to_string(),
        };

        assert_eq!(status.file_count, 10);
        assert_eq!(status.total_size, 10240);
    }
}
