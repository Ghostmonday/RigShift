//! Universal Checkpoint System for RigShift
//!
//! Provides a unified checkpoint/rollback system that saves the state of all
//! system modifications (registry, startup, services, privacy) to disk.
//! This enables safe undo operations for all optimization features.
//!
//! Checkpoint Structure:
//! %APPDATA%/RigShift/checkpoints/
//!   ├── registry/              # Registry backup checkpoints
//!   │   └── 1705320000_registry.json
//!   ├── startup/               # Startup item backups
//!   │   └── 1705320000_startup.json
//!   ├── services/              # Service state backups
//!   │   └── 1705320000_services.json
//!   ├── privacy/               # Privacy settings backups
//!   │   └── 1705320000_privacy.json
//!   └── latest.json            # Most recent checkpoint reference

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Type of checkpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointType {
    /// Registry changes
    Registry,
    /// Startup programs
    Startup,
    /// Windows services
    Services,
    /// Privacy settings
    Privacy,
    /// Large file deletion
    LargeFiles,
    /// Program uninstallation
    Uninstall,
    /// Full system optimization
    FullSystem,
    /// Custom/unknown
    Custom(String),
}

/// A single backup entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    /// Type of entry
    pub entry_type: EntryType,
    /// Original location/key path
    pub path: String,
    /// Value name (if registry)
    pub value_name: Option<String>,
    /// Data before modification
    pub data: BackupData,
    /// Description
    pub description: String,
    /// Timestamp of backup
    pub timestamp: u64,
}

/// Type of backup entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryType {
    /// Registry key value
    RegistryValue,
    /// Registry key (with all values)
    RegistryKey,
    /// File deletion
    File,
    /// Directory deletion
    Directory,
    /// Service configuration
    Service,
    /// Startup folder item
    StartupFolder,
    /// Scheduled task
    Task,
}

/// Data backup container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupData {
    /// Registry DWORD value
    Dword(u32),
    /// Registry string value
    String(String),
    /// Registry binary data
    Binary(Vec<u8>),
    /// Registry multi-string (REG_MULTI_SZ)
    MultiString(Vec<String>),
    /// Registry expand string
    ExpandString(String),
    /// File contents (for small files)
    FileContents(Vec<u8>),
    /// File metadata only
    FileMetadata(FileMetadata),
    /// Service configuration blob
    ServiceConfig(Vec<u8>),
    /// Custom data
    Custom(HashMap<String, String>),
}

/// File metadata for backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: String,
    pub size: u64,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub attributes: u32,
}

/// Main checkpoint structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalCheckpoint {
    /// Checkpoint version
    pub version: u32,
    /// Unique checkpoint ID
    pub id: String,
    /// Type of checkpoint
    pub checkpoint_type: CheckpointType,
    /// Description
    pub description: String,
    /// Created timestamp
    pub created_at: u64,
    /// Number of entries
    pub entry_count: usize,
    /// Total data size
    pub total_size: u64,
    /// Entries
    pub entries: Vec<BackupEntry>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Result of a checkpoint operation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckpointResult {
    /// Whether operation was successful
    pub success: bool,
    /// Checkpoint ID
    pub checkpoint_id: Option<String>,
    /// Path to checkpoint file
    pub checkpoint_path: Option<String>,
    /// Number of entries backed up
    pub entries_count: usize,
    /// Total size of backup
    pub size_bytes: u64,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Warnings
    pub warnings: Vec<String>,
    /// Time taken
    pub duration_ms: u128,
}

/// Result of a restore operation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RestoreCheckpointResult {
    /// Whether operation was successful
    pub success: bool,
    /// Number of entries restored
    pub entries_restored: usize,
    /// Number of entries failed
    pub entries_failed: usize,
    /// Total size restored
    pub size_bytes: u64,
    /// Errors
    pub errors: Vec<String>,
    /// Time taken
    pub duration_ms: u128,
}

/// Universal Checkpoint Manager
pub struct UniversalCheckpointManager {
    /// Base checkpoint directory
    checkpoint_dir: PathBuf,
    /// Latest checkpoint reference file
    latest_file: PathBuf,
}

impl UniversalCheckpointManager {
    /// Create a new checkpoint manager
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let checkpoint_dir = Self::get_checkpoint_dir()?;
        let latest_file = checkpoint_dir.join("latest.json");

        // Create directory structure
        let subdirs = [
            "registry",
            "startup",
            "services",
            "privacy",
            "files",
            "uninstall",
        ];
        for subdir in &subdirs {
            let path = checkpoint_dir.join(subdir);
            if !path.exists() {
                fs::create_dir_all(&path)?;
            }
        }

        Ok(UniversalCheckpointManager {
            checkpoint_dir,
            latest_file,
        })
    }

    /// Get the checkpoint directory
    fn get_checkpoint_dir() -> Result<PathBuf, Box<dyn Error>> {
        let app_data = std::env::var("APPDATA")?;
        let checkpoint_dir = PathBuf::from(app_data).join("RigShift").join("checkpoints");

        if !checkpoint_dir.exists() {
            fs::create_dir_all(&checkpoint_dir)?;
        }

        Ok(checkpoint_dir)
    }

    /// Create a new checkpoint
    pub fn create_checkpoint(
        &self,
        checkpoint_type: CheckpointType,
        description: String,
        entries: Vec<BackupEntry>,
    ) -> CheckpointResult {
        let start_time = SystemTime::now();
        let mut result = CheckpointResult::default();

        let timestamp = Self::now_timestamp();
        let checkpoint_id = format!("{}", timestamp);

        // Calculate total size
        let total_size: u64 = entries.iter().map(|e| self.entry_size(e)).sum();

        // Create checkpoint
        let checkpoint = UniversalCheckpoint {
            version: 1,
            id: checkpoint_id.clone(),
            checkpoint_type: checkpoint_type.clone(),
            description: description.clone(),
            created_at: timestamp,
            entry_count: entries.len(),
            total_size,
            entries: entries.clone(),
            metadata: HashMap::new(),
        };

        // Determine subdirectory
        let subdir = match checkpoint_type {
            CheckpointType::Registry => "registry",
            CheckpointType::Startup => "startup",
            CheckpointType::Services => "services",
            CheckpointType::Privacy => "privacy",
            CheckpointType::LargeFiles => "files",
            CheckpointType::Uninstall => "uninstall",
            CheckpointType::FullSystem => "registry",
            CheckpointType::Custom(_) => "registry",
        };

        // Save checkpoint file
        let checkpoint_path = self
            .checkpoint_dir
            .join(subdir)
            .join(format!("{}.json", checkpoint_id));

        match serde_json::to_string_pretty(&checkpoint) {
            Ok(content) => {
                if let Err(e) = fs::write(&checkpoint_path, &content) {
                    result
                        .errors
                        .push(format!("Failed to write checkpoint: {}", e));
                }
            }
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to serialize checkpoint: {}", e));
            }
        }

        // Update latest reference file
        let latest_content = format!(
            r#"{{"latest": "{}", "type": {:?}, "timestamp": {}, "description": "{}"}}"#,
            checkpoint_path.to_string_lossy(),
            checkpoint_type,
            timestamp,
            description.replace('"', "\\\"")
        );

        if let Err(e) = fs::write(&self.latest_file, &latest_content) {
            result
                .warnings
                .push(format!("Failed to update latest reference: {}", e));
        }

        // Generate export file for registry checkpoints
        if checkpoint_type == CheckpointType::Registry {
            if let Err(e) = self.export_registry_file(&checkpoint, &checkpoint_path) {
                result
                    .warnings
                    .push(format!("Failed to export .reg file: {}", e));
            }
        }

        let duration = SystemTime::now()
            .duration_since(start_time)
            .unwrap_or_default();

        result.success = result.errors.is_empty();
        result.checkpoint_id = Some(checkpoint_id);
        result.checkpoint_path = Some(checkpoint_path.to_string_lossy().to_string());
        result.entries_count = entries.len();
        result.size_bytes = total_size;
        result.duration_ms = duration.as_millis();

        result
    }

    /// Export registry data to .reg file format for Windows registry import
    fn export_registry_file(
        &self,
        checkpoint: &UniversalCheckpoint,
        checkpoint_path: &Path,
    ) -> Result<(), Box<dyn Error>> {
        let reg_path = checkpoint_path.with_extension("reg");

        let mut content = String::new();
        content.push_str("Windows Registry Editor Version 5.00\n\n");
        content.push_str("; RigShift Checkpoint Export\n");
        content.push_str(&format!("; Checkpoint ID: {}\n", checkpoint.id));
        content.push_str(&format!(
            "; Created: {}\n\n",
            Self::format_timestamp(checkpoint.created_at)
        ));

        // Group by key
        let mut key_entries: HashMap<String, Vec<&BackupEntry>> = HashMap::new();
        for entry in &checkpoint.entries {
            if entry.entry_type == EntryType::RegistryValue
                || entry.entry_type == EntryType::RegistryKey
            {
                key_entries
                    .entry(entry.path.clone())
                    .or_insert_with(Vec::new)
                    .push(entry);
            }
        }

        // Write each key
        for (key_path, entries) in key_entries {
            // Convert abbreviations to full names
            let reg_key = Self::format_reg_path(key_path);
            content.push_str(&format!("[{}]\n", reg_key));

            for entry in entries {
                if let Some(value_name) = &entry.value_name {
                    let data_str = Self::format_reg_value(&entry.data);
                    if value_name.is_empty() {
                        content.push_str(&format!("@={}\n", data_str));
                    } else {
                        content.push_str(&format!("\"{}\"={}\n", value_name, data_str));
                    }
                }
            }
            content.push('\n');
        }

        fs::write(&reg_path, content)?;
        Ok(())
    }

    /// Format registry path for .reg file
    fn format_reg_path(path: &str) -> String {
        let mut result = path.to_string();

        let replacements = [
            ("HKLM", "HKEY_LOCAL_MACHINE"),
            ("HKCU", "HKEY_CURRENT_USER"),
            ("HKCR", "HKEY_CLASSES_ROOT"),
            ("HKU", "HKEY_USERS"),
            ("HKCC", "HKEY_CURRENT_CONFIG"),
        ];

        for (abbr, full) in &replacements {
            result = result.replace(abbr, full);
        }

        result
    }

    /// Format registry value for .reg file
    fn format_reg_value(data: &BackupData) -> String {
        match data {
            BackupData::Dword(v) => format!("dword:{:08x}", v),
            BackupData::String(s) => format!("\"{}\"", s.replace('"', "\\\"")),
            BackupData::ExpandString(s) => format!("\"{}\"", s.replace('"', "\\\"")),
            BackupData::Binary(b) => {
                let hex: Vec<String> = b.iter().map(|b| format!("{:02x}", b)).collect();
                format!("hex:{}", hex.join(","))
            }
            BackupData::MultiString(v) => {
                let hex: Vec<String> = v
                    .iter()
                    .flat_map(|s| s.chars().map(|c| format!("{:02x}", c as u8)))
                    .collect();
                format!("hex(2):{}", hex.join(","))
            }
            _ => String::new(),
        }
    }

    /// Restore from a checkpoint
    pub fn restore_checkpoint(
        &self,
        checkpoint_id: &str,
        preview: bool,
    ) -> Result<RestoreCheckpointResult, Box<dyn Error>> {
        let start_time = SystemTime::now();
        let mut result = RestoreCheckpointResult::default();

        // Find checkpoint file
        let checkpoint_path = self.find_checkpoint(checkpoint_id)?;

        // Read checkpoint
        let content = fs::read_to_string(&checkpoint_path)?;
        let checkpoint: UniversalCheckpoint = serde_json::from_str(&content)?;

        // Restore each entry
        let mut entries_restored = 0;
        let mut entries_failed = 0;
        let mut size_restored = 0;

        for entry in &checkpoint.entries {
            if preview {
                println!("Would restore: {} -> {}", entry.path, entry.description);
                continue;
            }

            match self.restore_entry(entry) {
                Ok(Some(size)) => {
                    entries_restored += 1;
                    size_restored += size;
                }
                Ok(None) => {
                    entries_restored += 1;
                }
                Err(e) => {
                    entries_failed += 1;
                    result
                        .errors
                        .push(format!("Failed to restore {}: {}", entry.path, e));
                }
            }
        }

        let duration = SystemTime::now()
            .duration_since(start_time)
            .unwrap_or_default();

        result.success = entries_failed == 0;
        result.entries_restored = entries_restored;
        result.entries_failed = entries_failed;
        result.size_bytes = size_restored;
        result.duration_ms = duration.as_millis();

        Ok(result)
    }

    /// Restore a single entry
    fn restore_entry(&self, entry: &BackupEntry) -> Result<Option<u64>, Box<dyn Error>> {
        match &entry.entry_type {
            EntryType::RegistryValue | EntryType::RegistryKey => {
                self.restore_registry_entry(entry)?;
                Ok(None)
            }
            EntryType::File => self.restore_file(entry),
            EntryType::Directory => self.restore_directory(entry),
            _ => Ok(None),
        }
    }

    /// Restore a registry entry
    fn restore_registry_entry(&self, entry: &BackupEntry) -> Result<(), Box<dyn Error>> {
        use winreg::enums::*;
        use winreg::RegKey;

        let (hive_str, key_path) = self.parse_registry_path(&entry.path)?;

        let hive = match hive_str {
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKEY_USERS" => HKEY_USERS,
            "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
            _ => return Err("Unknown hive".into()),
        };

        // Open or create the key
        let key = RegKey::predef(hive).create_subkey(key_path)?;

        // Set the value
        match &entry.data {
            BackupData::Dword(v) => key.set_value(entry.value_name.as_deref().unwrap_or(""), v)?,
            BackupData::String(s) | BackupData::ExpandString(s) => {
                key.set_value(entry.value_name.as_deref().unwrap_or(""), s)?
            }
            BackupData::Binary(b) => {
                key.set_raw_value(entry.value_name.as_deref().unwrap_or(""), REG_BINARY, b)?
            }
            BackupData::MultiString(v) => {
                key.set_value(entry.value_name.as_deref().unwrap_or(""), v)?
            }
            _ => {}
        }

        Ok(())
    }

    /// Restore a file
    fn restore_file(&self, entry: &BackupEntry) -> Result<Option<u64>, Box<dyn Error>> {
        if let BackupData::FileContents(contents) = &entry.data {
            let path = PathBuf::from(&entry.path);

            // Create parent directories
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }

            fs::write(&path, contents)?;

            return Ok(Some(contents.len() as u64));
        }
        Ok(None)
    }

    /// Restore a directory
    fn restore_directory(&self, entry: &BackupEntry) -> Result<Option<u64>, Box<dyn Error>> {
        let path = PathBuf::from(&entry.path);
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        Ok(None)
    }

    /// Find a checkpoint by ID
    fn find_checkpoint(&self, checkpoint_id: &str) -> Result<PathBuf, Box<dyn Error>> {
        let subdirs = [
            "registry",
            "startup",
            "services",
            "privacy",
            "files",
            "uninstall",
        ];

        for subdir in &subdirs {
            let path = self
                .checkpoint_dir
                .join(subdir)
                .join(format!("{}.json", checkpoint_id));
            if path.exists() {
                return Ok(path);
            }
        }

        // Also try looking in latest.json
        if self.latest_file.exists() {
            if let Ok(content) = fs::read_to_string(&self.latest_file) {
                if let Ok(latest) = serde_json::from_str::<LatestRef>(&content) {
                    if latest.latest.contains(checkpoint_id) {
                        return Ok(PathBuf::from(&latest.latest));
                    }
                }
            }
        }

        Err(format!("Checkpoint {} not found", checkpoint_id).into())
    }

    /// List all checkpoints
    pub fn list_checkpoints(&self) -> Result<Vec<CheckpointInfo>, Box<dyn Error>> {
        let mut checkpoints = Vec::new();

        let subdirs = [
            "registry",
            "startup",
            "services",
            "privacy",
            "files",
            "uninstall",
        ];

        for subdir in &subdirs {
            let dir = self.checkpoint_dir.join(subdir);
            if !dir.exists() {
                continue;
            }

            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if entry
                        .path()
                        .extension()
                        .map(|e| e == "json")
                        .unwrap_or(false)
                    {
                        if let Ok(content) = fs::read_to_string(&entry.path()) {
                            if let Ok(cp) = serde_json::from_str::<UniversalCheckpoint>(&content) {
                                checkpoints.push(CheckpointInfo {
                                    id: cp.id.clone(),
                                    checkpoint_type: cp.checkpoint_type.clone(),
                                    description: cp.description,
                                    created_at: cp.created_at,
                                    entry_count: cp.entry_count,
                                    total_size: cp.total_size,
                                    path: entry.path().to_string_lossy().to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        checkpoints.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(checkpoints)
    }

    /// Delete a checkpoint
    pub fn delete_checkpoint(&self, checkpoint_id: &str) -> Result<(), Box<dyn Error>> {
        let checkpoint_path = self.find_checkpoint(checkpoint_id)?;

        // Delete JSON file
        fs::remove_file(&checkpoint_path)?;

        // Delete associated .reg file if exists
        let reg_path = checkpoint_path.with_extension("reg");
        if reg_path.exists() {
            fs::remove_file(&reg_path)?;
        }

        Ok(())
    }

    /// Get checkpoint info by ID
    pub fn get_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> Result<UniversalCheckpoint, Box<dyn Error>> {
        let path = self.find_checkpoint(checkpoint_id)?;
        let content = fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&content)?)
    }

    /// Calculate entry size
    fn entry_size(&self, entry: &BackupEntry) -> u64 {
        match &entry.data {
            BackupData::String(s) | BackupData::ExpandString(s) => s.len() as u64,
            BackupData::Binary(b) => b.len() as u64,
            BackupData::MultiString(v) => v.iter().map(|s| s.len() as u64).sum(),
            BackupData::FileContents(b) => b.len() as u64,
            BackupData::FileMetadata(m) => m.size,
            BackupData::Dword(_) => 4,
            BackupData::ServiceConfig(b) => b.len() as u64,
            BackupData::Custom(m) => m.values().map(|s| s.len() as u64).sum(),
        }
    }

    /// Parse registry path
    fn parse_registry_path(&self, path: &str) -> Result<(String, String), Box<dyn Error>> {
        for prefix in &[
            "HKEY_LOCAL_MACHINE",
            "HKLM",
            "HKEY_CURRENT_USER",
            "HKCU",
            "HKEY_CLASSES_ROOT",
            "HKCR",
            "HKEY_USERS",
            "HKU",
            "HKEY_CURRENT_CONFIG",
            "HKCC",
        ] {
            if path.starts_with(prefix) {
                let key_path = &path[prefix.len()..].trim_start_matches('\\');
                return Ok((prefix.to_string(), key_path.to_string()));
            }
        }
        Err(format!("Invalid registry path: {}", path).into())
    }

    /// Get current timestamp
    fn now_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Format timestamp for display
    fn format_timestamp(timestamp: u64) -> String {
        let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0);
        if let Some(dt) = datetime {
            dt.format("%Y-%m-%d %H:%M:%S").to_string()
        } else {
            timestamp.to_string()
        }
    }

    /// Get the latest checkpoint
    pub fn get_latest(&self) -> Result<Option<CheckpointInfo>, Box<dyn Error>> {
        if !self.latest_file.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.latest_file)?;
        let latest: LatestRef = serde_json::from_str(&content)?;

        // Extract ID from path
        let path = PathBuf::from(&latest.latest);
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        if let Ok(cp) = self.get_checkpoint(&id) {
            Ok(Some(CheckpointInfo {
                id: cp.id,
                checkpoint_type: cp.checkpoint_type,
                description: cp.description,
                created_at: cp.created_at,
                entry_count: cp.entry_count,
                total_size: cp.total_size,
                path: latest.latest,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Latest checkpoint reference
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LatestRef {
    latest: String,
    timestamp: u64,
    #[serde(skip)]
    checkpoint_type: CheckpointType,
    #[serde(skip)]
    description: String,
}

/// Checkpoint info for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointInfo {
    pub id: String,
    pub checkpoint_type: CheckpointType,
    pub description: String,
    pub created_at: u64,
    pub entry_count: usize,
    pub total_size: u64,
    pub path: String,
}

impl Default for UniversalCheckpointManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            checkpoint_dir: PathBuf::from("checkpoints"),
            latest_file: PathBuf::from("checkpoints/latest.json"),
        })
    }
}

impl fmt::Display for CheckpointResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Checkpoint Created")?;
        writeln!(f, "===============")?;
        writeln!(f, "Success: {}", self.success)?;
        if let Some(id) = &self.checkpoint_id {
            writeln!(f, "ID: {}", id)?;
        }
        if let Some(path) = &self.checkpoint_path {
            writeln!(f, "Path: {}", path)?;
        }
        writeln!(f, "Entries: {}", self.entries_count)?;
        writeln!(f, "Size: {} bytes", self.size_bytes)?;
        writeln!(f, "Duration: {}ms", self.duration_ms)?;

        if !self.errors.is_empty() {
            writeln!(f)?;
            writeln!(f, "Errors:")?;
            for error in &self.errors {
                writeln!(f, "  - {}", error)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for RestoreCheckpointResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Restore Result")?;
        writeln!(f, "=============")?;
        writeln!(f, "Success: {}", self.success)?;
        writeln!(f, "Restored: {}", self.entries_restored)?;
        writeln!(f, "Failed: {}", self.entries_failed)?;
        writeln!(f, "Size: {} bytes", self.size_bytes)?;
        writeln!(f, "Duration: {}ms", self.duration_ms)?;

        if !self.errors.is_empty() {
            writeln!(f)?;
            writeln!(f, "Errors:")?;
            for error in &self.errors {
                writeln!(f, "  - {}", error)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for CheckpointInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "[{:?}] {} - {}",
            self.checkpoint_type,
            Self::format_timestamp(self.created_at),
            self.description
        )?;
        writeln!(
            f,
            "   Entries: {}, Size: {} bytes",
            self.entry_count, self.total_size
        )?;
        writeln!(f, "   ID: {}", self.id)?;
        Ok(())
    }
}

impl CheckpointInfo {
    fn format_timestamp(timestamp: u64) -> String {
        let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0);
        if let Some(dt) = datetime {
            dt.format("%Y-%m-%d %H:%M:%S").to_string()
        } else {
            timestamp.to_string()
        }
    }
}

/// Helper trait for creating checkpoints
pub trait Checkpointable {
    /// Get entries to backup before making changes
    fn get_backup_entries(&self) -> Vec<BackupEntry>;

    /// Get the checkpoint type
    fn get_checkpoint_type(&self) -> CheckpointType;

    /// Get description for checkpoint
    fn get_description(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_entry_creation() {
        let entry = BackupEntry {
            entry_type: EntryType::RegistryValue,
            path: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Test".to_string(),
            value_name: Some("TestValue".to_string()),
            data: BackupData::Dword(123),
            description: "Test backup".to_string(),
            timestamp: 1705320000,
        };

        assert_eq!(entry.entry_type, EntryType::RegistryValue);
        assert_eq!(entry.path, "HKEY_LOCAL_MACHINE\\SOFTWARE\\Test");
    }

    #[test]
    fn test_checkpoint_creation() {
        let entries = vec![
            BackupEntry {
                entry_type: EntryType::RegistryValue,
                path: "HKLM\\SOFTWARE\\Test".to_string(),
                value_name: Some("Value1".to_string()),
                data: BackupData::Dword(1),
                description: "Test 1".to_string(),
                timestamp: 1705320000,
            },
            BackupEntry {
                entry_type: EntryType::RegistryValue,
                path: "HKLM\\SOFTWARE\\Test".to_string(),
                value_name: Some("Value2".to_string()),
                data: BackupData::String("test".to_string()),
                description: "Test 2".to_string(),
                timestamp: 1705320000,
            },
        ];

        let checkpoint = UniversalCheckpoint {
            version: 1,
            id: "1705320000".to_string(),
            checkpoint_type: CheckpointType::Registry,
            description: "Test checkpoint".to_string(),
            created_at: 1705320000,
            entry_count: 2,
            total_size: 0,
            entries: entries.clone(),
            metadata: HashMap::new(),
        };

        assert_eq!(checkpoint.version, 1);
        assert_eq!(checkpoint.entry_count, 2);
        assert_eq!(checkpoint.checkpoint_type, CheckpointType::Registry);
    }

    #[test]
    fn test_checkpoint_result_creation() {
        let result = CheckpointResult::default();
        assert!(!result.success);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_restore_result_creation() {
        let result = RestoreCheckpointResult::default();
        assert!(!result.success);
        assert_eq!(result.entries_restored, 0);
    }

    #[test]
    fn test_checkpoint_type_variants() {
        assert_eq!(CheckpointType::Registry, CheckpointType::Registry);
        assert_eq!(CheckpointType::Startup, CheckpointType::Startup);
        assert_ne!(CheckpointType::Registry, CheckpointType::Startup);
    }

    #[test]
    fn test_entry_type_variants() {
        assert_eq!(EntryType::RegistryValue, EntryType::RegistryValue);
        assert_eq!(EntryType::File, EntryType::File);
        assert_ne!(EntryType::RegistryValue, EntryType::File);
    }

    #[test]
    fn test_backup_data_variants() {
        assert_eq!(BackupData::Dword(42), BackupData::Dword(42));
        assert_ne!(BackupData::Dword(42), BackupData::Dword(0));
        assert_eq!(
            BackupData::String("test".to_string()),
            BackupData::String("test".to_string())
        );
    }

    #[test]
    fn test_file_metadata() {
        let metadata = FileMetadata {
            path: "C:\\test.txt".to_string(),
            size: 1024,
            created: Some(1705320000),
            modified: Some(1705320000),
            attributes: 32,
        };

        assert_eq!(metadata.size, 1024);
        assert_eq!(metadata.attributes, 32);
    }

    #[test]
    fn test_serde_roundtrip() {
        let entry = BackupEntry {
            entry_type: EntryType::RegistryValue,
            path: "HKLM\\SOFTWARE\\Test".to_string(),
            value_name: Some("Test".to_string()),
            data: BackupData::String("value".to_string()),
            description: "Test".to_string(),
            timestamp: 1705320000,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let decoded: BackupEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.path, decoded.path);
        assert_eq!(entry.value_name, decoded.value_name);
    }
}
