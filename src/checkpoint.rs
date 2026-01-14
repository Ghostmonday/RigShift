//! Checkpoint module for saving and restoring file state
//! Handles saving file metadata before deletion and recreating empty files on restore

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a single file entry in a checkpoint
#[derive(Debug, Clone)]
pub struct CheckpointEntry {
    /// Original file path
    pub path: PathBuf,
    /// File size in bytes at time of checkpoint
    pub size: u64,
    /// Last modified timestamp (epoch seconds)
    pub modified: u64,
    /// Category of the file (for reference)
    pub category: String,
}

impl CheckpointEntry {
    /// Creates a new checkpoint entry
    pub fn new(path: PathBuf, size: u64, modified: SystemTime, category: &str) -> Self {
        let timestamp = modified
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        CheckpointEntry {
            path,
            size,
            modified: timestamp,
            category: category.to_string(),
        }
    }
}

/// Represents a complete checkpoint containing multiple file entries
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Version of checkpoint format
    pub version: String,
    /// Timestamp when checkpoint was created
    pub timestamp: u64,
    /// Description of the checkpoint
    pub description: String,
    /// List of file entries
    pub entries: Vec<CheckpointEntry>,
}

impl Checkpoint {
    /// Creates a new empty checkpoint
    pub fn new(description: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Checkpoint {
            version: "1.0.0".to_string(),
            timestamp,
            description,
            entries: Vec::new(),
        }
    }

    /// Adds a file entry to the checkpoint
    pub fn add_file(&mut self, path: &Path, size: u64, modified: SystemTime, category: &str) {
        self.entries.push(CheckpointEntry::new(
            path.to_path_buf(),
            size,
            modified,
            category,
        ));
    }

    /// Returns the number of files in the checkpoint
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the checkpoint is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Calculates total size of all files in checkpoint
    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }
}

/// Result of a restore operation
#[derive(Debug, Default)]
pub struct RestoreResult {
    /// Number of files successfully restored
    pub files_restored: usize,
    /// Number of files skipped (already existed)
    pub files_skipped: usize,
    /// Total size of restored files
    pub size_restored: u64,
    /// List of errors that occurred
    pub errors: Vec<String>,
}

impl RestoreResult {
    /// Creates a new empty restore result
    pub fn new() -> Self {
        RestoreResult {
            files_restored: 0,
            files_skipped: 0,
            size_restored: 0,
            errors: Vec::new(),
        }
    }

    /// Returns true if any errors occurred
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// Manages checkpoint operations - save and restore
pub struct CheckpointManager {
    /// Directory where checkpoints are stored
    pub(crate) checkpoint_dir: PathBuf,
}

impl CheckpointManager {
    /// Creates a new CheckpointManager with the specified checkpoint directory
    pub fn new() -> io::Result<Self> {
        let checkpoint_dir = Self::get_default_checkpoint_dir()?;

        if !checkpoint_dir.exists() {
            fs::create_dir_all(&checkpoint_dir)?;
        }

        Ok(CheckpointManager { checkpoint_dir })
    }

    /// Gets the default checkpoint directory path (static method)
    fn get_default_checkpoint_dir() -> io::Result<PathBuf> {
        let app_data = std::env::var_os("APPDATA").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "APPDATA environment variable not found",
            )
        })?;

        Ok(PathBuf::from(app_data).join("RigShift").join("checkpoints"))
    }

    /// Generates a unique checkpoint filename based on timestamp
    fn generate_checkpoint_filename(&self, description: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        let sanitized: String = description
            .chars()
            .take(20)
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect();

        format!("rigshift_{}_{}.json", sanitized, timestamp)
    }

    /// Saves a checkpoint to the checkpoint directory
    pub fn save(&self, checkpoint: &Checkpoint) -> io::Result<PathBuf> {
        let filename = self.generate_checkpoint_filename(&checkpoint.description);
        let file_path = self.checkpoint_dir.join(&filename);

        if !self.checkpoint_dir.exists() {
            fs::create_dir_all(&self.checkpoint_dir)?;
        }

        let json = self.serialize_checkpoint(checkpoint)?;

        let mut file = File::create(&file_path)?;
        file.write_all(json.as_bytes())?;

        Ok(file_path)
    }

    /// Loads a checkpoint from a file
    pub fn load(&self, path: &Path) -> io::Result<Checkpoint> {
        let content = fs::read_to_string(path)?;
        self.deserialize_checkpoint(&content)
    }

    /// Lists all available checkpoints in the checkpoint directory
    pub fn list_checkpoints(&self) -> io::Result<Vec<PathBuf>> {
        if !self.checkpoint_dir.exists() {
            return Ok(Vec::new());
        }

        let mut checkpoints = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.checkpoint_dir) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    checkpoints.push(entry.path());
                }
            }
        }

        checkpoints.sort_by_key(|p| {
            fs::metadata(p)
                .and_then(|m| m.modified())
                .unwrap_or(UNIX_EPOCH)
        });
        checkpoints.reverse();

        Ok(checkpoints)
    }

    /// Restores files from a checkpoint (recreates empty files)
    pub fn restore(&self, checkpoint: &Checkpoint, _dry_run: bool) -> io::Result<RestoreResult> {
        let mut result = RestoreResult::new();

        for entry in &checkpoint.entries {
            if let Some(parent) = entry.path.parent() {
                if !parent.exists() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        result.errors.push(format!(
                            "Failed to create directory {}: {}",
                            parent.display(),
                            e
                        ));
                        continue;
                    }
                }
            }

            match File::create(&entry.path) {
                Ok(_) => {
                    result.files_restored += 1;
                    result.size_restored += entry.size;
                }
                Err(e) => {
                    result.errors.push(format!(
                        "Failed to restore {}: {}",
                        entry.path.display(),
                        e
                    ));
                }
            }
        }

        Ok(result)
    }

    /// Gets the path to the latest checkpoint
    pub fn get_latest_checkpoint(&self) -> io::Result<Option<PathBuf>> {
        let checkpoints = self.list_checkpoints()?;
        Ok(checkpoints.first().cloned())
    }

    /// Deletes a checkpoint file
    pub fn delete(&self, path: &Path) -> io::Result<()> {
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Gets the checkpoint directory path
    pub fn get_checkpoint_directory(&self) -> &PathBuf {
        &self.checkpoint_dir
    }

    /// Serializes a checkpoint to JSON string
    fn serialize_checkpoint(&self, checkpoint: &Checkpoint) -> io::Result<String> {
        let mut json = String::new();

        json.push_str("{\n");
        json.push_str(r#"  "version": ""#);
        json.push_str(&checkpoint.version);
        json.push_str("\",\n");

        json.push_str(r#"  "timestamp": "#);
        json.push_str(&checkpoint.timestamp.to_string());
        json.push_str(",\n");

        json.push_str(r#"  "description": ""#);
        json.push_str(&self.escape_json_string(&checkpoint.description));
        json.push_str("\",\n");

        json.push_str("  \"entries\": [\n");

        for (i, entry) in checkpoint.entries.iter().enumerate() {
            json.push_str("    {\n");

            json.push_str(r#"      "path": ""#);
            json.push_str(&self.escape_json_string(&entry.path.to_string_lossy()));
            json.push_str("\",\n");

            json.push_str("      \"size\": ");
            json.push_str(&entry.size.to_string());
            json.push_str(",\n");

            json.push_str("      \"modified\": ");
            json.push_str(&entry.modified.to_string());
            json.push_str(",\n");

            json.push_str(r#"      "category": ""#);
            json.push_str(&self.escape_json_string(&entry.category));
            json.push_str("\"\n");

            json.push_str("    }");
            if i < checkpoint.entries.len() - 1 {
                json.push_str(",");
            }
            json.push_str("\n");
        }

        json.push_str("  ]\n");
        json.push_str("}\n");

        Ok(json)
    }

    /// Escapes special characters in a JSON string
    fn escape_json_string(&self, s: &str) -> String {
        let mut escaped = String::new();
        for c in s.chars() {
            match c {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                c => escaped.push(c),
            }
        }
        escaped
    }

    /// Deserializes a checkpoint from JSON string
    fn deserialize_checkpoint(&self, json: &str) -> io::Result<Checkpoint> {
        let mut checkpoint = Checkpoint::new(String::new());

        if let Some(version) = self.extract_string_value(json, "version") {
            checkpoint.version = version;
        }

        if let Some(timestamp) = self.extract_u64_value(json, "timestamp") {
            checkpoint.timestamp = timestamp;
        }

        if let Some(description) = self.extract_string_value(json, "description") {
            checkpoint.description = description;
        }

        checkpoint.entries = self.parse_entries(json)?;

        Ok(checkpoint)
    }

    /// Extracts a string value from JSON
    fn extract_string_value(&self, json: &str, key: &str) -> Option<String> {
        let pattern = format!(r#""{}": ""#, key);
        if let Some(start) = json.find(&pattern) {
            let content_start = start + pattern.len();
            let mut end = content_start;
            while end < json.len() {
                let c = json.as_bytes()[end];
                if c == b'"' && json.as_bytes()[end - 1] != b'\\' {
                    break;
                }
                end += 1;
            }
            if end > content_start {
                let value = &json[content_start..end];
                return Some(self.unescape_json_string(value));
            }
        }
        None
    }

    /// Extracts a u64 value from JSON
    fn extract_u64_value(&self, json: &str, key: &str) -> Option<u64> {
        let pattern = format!(r#""{}": "#, key);
        if let Some(start) = json.find(&pattern) {
            let content_start = start + pattern.len();
            let mut end = content_start;
            while end < json.len() {
                let c = json.as_bytes()[end];
                if !c.is_ascii_digit() {
                    break;
                }
                end += 1;
            }
            if end > content_start {
                return json[content_start..end].parse().ok();
            }
        }
        None
    }

    /// Unescapes JSON string escape sequences
    fn unescape_json_string(&self, s: &str) -> String {
        let mut result = String::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    match next {
                        '"' => {
                            result.push('"');
                            chars.next();
                        }
                        '\\' => {
                            result.push('\\');
                            chars.next();
                        }
                        'n' => {
                            result.push('\n');
                            chars.next();
                        }
                        'r' => {
                            result.push('\r');
                            chars.next();
                        }
                        't' => {
                            result.push('\t');
                            chars.next();
                        }
                        _ => {
                            result.push(c);
                        }
                    }
                } else {
                    result.push(c);
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Parses the entries array from JSON
    fn parse_entries(&self, json: &str) -> io::Result<Vec<CheckpointEntry>> {
        let mut entries = Vec::new();

        let entries_start = match json.find("\"entries\": [") {
            Some(pos) => pos + 12,
            None => {
                return Ok(entries);
            }
        };
        let array_content = &json[entries_start..];

        let mut depth = 1;
        let start = 0;
        let mut end = 0;

        for (i, c) in array_content.chars().enumerate() {
            if c == '[' {
                depth += 1;
            } else if c == ']' {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
        }

        if end == 0 {
            return Ok(entries);
        }

        let entries_json = &array_content[start + 1..end];

        let mut pos = 0;
        while pos < entries_json.len() {
            if let Some(obj_start) = entries_json[pos..].find("{") {
                pos += obj_start;

                depth = 1;
                let mut obj_end = pos + 1;
                while obj_end < entries_json.len() && depth > 0 {
                    match entries_json.as_bytes()[obj_end] {
                        b'{' => depth += 1,
                        b'}' => depth -= 1,
                        _ => {}
                    }
                    obj_end += 1;
                }

                if depth == 0 {
                    let entry_json = &entries_json[pos..obj_end];
                    if let Some(entry) = self.parse_entry(entry_json) {
                        entries.push(entry);
                    }
                    pos = obj_end;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(entries)
    }

    /// Parses a single entry object from JSON
    fn parse_entry(&self, json: &str) -> Option<CheckpointEntry> {
        let path = self.extract_string_value(json, "path")?;
        let size = self.extract_u64_value(json, "size")?;
        let modified = self.extract_u64_value(json, "modified")?;
        let category = self.extract_string_value(json, "category")?;

        Some(CheckpointEntry {
            path: PathBuf::from(path),
            size,
            modified,
            category,
        })
    }
}

impl Default for CheckpointManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| CheckpointManager {
            checkpoint_dir: PathBuf::from(r"C:\ProgramData\RigShift\checkpoints"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_checkpoint_new() {
        let cp = Checkpoint::new("test checkpoint".to_string());
        assert_eq!(cp.description, "test checkpoint");
        assert_eq!(cp.version, "1.0.0");
        assert!(cp.is_empty());
    }

    #[test]
    fn test_checkpoint_add_file() {
        let mut cp = Checkpoint::new("test".to_string());
        let path = PathBuf::from(r"C:\test\file.txt");

        cp.add_file(&path, 1024, SystemTime::UNIX_EPOCH, "temp");

        assert_eq!(cp.len(), 1);
        assert_eq!(cp.total_size(), 1024);
    }

    #[test]
    fn test_restore_result() {
        let result = RestoreResult::new();
        assert_eq!(result.files_restored, 0);
        assert!(!result.has_errors());
    }

    #[test]
    fn test_json_string_escaping() {
        let manager = CheckpointManager {
            checkpoint_dir: PathBuf::new(),
        };

        let escaped = manager.escape_json_string(r#"test"quote\nline"#);
        assert_eq!(escaped, r#"test\"quote\\nline"#);
    }
}
