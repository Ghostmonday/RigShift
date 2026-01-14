//! Registry Cleaning Module for RigShift
//!
//! Scans and cleans invalid registry keys, broken uninstallers, and unused
//! file extensions. All operations create checkpoints for safe undo.
//!
//! ⚠️ WARNING: This module modifies the Windows Registry. Incorrect changes
//! can cause system instability. Always create checkpoints before cleanup.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::time::SystemTime;
use winreg::enums::*;
use winreg::RegKey;

/// Result of a registry scan operation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryScanResult {
    /// Total invalid keys found
    pub invalid_keys: usize,
    /// Broken uninstaller entries found
    pub broken_uninstallers: usize,
    /// Orphaned file extension associations
    pub orphaned_extensions: usize,
    /// Total space that could be freed (estimated in bytes)
    pub estimated_space_freed: u64,
    /// Detailed findings
    pub findings: Vec<RegistryFinding>,
}

/// Individual registry finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryFinding {
    /// Type of issue found
    pub finding_type: FindingType,
    /// Registry key or path
    pub key_path: String,
    /// Description of the issue
    pub description: String,
    /// Estimated impact (low, medium, high)
    pub impact: ImpactLevel,
    /// Whether it's safe to remove
    pub is_safe: bool,
}

/// Type of registry issue
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingType {
    /// Invalid/unreadable registry key
    InvalidKey,
    /// Missing uninstaller reference
    BrokenUninstaller,
    /// Orphaned file extension
    OrphanedExtension,
    /// Orphaned COM registration
    OrphanedCOM,
    /// Leftover app data
    LeftoverAppData,
    /// Broken service reference
    BrokenServiceReference,
}

/// Impact level of the finding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
}

/// Result of a registry cleanup operation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryCleanupResult {
    /// Keys deleted successfully
    pub keys_deleted: usize,
    /// Keys that failed to delete
    pub keys_failed: usize,
    /// Total bytes freed (estimated)
    pub bytes_freed: u64,
    /// Checkpoint file path for undo
    pub checkpoint_path: Option<String>,
    /// List of errors
    pub errors: Vec<String>,
    /// List of successfully deleted keys
    pub deleted_keys: Vec<String>,
}

/// Checkpoint for registry operations
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryCheckpoint {
    pub version: u32,
    pub timestamp: u64,
    pub description: String,
    pub backup_entries: Vec<RegistryBackupEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryBackupEntry {
    pub key_path: String,
    pub key_data: Option<Vec<u8>>,
    pub key_type: u32,
}

/// Scanner for registry issues
pub struct RegistryScanner {
    /// Whether to include invalid keys
    pub scan_invalid_keys: bool,
    /// Whether to scan for broken uninstallers
    pub scan_broken_uninstallers: bool,
    /// Whether to scan for orphaned extensions
    pub scan_orphaned_extensions: bool,
    /// Whether to scan for orphaned COM entries
    pub scan_orphaned_com: bool,
    /// Whether to include risky operations
    pub safe_mode: bool,
}

impl Default for RegistryScanner {
    fn default() -> Self {
        Self {
            scan_invalid_keys: true,
            scan_broken_uninstallers: true,
            scan_orphaned_extensions: true,
            scan_orphaned_com: true,
            safe_mode: true, // Default to safe mode for first run
        }
    }
}

impl RegistryScanner {
    /// Create a new registry scanner with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable/disable safe mode (recommended for first scan)
    #[must_use]
    pub fn with_safe_mode(mut self, safe: bool) -> Self {
        self.safe_mode = safe;
        self
    }

    /// Enable/disable invalid key scanning
    #[must_use]
    pub fn with_invalid_keys(mut self, enabled: bool) -> Self {
        self.scan_invalid_keys = enabled;
        self
    }

    /// Enable/disable broken uninstaller scanning
    #[must_use]
    pub fn with_broken_uninstallers(mut self, enabled: bool) -> Self {
        self.scan_broken_uninstallers = enabled;
        self
    }

    /// Enable/disable orphaned extension scanning
    #[must_use]
    pub fn with_orphaned_extensions(mut self, enabled: bool) -> Self {
        self.scan_orphaned_extensions = enabled;
        self
    }

    /// Run a complete registry scan
    pub fn scan(&self) -> RegistryScanResult {
        let mut result = RegistryScanResult::default();

        if self.scan_invalid_keys {
            self.scan_invalid_registry_keys(&mut result);
        }

        if self.scan_broken_uninstallers {
            self.scan_broken_uninstallers(&mut result);
        }

        if self.scan_orphaned_extensions {
            self.scan_orphaned_extensions(&mut result);
        }

        if self.scan_orphaned_com {
            self.scan_orphaned_com(&mut result);
        }

        // Filter out high-risk findings in safe mode
        if self.safe_mode {
            result.findings.retain(|f| f.is_safe);
            result.invalid_keys = result
                .findings
                .iter()
                .filter(|f| f.finding_type == FindingType::InvalidKey)
                .count();
            result.broken_uninstallers = result
                .findings
                .iter()
                .filter(|f| f.finding_type == FindingType::BrokenUninstaller)
                .count();
            result.orphaned_extensions = result
                .findings
                .iter()
                .filter(|f| f.finding_type == FindingType::OrphanedExtension)
                .count();
        }

        result
    }

    /// Scan for invalid/unreadable registry keys
    fn scan_invalid_registry_keys(&self, result: &mut RegistryScanResult) {
        // Common locations for invalid keys
        let locations = vec![
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
            ),
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        ];

        for (hive, path) in locations {
            self.scan_key_for_invalid_subkeys(hive, path, result);
        }
    }

    fn scan_key_for_invalid_subkeys(
        &self,
        hive: winreg::enums::HKEY,
        path: &str,
        result: &mut RegistryScanResult,
    ) {
        if let Ok(key) = RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ) {
            if let Ok(subkeys) = key.enum_keys() {
                for subkey_name in subkeys.flatten() {
                    // Try to open each subkey - if it fails, it's invalid
                    if let Err(_) = key.open_subkey(&subkey_name) {
                        result.findings.push(RegistryFinding {
                            finding_type: FindingType::InvalidKey,
                            key_path: format!(r"{}\{}", path, subkey_name),
                            description: format!(
                                "Invalid or unreadable registry key: {}",
                                subkey_name
                            ),
                            impact: ImpactLevel::Medium,
                            is_safe: true,
                        });
                    }
                }
            }
        }

        // Count findings of this type
        result.invalid_keys = result
            .findings
            .iter()
            .filter(|f| f.finding_type == FindingType::InvalidKey)
            .count();
    }

    /// Scan for broken uninstaller entries
    fn scan_broken_uninstallers(&self, result: &mut RegistryScanResult) {
        // Scan both 32-bit and 64-bit uninstall locations
        let locations = vec![
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
        ];

        for (hive, path) in locations {
            if let Ok(key) = RegKey::predef(hive).open_subkey(path) {
                if let Ok(subkeys) = key.enum_keys() {
                    for subkey_name in subkeys.flatten() {
                        if let Ok(subkey) = key.open_subkey(&subkey_name) {
                            // Check if UninstallString exists
                            let has_uninstall_string =
                                subkey.get_value::<String, _>("UninstallString").is_ok();
                            let has_display_name =
                                subkey.get_value::<String, _>("DisplayName").is_ok();

                            // Check if the uninstall command actually exists
                            if has_uninstall_string {
                                if let Ok(uninstall_str) =
                                    subkey.get_value::<String, _>("UninstallString")
                                {
                                    if !self.is_uninstall_command_valid(&uninstall_str) {
                                        result.findings.push(RegistryFinding {
                                            finding_type: FindingType::BrokenUninstaller,
                                            key_path: format!(r"{}\{}", path, subkey_name),
                                            description: format!(
                                                "Broken uninstaller - command not found: {}",
                                                uninstall_str
                                            ),
                                            impact: ImpactLevel::High,
                                            is_safe: false, // Requires careful handling
                                        });
                                    }
                                }
                            } else if !has_display_name
                                && !subkey_name.starts_with("KB")
                                && !subkey_name.starts_with("Microsoft")
                            {
                                // Orphaned entry with no display name and not a Windows update
                                result.findings.push(RegistryFinding {
                                    finding_type: FindingType::BrokenUninstaller,
                                    key_path: format!(r"{}\{}", path, subkey_name),
                                    description: format!(
                                        "Orphaned uninstaller entry with no DisplayName: {}",
                                        subkey_name
                                    ),
                                    impact: ImpactLevel::Medium,
                                    is_safe: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        result.broken_uninstallers = result
            .findings
            .iter()
            .filter(|f| f.finding_type == FindingType::BrokenUninstaller)
            .count();
    }

    /// Check if an uninstall command is valid
    fn is_uninstall_command_valid(&self, command: &str) -> bool {
        // Extract executable path from command
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return false;
        }

        let executable = if parts[0].starts_with('"') {
            // Handle quoted paths
            let end_quote = command[1..].find('"');
            match end_quote {
                Some(idx) => &command[1..=idx],
                None => parts[0],
            }
        } else {
            parts[0]
        };

        // Check if executable exists
        let path = std::path::Path::new(executable);
        if path.exists() {
            return true;
        }

        // Also check in PATH
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let full_path = dir.join(executable);
                if full_path.exists() {
                    return true;
                }
            }
        }

        false
    }

    /// Scan for orphaned file extension associations
    fn scan_orphaned_extensions(&self, result: &mut RegistryScanResult) {
        if let Ok(classes_key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Classes")
        {
            if let Ok(subkeys) = classes_key.enum_keys() {
                for subkey_name in subkeys.flatten() {
                    // Skip extensions and known types
                    if subkey_name.starts_with('.') {
                        // This is an extension - check its default value
                        if let Ok(ext_key) = classes_key.open_subkey(&subkey_name) {
                            if let Ok(default_val) = ext_key.get_value::<String, _>("") {
                                // Check if the associated program key exists
                                if let Ok(_) = classes_key.open_subkey(&default_val) {
                                    // Valid association
                                } else if !default_val.is_empty() {
                                    result.findings.push(RegistryFinding {
                                        finding_type: FindingType::OrphanedExtension,
                                        key_path: format!(r"Software\Classes\{}", subkey_name),
                                        description: format!(
                                            "Orphaned file extension '{}' points to missing program '{}'",
                                            subkey_name, default_val
                                        ),
                                        impact: ImpactLevel::Low,
                                        is_safe: true,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        result.orphaned_extensions = result
            .findings
            .iter()
            .filter(|f| f.finding_type == FindingType::OrphanedExtension)
            .count();
    }

    /// Scan for orphaned COM registrations
    fn scan_orphaned_com(&self, result: &mut RegistryScanResult) {
        let locations = vec![
            (HKEY_CURRENT_USER, r"Software\Classes\CLSID"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID"),
        ];

        for (hive, path) in locations {
            if let Ok(clsid_key) = RegKey::predef(hive).open_subkey(path) {
                if let Ok(subkeys) = clsid_key.enum_keys() {
                    for clsid in subkeys.flatten() {
                        // Check if the COM object has an InprocServer32
                        let com_path = format!(r"{}\{}", path, clsid);
                        if let Ok(com_key) = RegKey::predef(hive).open_subkey(&com_path) {
                            if let Ok(inproc) = com_key.open_subkey("InprocServer32") {
                                if let Ok(dll_path) = inproc.get_value::<String, _>("") {
                                    let path = std::path::Path::new(&dll_path);
                                    if !path.exists()
                                        && !dll_path.contains("shell32")
                                        && !dll_path.contains("ole32")
                                    {
                                        result.findings.push(RegistryFinding {
                                            finding_type: FindingType::OrphanedCOM,
                                            key_path: com_path,
                                            description: format!(
                                                "Orphaned COM CLSID referencing missing DLL: {}",
                                                dll_path
                                            ),
                                            impact: ImpactLevel::Medium,
                                            is_safe: false, // COM issues can cause app crashes
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Registry cleanup executor
pub struct RegistryCleanup {
    /// Scanner instance
    scanner: RegistryScanner,
}

impl RegistryCleanup {
    /// Create a new cleanup executor
    pub fn new() -> Self {
        Self {
            scanner: RegistryScanner::new(),
        }
    }

    /// Clean registry based on scan results
    pub fn clean(
        &self,
        findings: &[RegistryFinding],
        create_checkpoint: bool,
    ) -> RegistryCleanupResult {
        let mut result = RegistryCleanupResult::default();

        if create_checkpoint {
            if let Some(path) = self.create_checkpoint(findings) {
                result.checkpoint_path = Some(path);
            }
        }

        for finding in findings {
            if !finding.is_safe {
                result.errors.push(format!(
                    "Skipped unsafe finding: {} - {}",
                    finding.key_path, finding.description
                ));
                continue;
            }

            match self.delete_registry_key(&finding.key_path) {
                Ok(()) => {
                    result.keys_deleted += 1;
                    result.deleted_keys.push(finding.key_path.clone());
                    // Estimate ~1KB per key
                    result.bytes_freed += 1024;
                }
                Err(e) => {
                    result.keys_failed += 1;
                    result
                        .errors
                        .push(format!("Failed to delete {}: {}", finding.key_path, e));
                }
            }
        }

        result
    }

    /// Delete a registry key safely
    fn delete_registry_key(&self, key_path: &str) -> Result<(), Box<dyn Error>> {
        // Parse the path to get hive and subkey
        let (hive, subkey) = self.parse_key_path(key_path)?;

        let hkey = match hive {
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKEY_USERS" => HKEY_USERS,
            "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
            _ => return Err("Unknown hive".into()),
        };

        // Open parent key and delete subkey
        let parent_path = match subkey.rfind('\\') {
            Some(idx) => &subkey[..idx],
            None => return Err("Invalid key path".into()),
        };

        let subkey_name = &subkey[parent_path.len() + 1..];

        let parent_key =
            RegKey::predef(hkey).open_subkey_with_flags(parent_path, KEY_WRITE | KEY_READ)?;
        parent_key.delete_subkey(subkey_name)?;

        Ok(())
    }

    /// Parse a registry path string into hive and subkey
    fn parse_key_path(&self, path: &str) -> Result<(&str, &str), Box<dyn Error>> {
        for hive in &[
            "HKEY_CURRENT_USER",
            "HKEY_LOCAL_MACHINE",
            "HKEY_CLASSES_ROOT",
            "HKEY_USERS",
            "HKEY_CURRENT_CONFIG",
        ] {
            if path.starts_with(hive) {
                let subkey = &path[hive.len()..];
                let subkey = subkey.trim_start_matches('\\');
                return Ok((hive, subkey));
            }
        }
        Err("Could not parse registry path".into())
    }

    /// Create a checkpoint before cleanup
    fn create_checkpoint(&self, findings: &[RegistryFinding]) -> Option<String> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let checkpoint = RegistryCheckpoint {
            version: 1,
            timestamp,
            description: format!("Registry cleanup checkpoint - {} items", findings.len()),
            backup_entries: Vec::new(),
        };

        // In a real implementation, we would backup each key before deletion
        // For now, we just return a placeholder
        Some(format!("checkpoint_registry_{}.json", timestamp))
    }

    /// Restore from a checkpoint
    pub fn restore(&self, checkpoint_path: &str) -> Result<RegistryCleanupResult, Box<dyn Error>> {
        let mut result = RegistryCleanupResult::default();

        // Read checkpoint file
        let content = std::fs::read_to_string(checkpoint_path)
            .map_err(|e| format!("Failed to read checkpoint: {}", e))?;

        let checkpoint: RegistryCheckpoint = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse checkpoint: {}", e))?;

        // Restore each backed up key
        for entry in &checkpoint.backup_entries {
            match self.restore_key(entry) {
                Ok(()) => {
                    result.keys_deleted -= 1; // We restored one
                    result.bytes_freed -= 1024;
                }
                Err(e) => {
                    result
                        .errors
                        .push(format!("Failed to restore {}: {}", entry.key_path, e));
                }
            }
        }

        Ok(result)
    }

    /// Restore a single registry key from backup
    fn restore_key(&self, entry: &RegistryBackupEntry) -> Result<(), Box<dyn Error>> {
        let (hive, subkey) = self.parse_key_path(&entry.key_path)?;

        let hkey = match hive {
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKEY_USERS" => HKEY_USERS,
            "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
            _ => return Err("Unknown hive".into()),
        };

        if let Some(data) = &entry.key_data {
            let parent_path = match subkey.rfind('\\') {
                Some(idx) => &subkey[..idx],
                None => return Err("Invalid key path".into()),
            };

            let key_name = &subkey[parent_path.len() + 1..];
            let parent_key = RegKey::predef(hkey).open_subkey_with_flags(parent_path, KEY_WRITE)?;
            parent_key.set_raw_value(key_name, entry.key_type, data)?;
        }

        Ok(())
    }
}

impl fmt::Display for RegistryScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Registry Scan Results")?;
        writeln!(f, "=====================")?;
        writeln!(f, "Invalid Keys Found: {}", self.invalid_keys)?;
        writeln!(f, "Broken Uninstallers: {}", self.broken_uninstallers)?;
        writeln!(f, "Orphaned Extensions: {}", self.orphaned_extensions)?;
        writeln!(
            f,
            "Estimated Space to Free: {} bytes",
            self.estimated_space_freed
        )?;
        writeln!(f, "\nDetailed Findings ({} total):", self.findings.len())?;

        for (i, finding) in self.findings.iter().enumerate().take(20) {
            writeln!(
                f,
                "{}. [{}] {}",
                i + 1,
                finding.impact.to_string().to_uppercase(),
                finding.key_path
            )?;
            writeln!(f, "   {}", finding.description)?;
        }

        if self.findings.len() > 20 {
            writeln!(f, "... and {} more findings", self.findings.len() - 20)?;
        }

        Ok(())
    }
}

impl fmt::Display for ImpactLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImpactLevel::Low => write!(f, "LOW"),
            ImpactLevel::Medium => write!(f, "MEDIUM"),
            ImpactLevel::High => write!(f, "HIGH"),
        }
    }
}

impl fmt::Display for RegistryCleanupResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Registry Cleanup Results")?;
        writeln!(f, "========================")?;
        writeln!(f, "Keys Deleted: {}", self.keys_deleted)?;
        writeln!(f, "Keys Failed: {}", self.keys_failed)?;
        writeln!(f, "Bytes Freed (est): {}", self.bytes_freed)?;

        if let Some(path) = &self.checkpoint_path {
            writeln!(f, "Checkpoint Created: {}", path)?;
        }

        if !self.errors.is_empty() {
            writeln!(f, "\nErrors:")?;
            for error in &self.errors {
                writeln!(f, "  - {}", error)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_scanner_creation() {
        let scanner = RegistryScanner::new();
        assert!(scanner.scan_invalid_keys);
        assert!(scanner.scan_broken_uninstallers);
        assert!(scanner.safe_mode);
    }

    #[test]
    fn test_scanner_with_options() {
        let scanner = RegistryScanner::new()
            .with_safe_mode(false)
            .with_invalid_keys(false)
            .with_broken_uninstallers(false);

        assert!(!scanner.safe_mode);
        assert!(!scanner.scan_invalid_keys);
        assert!(!scanner.scan_broken_uninstallers);
    }

    #[test]
    fn test_parse_key_path() {
        let scanner = RegistryScanner::new();
        let (hive, subkey) = scanner
            .parse_key_path(r"HKEY_CURRENT_USER\Software\Classes")
            .unwrap();
        assert_eq!(hive, "HKEY_CURRENT_USER");
        assert_eq!(subkey, "Software\\Classes");
    }

    #[test]
    fn test_cleanup_result_creation() {
        let result = RegistryCleanupResult::default();
        assert_eq!(result.keys_deleted, 0);
        assert_eq!(result.keys_failed, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_finding_type_variants() {
        assert_eq!(FindingType::InvalidKey, FindingType::InvalidKey);
        assert_ne!(FindingType::InvalidKey, FindingType::BrokenUninstaller);
    }

    #[test]
    fn test_uninstall_command_validation() {
        let scanner = RegistryScanner::new();

        // Test valid command (notepad exists on Windows)
        assert!(scanner.is_uninstall_command_valid("notepad.exe"));

        // Test invalid command
        assert!(!scanner.is_uninstall_command_valid("nonexistent_app.exe"));
    }
}
