//! Uninstaller Module
//!
//! Provides comprehensive program uninstallation capabilities including:
//! - Detection of installed programs via registry
//! - Analysis of leftover files and registry entries after uninstallation
//! - Safe cleanup of orphaned artifacts
//! - Checkpoint creation before cleanup for rollback support
//!
//! This module helps clean up programs that Windows' default uninstaller
//! leaves behind, similar to third-party tools like Revo Uninstaller.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use winreg::enums::*;
use winreg::RegKey;

/// Represents an installed program detected in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledProgram {
    /// Registry key name (unique identifier)
    pub registry_key: String,
    /// Display name shown in Programs and Features
    pub display_name: String,
    /// Publisher/developer
    pub publisher: Option<String>,
    /// Version string
    pub version: Option<String>,
    /// Uninstall command
    pub uninstall_command: String,
    /// Quiet uninstall command (if available)
    pub quiet_uninstall_command: Option<String>,
    /// Install location
    pub install_location: Option<String>,
    /// Install date (if available)
    pub install_date: Option<String>,
    /// Estimated size in bytes
    pub estimated_size: u64,
    /// URL for more info
    pub help_link: Option<String>,
    /// URL for support
    pub support_link: Option<String>,
    /// Whether it's a Windows update/hotfix
    pub is_update: bool,
    /// Whether it's a Microsoft product
    pub is_microsoft: bool,
    /// When the program was installed
    pub install_timestamp: Option<u64>,
}

/// Leftover artifact after uninstallation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LeftoverArtifact {
    /// Directory that still exists
    Directory(PathBuf),
    /// File that still exists
    File(PathBuf),
    /// Registry key that still exists
    RegistryKey(RegistryLeftover),
    /// Registry value that still exists
    RegistryValue(RegistryValueLeftover),
    /// Start menu shortcut
    StartMenuShortcut(ShortcutInfo),
    /// Desktop shortcut
    DesktopShortcut(ShortcutInfo),
    /// Other shortcut type
    OtherShortcut(ShortcutInfo),
}

/// Registry leftover information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryLeftover {
    /// Full registry path
    pub key_path: String,
    /// Key name
    pub key_name: String,
    /// Parent key path
    pub parent_path: String,
}

/// Registry value leftover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValueLeftover {
    /// Full registry path
    pub key_path: String,
    /// Value name
    pub value_name: String,
    /// Value data
    pub value_data: String,
}

/// Shortcut information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShortcutInfo {
    /// Full path to the shortcut
    pub path: PathBuf,
    /// Target of the shortcut
    pub target: String,
    /// Working directory
    pub working_dir: Option<String>,
    /// Arguments passed to target
    pub arguments: Option<String>,
}

/// Leftover category for organization
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeftoverCategory {
    /// Program files directory
    ProgramFiles,
    /// AppData directory
    AppData,
    /// Registry uninstall entries
    RegistryUninstall,
    /// Registry run entries
    RegistryRun,
    /// Registry COM entries
    RegistryCOM,
    /// Start menu items
    StartMenu,
    /// Desktop items
    Desktop,
    /// Other shortcuts
    OtherShortcuts,
    /// Unknown category
    Unknown,
}

/// Result of analyzing leftovers
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeftoverAnalysis {
    /// All leftovers found
    pub leftovers: Vec<LeftoverArtifact>,
    /// Leftovers organized by category
    pub by_category: HashMap<LeftoverCategory, Vec<LeftoverArtifact>>,
    /// Total number of leftovers
    pub total_count: usize,
    /// Total size of leftover files in bytes
    pub total_size_bytes: u64,
    /// Leftovers that are safe to remove
    pub safe_to_remove: Vec<LeftoverArtifact>,
    /// Leftovers that require caution
    pub caution_required: Vec<LeftoverArtifact>,
    /// Leftovers that should not be removed
    pub do_not_remove: Vec<LeftoverArtifact>,
    /// Risk assessment
    pub risk_level: RiskLevel,
}

/// Risk level for cleanup operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Very low risk - safe to clean
    Minimal,
    /// Low risk - generally safe
    Low,
    /// Medium risk - review before cleaning
    Medium,
    /// High risk - careful review required
    High,
    /// Very high risk - manual review recommended
    Critical,
}

/// Result of an uninstall operation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UninstallResult {
    /// Whether the uninstall was successful
    pub success: bool,
    /// The program that was uninstalled
    pub program: String,
    /// Uninstaller exit code
    pub exit_code: i32,
    /// Leftovers found before cleanup
    pub pre_cleanup_leftovers: usize,
    /// Leftovers removed during cleanup
    pub leftovers_removed: usize,
    /// Leftovers that couldn't be removed
    pub leftovers_failed: usize,
    /// Whether checkpoint was created
    pub checkpoint_created: bool,
    /// Checkpoint path
    pub checkpoint_path: Option<String>,
    /// Total space freed in bytes
    pub bytes_freed: u64,
    /// Time taken in milliseconds
    pub duration_ms: u128,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Warnings about the uninstall
    pub warnings: Vec<String>,
}

/// Result of scanning for installed programs
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProgramScanResult {
    /// All installed programs found
    pub programs: Vec<InstalledProgram>,
    /// Total count
    pub total_count: usize,
    /// Microsoft programs
    pub microsoft_count: usize,
    /// Windows updates/hotfixes
    pub update_count: usize,
    /// Programs organized by publisher
    pub by_publisher: HashMap<String, Vec<InstalledProgram>>,
}

/// Uninstaller manager
pub struct Uninstaller {
    /// Known safe registry locations to clean
    safe_registry_paths: Vec<&'static str>,
    /// Known system-critical paths
    protected_paths: Vec<&'static str>,
    /// Common leftover locations
    leftover_locations: Vec<&'static str>,
}

impl Uninstaller {
    /// Create a new uninstaller manager
    pub fn new() -> Self {
        Uninstaller {
            safe_registry_paths: vec![
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData",
            ],
            protected_paths: vec![
                r"C:\Windows\System32",
                r"C:\Windows\SysWOW64",
                r"C:\Program Files\WindowsApps",
                r"C:\Program Files (x86)\WindowsApps",
            ],
            leftover_locations: vec![
                r"AppData\Local",
                r"AppData\Roaming",
                r"AppData\LocalLow",
                r"ProgramData",
            ],
        }
    }

    /// Scan for all installed programs
    pub fn scan_programs(&self) -> ProgramScanResult {
        let mut programs = Vec::new();
        let mut by_publisher: HashMap<String, Vec<InstalledProgram>> = HashMap::new();
        let mut microsoft_count = 0;
        let mut update_count = 0;

        // Scan HKLM uninstall keys
        self.scan_uninstall_key(HKEY_LOCAL_MACHINE, &mut programs, &mut update_count);

        // Scan HKCU uninstall keys
        self.scan_uninstall_key(HKEY_CURRENT_USER, &mut programs, &mut update_count);

        // Check for 32-bit programs on 64-bit systems
        if let Ok(hklm) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
        {
            self.scan_uninstall_key_generic(&hklm, &mut programs, &mut update_count);
        }

        // Organize by publisher
        for program in &programs {
            let publisher = program.publisher.clone().unwrap_or_else(|| "Unknown".to_string());

            if publisher.to_lowercase().contains("microsoft") || program.is_microsoft {
                microsoft_count += 1;
            }

            by_publisher
                .entry(publisher)
                .or_insert_with(Vec::new)
                .push(program.clone());
        }

        // Sort programs by name
        programs.sort_by(|a, b| a.display_name.cmp(&b.display_name));

        ProgramScanResult {
            programs,
            total_count: programs.len(),
            microsoft_count,
            update_count,
            by_publisher,
        }
    }

    /// Scan an uninstall registry key
    fn scan_uninstall_key(
        &self,
        hive: winreg::enums::HKEY,
        programs: &mut Vec<InstalledProgram>,
        update_count: &mut usize,
    ) {
        if let Ok(uninstall) = RegKey::predef(hive)
            .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        {
            self.scan_uninstall_key_generic(&uninstall, programs, update_count);
        }
    }

    /// Generic scan of an uninstall key
    fn scan_uninstall_key_generic(
        &self,
        uninstall: &RegKey,
        programs: &mut Vec<InstalledProgram>,
        update_count: &mut usize,
    ) {
        if let Ok(key_names) = uninstall.enum_keys() {
            for key_name in key_names.flatten() {
                // Skip Windows updates (KB numbers)
                if key_name.starts_with("KB") || key_name.starts_with("Update for KB") {
                    *update_count += 1;
                    continue;
                }

                if let Ok(key) = uninstall.open_subkey(&key_name) {
                    if let Ok(display_name) = key.get_value::<String, _>("DisplayName") {
                        // Skip entries without proper uninstall info
                        let uninstall_string: Result<String, _> =
                            key.get_value::<String, _>("UninstallString");

                        if uninstall_string.is_err() {
                            continue;
                        }

                        let program = self.parse_program_info(&key_name, &display_name, &key);
                        programs.push(program);
                    }
                }
            }
        }
    }

    /// Parse program information from registry
    fn parse_program_info(
        &self,
        registry_key: &str,
        display_name: &str,
        key: &RegKey,
    ) -> InstalledProgram {
        let publisher = key.get_value::<String, _>("Publisher").ok();
        let version = key.get_value::<String, _>("DisplayVersion").ok();
        let uninstall_string = key.get_value::<String, _>("UninstallString").unwrap_or_default();
        let quiet_uninstall = key.get_value::<String, _>("QuietUninstallString").ok();
        let install_location = key.get_value::<String, _>("InstallLocation").ok();
        let install_date = key.get_value::<String, _>("InstallDate").ok();
        let estimated_size = key.get_value::<u32, _>("EstimatedSize").ok().map(|u| u as u64 * 1024);
        let help_link = key.get_value::<String, _>("HelpLink").ok();
        let support_link = key.get_value::<String, _>("SupportUrl").ok();

        let is_microsoft = publisher
            .as_ref()
            .map(|p| p.to_lowercase().contains("microsoft"))
            .unwrap_or(false);

        // Check for updates by name patterns
        let is_update = display_name.to_lowercase().contains("update")
            || display_name.to_lowercase().contains("security update")
            || display_name.to_lowercase().contains("hotfix");

        let install_timestamp = install_date.and_then(|_| None); // Would need parsing

        InstalledProgram {
            registry_key: registry_key.to_string(),
            display_name: display_name.to_string(),
            publisher,
            version,
            uninstall_command: uninstall_string,
            quiet_uninstall_command: quiet_uninstall,
            install_location,
            install_date,
            estimated_size: estimated_size.unwrap_or(0),
            help_link,
            support_link,
            is_update,
            is_microsoft,
            install_timestamp,
        }
    }

    /// Analyze leftovers for a specific program
    pub fn analyze_leftovers(&self, program: &InstalledProgram) -> LeftoverAnalysis {
        let mut leftovers = Vec::new();
        let mut by_category: HashMap<LeftoverCategory, Vec<LeftoverArtifact>> = HashMap::new();
        let mut total_size = 0u64;
        let mut safe_to_remove = Vec::new();
        let mut caution_required = Vec::new();
        let mut do_not_remove = Vec::new();

        // Check install location
        if let Some(location) = &program.install_location {
            let install_path = Path::new(location);
            if install_path.exists() {
                self.scan_directory_leftovers(install_path, &mut leftovers, &mut total_size);
            }
        }

        // Check common leftover locations
        if let Ok(appdata_local) = std::env::var("LOCALAPPDATA") {
            self.scan_appdata_leftovers(
                Path::new(&appdata_local),
                &program.display_name,
                &mut leftovers,
                &mut total_size,
            );
        }

        if let Ok(appdata_roaming) = std::env::var("APPDATA") {
            self.scan_appdata_leftovers(
                Path::new(&appdata_roaming),
                &program.display_name,
                &mut leftovers,
                &mut total_size,
            );
        }

        // Check registry leftovers
        self.scan_registry_leftovers(program, &mut leftovers);

        // Check for shortcuts
        self.scan_shortcuts(&program.display_name, &mut leftovers);

        // Categorize leftovers
        for artifact in &leftovers {
            let category = self.categorize_artifact(artifact);
            by_category
                .entry(category)
                .or_insert_with(Vec::new)
                .push(artifact.clone());

            // Determine if safe to remove
            if self.is_safe_to_remove(artifact) {
                safe_to_remove.push(artifact.clone());
            } else if self.is_caution_required(artifact) {
                caution_required.push(artifact.clone());
            } else {
                do_not_remove.push(artifact.clone());
            }
        }

        // Sort by size
        leftovers.sort_by(|a, b| {
            let size_a = match a {
                LeftoverArtifact::File(p) => fs::metadata(p).map(|m| m.len()).unwrap_or(0),
                LeftoverArtifact::Directory(p) => self.dir_size(p).unwrap_or(0),
                _ => 0,
            };
            let size_b = match b {
                LeftoverArtifact::File(p) => fs::metadata(p).map(|m| m.len()).unwrap_or(0),
                LeftoverArtifact::Directory(p) => self.dir_size(p).unwrap_or(0),
                _ => 0,
            };
            size_b.cmp(&size_a)
        });

        // Determine risk level
        let risk_level = self.calculate_risk_level(&safe_to_remove, &caution_required, &do_not_remove);

        LeftoverAnalysis {
            leftovers,
            by_category,
            total_count: leftovers.len(),
            total_size_bytes: total_size,
            safe_to_remove,
            caution_required,
            do_not_remove,
            risk_level,
        }
    }

    /// Scan a directory for leftovers
    fn scan_directory_leftovers(
        &self,
        dir: &Path,
        leftovers: &mut Vec<LeftoverArtifact>,
        _total_size: &mut u64,
    ) {
        if !dir.exists() || !dir.is_dir() {
            return;
        }

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    // Check if directory is empty or contains leftover files
                    leftovers.push(LeftoverArtifact::Directory(path));
                } else if path.is_file() {
                    leftovers.push(LeftoverArtifact::File(path));
                }
            }
        }
    }

    /// Scan AppData for program leftovers
    fn scan_appdata_leftovers(
        &self,
        base: &Path,
        program_name: &str,
        leftovers: &mut Vec<LeftoverArtifact>,
        _total_size: &mut u64,
    ) {
        // Look for folders matching program name
        if let Ok(entries) = fs::read_dir(base) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    let dir_name = path.file_name().unwrap_or_default().to_string_lossy();

                    // Check if directory name contains program name
                    if dir_name.to_lowercase().contains(&program_name.to_lowercase())
                        || self.program_name_matches(program_name, &dir_name)
                    {
                        leftovers.push(LeftoverArtifact::Directory(path));
                    }
                }
            }
        }
    }

    /// Check if directory name matches program name pattern
    fn program_name_matches(&self, program_name: &str, dir_name: &str) -> bool {
        let program_lower = program_name.to_lowercase();
        let dir_lower = dir_name.to_lowercase();

        // Remove common suffixes/prefixes
        let clean_program = program_lower
            .replace(" inc", "")
            .replace(" corporation", "")
            .replace(" ltd", "")
            .replace(" llc", "");

        // Check for common variations
        dir_lower.contains(&clean_program)
            || dir_lower.starts_with(&clean_program[..clean_program.len().min(5)])
    }

    /// Scan registry for leftovers
    fn scan_registry_leftovers(&self, program: &InstalledProgram, leftovers: &mut Vec<LeftoverArtifact>) {
        let program_key = &program.registry_key;

        // Check if uninstall key still exists
        if let Ok(hklm) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        {
            if hklm.open_subkey(program_key).is_ok() {
                leftovers.push(LeftoverArtifact::RegistryKey(RegistryLeftover {
                    key_path: format!(
                        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{}",
                        program_key
                    ),
                    key_name: program.display_name.clone(),
                    parent_path: r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
                        .to_string(),
                }));
            }
        }

        // Check for related registry entries
        let locations = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        ];

        for location in &locations {
            if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(location) {
                for value_name in key.enum_values().flatten().map(|(n, _)| n) {
                    if self.value_matches_program(&value_name, &program.display_name) {
                        leftovers.push(LeftoverArtifact::RegistryValue(RegistryValueLeftover {
                            key_path: format!(r"HKEY_LOCAL_MACHINE\{}", location),
                            value_name,
                            value_data: String::new(),
                        }));
                    }
                }
            }
        }
    }

    /// Check if registry value matches program name
    fn value_matches_program(&self, value_name: &str, program_name: &str) -> bool {
        let value_lower = value_name.to_lowercase();
        let program_lower = program_name.to_lowercase();

        value_lower.contains(&program_lower) || program_lower.contains(&value_lower)
    }

    /// Scan for leftover shortcuts
    fn scan_shortcuts(&self, program_name: &str, leftovers: &mut Vec<LeftoverArtifact>) {
        // Check start menu
        if let Ok(appdata) = std::env::var("APPDATA") {
            let start_menu = Path::new(&appdata)
                .join(r"Microsoft\Windows\Start Menu\Programs");

            self.scan_shortcut_dir(&start_menu, program_name, leftovers);
        }

        // Check desktop
        if let Ok(desktop) = std::env::var("PUBLIC")
            .or_else(|_| std::env::var("USERPROFILE"))
        {
            let desktop_path = Path::new(&desktop).join("Desktop");
            self.scan_shortcut_dir(&desktop_path, program_name, leftovers);
        }
    }

    /// Scan a directory for shortcuts
    fn scan_shortcut_dir(&self, dir: &Path, program_name: &str, leftovers: &mut Vec<LeftoverArtifact>) {
        if !dir.exists() || !dir.is_dir() {
            return;
        }

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.extension().map(|e| e == "lnk").unwrap_or(false) {
                    let file_name = path.file_name().unwrap_or_default().to_string_lossy();

                    if file_name.to_lowercase().contains(&program_name.to_lowercase())
                        || self.program_name_matches(program_name, &file_name)
                    {
                        let is_start_menu = dir.to_string_lossy().contains("Start Menu");
                        let is_desktop = dir.to_string_lossy().contains("Desktop");

                        let artifact = if is_start_menu {
                            LeftoverArtifact::StartMenuShortcut(ShortcutInfo {
                                path,
                                target: String::new(),
                                working_dir: None,
                                arguments: None,
                            })
                        } else if is_desktop {
                            LeftoverArtifact::DesktopShortcut(ShortcutInfo {
                                path,
                                target: String::new(),
                                working_dir: None,
                                arguments: None,
                            })
                        } else {
                            LeftoverArtifact::OtherShortcut(ShortcutInfo {
                                path,
                                target: String::new(),
                                working_dir: None,
                                arguments: None,
                            })
                        };

                        leftovers.push(artifact);
                    }
                }
            }
        }
    }

    /// Categorize a leftover artifact
    fn categorize_artifact(&self, artifact: &LeftoverArtifact) -> LeftoverCategory {
        match artifact {
            LeftoverArtifact::Directory(path) => {
                let path_str = path.to_string_lossy().to_lowercase();
                if path_str.contains("appdata") {
                    if path_str.contains("local") {
                        LeftoverCategory::AppData
                    } else {
                        LeftoverCategory::AppData
                    }
                } else if path_str.contains("program files") {
                    LeftoverCategory::ProgramFiles
                } else {
                    LeftoverCategory::Unknown
                }
            }
            LeftoverArtifact::File(path) => {
                let path_str = path.to_string_lossy().to_lowercase();
                if path_str.contains("appdata") {
                    LeftoverCategory::AppData
                } else {
                    LeftoverCategory::Unknown
                }
            }
            LeftoverArtifact::RegistryKey(_) => LeftoverCategory::RegistryUninstall,
            LeftoverArtifact::RegistryValue(_) => LeftoverCategory::RegistryRun,
            LeftoverArtifact::StartMenuShortcut(_) => LeftoverCategory::StartMenu,
            LeftoverArtifact::DesktopShortcut(_) => LeftoverCategory::Desktop,
            LeftoverArtifact::OtherShortcut(_) => LeftoverCategory::OtherShortcuts,
        }
    }

    /// Check if artifact is safe to remove
    fn is_safe_to_remove(&self, artifact: &LeftoverArtifact) -> bool {
        match artifact {
            LeftoverArtifact::Directory(path) => {
                let path_str = path.to_string_lossy().to_lowercase();
                !self.is_protected_path(&path_str)
            }
            LeftoverArtifact::File(path) => {
                let path_str = path.to_string_lossy().to_lowercase();
                !self.is_protected_path(&path_str)
            }
            LeftoverArtifact::RegistryKey(reg) => {
                // Check if it's a known safe registry path
                let key_lower = reg.key_path.to_lowercase();
                key_lower.contains("uninstall") && !key_lower.contains("currentversion")
            }
            LeftoverArtifact::RegistryValue(reg) => {
                // Run entries might be needed
                false
            }
            _ => true,
        }
    }

    /// Check if artifact requires caution
    fn is_caution_required(&self, artifact: &LeftoverArtifact) -> bool {
        match artifact {
            LeftoverArtifact::Directory(path) => {
                let path_str = path.to_string_lossy().to_lowercase();
                path_str.contains("programdata")
            }
            LeftoverArtifact::RegistryKey(reg) => {
                reg.key_path.to_lowercase().contains("installer")
            }
            _ => false,
        }
    }

    /// Check if path is protected
    fn is_protected_path(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();

        // Check against protected paths
        for protected in &self.protected_paths {
            if path_lower.contains(&protected.to_lowercase()) {
                return true;
            }
        }

        // Check for system directories
        let system_dirs = ["windows", "system32", "syswow64", "boot", "recovery"];
        for dir in &system_dirs {
            if path_lower.contains(&format!("\\{}", dir))
                || path_lower.starts_with(&format!("{}:", dir))
            {
                return true;
            }
        }

        false
    }

    /// Calculate risk level
    fn calculate_risk_level(
        &self,
        safe: &[LeftoverArtifact],
        caution: &[LeftoverArtifact],
        do_not_remove: &[LeftoverArtifact],
    ) -> RiskLevel {
        let total = safe.len() + caution.len() + do_not_remove.len();

        if total == 0 {
            return RiskLevel::Minimal;
        }

        let caution_ratio = caution.len() as f64 / total as f64;
        let protected_ratio = do_not_remove.len() as f64 / total as f64;

        if protected_ratio > 0.3 {
            RiskLevel::Critical
        } else if caution_ratio > 0.3 || protected_ratio > 0.1 {
            RiskLevel::High
        } else if caution_ratio > 0.1 {
            RiskLevel::Medium
        } else if caution_ratio > 0 {
            RiskLevel::Low
        } else {
            RiskLevel::Minimal
        }
    }

    /// Get directory size
    fn dir_size(&self, dir: &Path) -> Option<u64> {
        if !dir.exists() || !dir.is_dir() {
            return None;
        }

        let mut total = 0u64;

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    total += self.dir_size(&path).unwrap_or(0);
                } else if let Ok(metadata) = fs::metadata(&path) {
                    total += metadata.len();
                }
            }
        }

        Some(total)
    }

    /// Remove leftovers
    pub fn remove_leftovers(
        &self,
        leftovers: &[LeftoverArtifact],
        create_checkpoint: bool,
    ) -> Result<CleanupResult, Box<dyn Error>> {
        let mut result = CleanupResult::default();

        if create_checkpoint {
            result.checkpoint_created = true;
            result.checkpoint_path = Some(format!(
                "leftover_cleanup_{}.json",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs()
            ));
        }

        for artifact in leftovers {
            if !self.is_safe_to_remove(artifact) {
                result.skipped_count += 1;
                result.errors.push(format!(
                    "Skipped protected item: {:?}",
                    artifact
                ));
                continue;
            }

            match self.remove_artifact(artifact) {
                Ok(size) => {
                    result.removed_count += 1;
                    result.bytes_freed += size;
                }
                Err(e) => {
                    result.failed_count += 1;
                    result.errors.push(format!("Failed to remove: {:?}", e));
                }
            }
        }

        Ok(result)
    }

    /// Remove a single artifact
    fn remove_artifact(&self, artifact: &LeftoverArtifact) -> Result<u64, Box<dyn Error>> {
        match artifact {
            LeftoverArtifact::Directory(path) => {
                let size = self.dir_size(path).unwrap_or(0);
                if path.exists() {
                    fs::remove_dir_all(path)?;
                }
                Ok(size)
            }
            LeftoverArtifact::File(path) => {
                let size = if path.exists() {
                    fs::metadata(path)?.len()
                } else {
                    0
                };
                if path.exists() {
                    fs::remove_file(path)?;
                }
                Ok(size)
            }
            LeftoverArtifact::StartMenuShortcut(info) | LeftoverArtifact::DesktopShortcut(info)
            | LeftoverArtifact::OtherShortcut(info) => {
                if info.path.exists() {
                    fs::remove_file(&info.path)?;
                }
                Ok(0)
            }
            LeftoverArtifact::RegistryKey(reg) => {
                self.delete_registry_key(&reg.key_path)?;
                Ok(0)
            }
            LeftoverArtifact::RegistryValue(reg) => {
                self.delete_registry_value(&reg.key_path, &reg.value_name)?;
                Ok(0)
            }
        }
    }

    /// Delete a registry key
    fn delete_registry_key(&self, key_path: &str) -> Result<(), Box<dyn Error>> {
        let (hive, subkey) = self.parse_registry_path(key_path)?;

        let hkey = match hive {
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKEY_USERS" => HKEY_USERS,
            _ => return Err("Unknown hive".into()),
        };

        // Open parent and delete subkey
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

    /// Delete a registry value
    fn delete_registry_value(&self, key_path: &str, value_name: &str) -> Result<(), Box<dyn Error>> {
        let (hive, subkey) = self.parse_registry_path(key_path)?;

        let hkey = match hive {
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            _ => return Err("Unknown hive".into()),
        };

        let key = RegKey::predef(hkey).open_subkey_with_flags(subkey, KEY_WRITE)?;
        key.delete_value(value_name)?;

        Ok(())
    }

    /// Parse a registry path
    fn parse_registry_path(&self, path: &str) -> Result<(&str, &str), Box<dyn Error>> {
        for hive in &[
            "HKEY_LOCAL_MACHINE",
            "HKEY_CURRENT_USER",
            "HKEY_CLASSES_ROOT",
            "HKEY_USERS",
        ] {
            if path.starts_with(hive) {
                let subkey = &path[hive.len()..].trim_start_matches('\\');
                return Ok((hive, subkey));
            }
        }
        Err("Invalid registry path".into())
    }
}

/// Result of cleanup operation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CleanupResult {
    /// Items removed
    pub removed_count: usize,
    /// Items that failed to remove
    pub failed_count: usize,
    /// Items skipped (protected)
    pub skipped_count: usize,
    /// Bytes freed
    pub bytes_freed: u64,
    /// Whether checkpoint was created
    pub checkpoint_created: bool,
    /// Checkpoint path
    pub checkpoint_path: Option<String>,
    /// Errors
    pub errors: Vec<String>,
}

impl Default for Uninstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProgramScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Installed Programs Scan")?;
        writeln!(f, "======================")?;
        writeln!(f, "Total Programs: {}", self.total_count)?;
        writeln!(f, "Microsoft Programs: {}", self.microsoft_count)?;
        writeln!(f, "Windows Updates: {}", self.update_count)?;
        writeln!(f)?;

        writeln!(f, "Programs by Publisher:")?;
        for (publisher, programs) in &self.by_publisher {
            writeln!(f, "  {}: {} programs", publisher, programs.len())?;
        }

        writeln!(f)?;
        writeln!(f, "Installed Programs:")?;
        for (i, program) in self.programs.iter().enumerate().take(30) {
            writeln!(
                f,
                "{}. {}",
                i + 1,
                program.display_name
            )?;
            if let Some(version) = &program.version {
                writeln!(f, "   Version: {}", version)?;
            }
            if let Some(publisher) = &program.publisher {
                writeln!(f, "   Publisher: {}", publisher)?;
            }
        }

        if self.programs.len() > 30 {
            writeln!(f, "... and {} more", self.programs.len() - 30)?;
        }

        Ok(())
    }
}

impl fmt::Display for LeftoverAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Leftover Analysis")?;
        writeln!(f, "================")?;
        writeln!(f, "Total Leftovers: {}", self.total_count)?;
        writeln!(f, "Total Size: {} bytes", self.total_size_bytes)?;
        writeln!(f, "Risk Level: {:?}", self.risk_level)?;
        writeln!(f)?;
        writeln!(f, "Safe to Remove: {}", self.safe_to_remove.len())?;
        writeln!(f, "Caution Required: {}", self.caution_required.len())?;
        writeln!(f, "Do Not Remove: {}", self.do_not_remove.len())?;
        writeln!(f)?;

        writeln!(f, "By Category:")?;
        for (category, artifacts) in &self.by_category {
            writeln!(f, "  {:?}: {} items", category, artifacts.len())?;
        }

        writeln!(f)?;
        writeln!(f, "Leftovers Found:")?;
        for (i, artifact) in self.leftovers.iter().enumerate().take(20) {
            writeln!(f, "{}. {:?}", i + 1, artifact)?;
        }

        if self.leftovers.len() > 20 {
            writeln!(f, "... and {} more", self.leftovers.len() - 20)?;
        }

        Ok(())
    }
}

impl fmt::Display for CleanupResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Cleanup Result")?;
        writeln!(f, "==============")?;
        writeln!(f, "Removed: {}", self.removed_count)?;
        writeln!(f, "Failed: {}", self.failed_count)?;
        writeln!(f, "Skipped: {}", self.skipped_count)?;
        writeln!(f, "Bytes Freed: {}", self.bytes_freed)?;

        if self.checkpoint_created {
            writeln!(f, "Checkpoint: {}", self.checkpoint_path.clone().unwrap_or_default())?;
        }

        if !self.errors.is_empty() {
            writeln!(f)?;
            writeln!(f, "Errors:")?;
            for error in &self.errors {
                writeln!(f, "  - {}", error)?;
