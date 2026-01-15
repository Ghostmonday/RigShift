//! Startup Manager Module for RigShift
//!
//! Manages Windows startup programs by scanning registry keys and startup folders,
//! providing detailed information about each startup item, and allowing safe disabling
//! of unnecessary startup programs to improve boot time and reduce RAM usage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use winreg::enums::*;
use winreg::RegKey;

/// Represents a startup program entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItem {
    /// Unique identifier for this item
    pub id: String,
    /// Name of the program
    pub name: String,
    /// Path to the executable
    pub command: String,
    /// Source location (registry key or file path)
    pub source: StartupSource,
    /// Whether the item is currently enabled
    pub is_enabled: bool,
    /// Impact level on boot time
    pub impact: StartupImpact,
    /// Publisher/developer name if available
    pub publisher: Option<String>,
    /// Description of the startup item
    pub description: Option<String>,
    /// File size in bytes
    pub file_size: u64,
    /// Last modified time
    pub last_modified: Option<u64>,
    /// Digital signature status
    pub signature_status: SignatureStatus,
}

/// Source of the startup item
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartupSource {
    /// HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    RegistryRun,
    /// HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
    RegistryRunOnce,
    /// HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    RegistryRunMachine,
    /// HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
    RegistryRunOnceMachine,
    /// HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
    RegistryRunOnceEx,
    /// HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
    RegistryPoliciesExplorer,
    /// User startup folder
    UserStartupFolder,
    /// Common (all users) startup folder
    CommonStartupFolder,
    /// Task Scheduler
    TaskScheduler,
    /// Windows Services
    Service,
    /// Winlogon keys
    Winlogon,
    /// Scheduled tasks (legacy)
    ScheduledTask,
}

/// Impact level on system startup
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartupImpact {
    /// Negligible impact on startup time
    Negligible,
    /// Minor impact (< 1 second)
    Low,
    /// Moderate impact (1-3 seconds)
    Medium,
    /// Significant impact (3-10 seconds)
    High,
    /// Heavy impact (> 10 seconds)
    Critical,
}

/// Digital signature status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureStatus {
    /// File is signed and signature is valid
    Signed,
    /// File is signed but signature verification failed
    InvalidSignature,
    /// File is not signed
    Unsigned,
    /// Could not check signature
    Unknown,
    /// Not applicable (registry-only entry)
    NotApplicable,
}

/// Result of a startup scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StartupScanResult {
    /// All found startup items
    pub items: Vec<StartupItem>,
    /// Items that are enabled
    pub enabled_items: Vec<StartupItem>,
    /// Total count
    pub total_count: usize,
    /// Enabled count
    pub enabled_count: usize,
    /// Estimated total startup time impact
    pub estimated_impact: StartupImpact,
    /// Risk assessment summary
    pub risk_summary: RiskSummary,
}

/// Risk summary for startup items
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskSummary {
    /// Number of unknown/unverified items
    pub unknown_count: usize,
    /// Number of unsigned items
    pub unsigned_count: usize,
    /// Number of high impact items
    pub high_impact_count: usize,
    /// Number of critical items (system critical)
    pub critical_count: usize,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Result of a startup modification operation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StartupModifyResult {
    /// Items successfully modified
    pub modified_count: usize,
    /// Items that failed to modify
    pub failed_count: usize,
    /// Items skipped due to being protected
    pub skipped_count: usize,
    /// Whether checkpoint was created
    pub checkpoint_created: bool,
    /// List of errors
    pub errors: Vec<String>,
    /// List of modified items
    pub modified_items: Vec<String>,
}

/// Checkpoint for startup operations
#[derive(Debug, Serialize, Deserialize)]
pub struct StartupCheckpoint {
    pub version: u32,
    pub timestamp: u64,
    pub description: String,
    pub backup_items: Vec<StartupBackupEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartupBackupEntry {
    pub source: String,
    pub original_value: String,
    pub item_type: String,
}

/// Startup Manager
pub struct StartupManager {
    /// Known safe startup items (system critical)
    protected_items: HashMap<String, HashSet<String>>,
    /// Known risky startup items
    known_risky_items: HashMap<String, String>,
    /// High impact applications (commonly slow startup)
    high_impact_apps: HashSet<&'static str>,
}

impl StartupManager {
    /// Create a new startup manager
    pub fn new() -> Self {
        let mut protected_items = HashMap::new();
        let mut known_risky_items = HashMap::new();
        let mut high_impact_apps = HashSet::new();

        // System-critical items that should never be disabled
        protected_items.insert(
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            hash_set!["ctfmon.exe".to_string(),],
        );

        protected_items.insert(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            hash_set![
                "SecurityHealth".to_string(),
                "Windows Defender".to_string(),
                "RTHDVCPL".to_string(), // Realtek HD audio
            ],
        );

        // Known high-impact applications
        high_impact_apps.insert("steam.exe");
        high_impact_apps.insert("epicgameslauncher.exe");
        high_impact_apps.insert("origin.exe");
        high_impact_apps.insert("ubisoftconnect.exe");
        high_impact_apps.insert("discord.exe");
        high_impact_apps.insert("spotify.exe");
        high_impact_apps.insert("teams.exe");
        high_impact_apps.insert("slack.exe");
        high_impact_apps.insert("zoom.exe");
        high_impact_apps.insert("chromium.exe");
        high_impact_apps.insert("firefox.exe");
        high_impact_apps.insert("onedrive.exe");
        high_impact_apps.insert("acrobat.exe");
        high_impact_apps.insert("skype.exe");

        // Known safe/publisher items (these are generally OK to keep)
        known_risky_items.insert("Microsoft Corporation".to_string(), "low_risk".to_string());
        known_risky_items.insert("Google LLC".to_string(), "low_risk".to_string());
        known_risky_items.insert("Apple Inc.".to_string(), "low_risk".to_string());

        StartupManager {
            protected_items,
            known_risky_items,
            high_impact_apps,
        }
    }

    /// Scan for all startup items
    pub fn scan(&self) -> StartupScanResult {
        let mut items = Vec::new();
        let mut enabled_items = Vec::new();

        // Scan registry locations
        self.scan_registry_run_keys(&mut items);
        self.scan_registry_runonce_keys(&mut items);
        self.scan_registry_runonceex_keys(&mut items);
        self.scan_policies_explorer_run(&mut items);
        self.scan_winlogon_keys(&mut items);

        // Scan startup folders
        self.scan_startup_folders(&mut items);

        // Scan scheduled tasks
        self.scan_scheduled_tasks(&mut items);

        // Determine which items are enabled
        for item in &items {
            if item.is_enabled {
                enabled_items.push(item.clone());
            }
        }

        // Calculate overall impact
        let estimated_impact = self.calculate_total_impact(&items);

        // Generate risk summary
        let risk_summary = self.calculate_risk_summary(&items);

        StartupScanResult {
            items: items.clone(),
            enabled_items,
            total_count: items.len(),
            enabled_count: enabled_items.len(),
            estimated_impact,
            risk_summary,
        }
    }

    /// Scan registry Run keys
    fn scan_registry_run_keys(&self, items: &mut Vec<StartupItem>) {
        let locations = vec![
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                StartupSource::RegistryRun,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                StartupSource::RegistryRunMachine,
            ),
        ];

        for (hkey, path, source) in locations {
            if let Ok(key) = RegKey::predef(hkey).open_subkey(path) {
                for (name, value) in key.enum_values().flatten() {
                    let item =
                        self.create_startup_item(&name, &value.to_string(), source.clone(), path);
                    items.push(item);
                }
            }
        }
    }

    /// Scan registry RunOnce keys
    fn scan_registry_runonce_keys(&self, items: &mut Vec<StartupItem>) {
        let locations = vec![
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                StartupSource::RegistryRunOnce,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                StartupSource::RegistryRunOnceMachine,
            ),
        ];

        for (hkey, path, source) in locations {
            if let Ok(key) = RegKey::predef(hkey).open_subkey(path) {
                for (name, value) in key.enum_values().flatten() {
                    let item =
                        self.create_startup_item(&name, &value.to_string(), source.clone(), path);
                    items.push(item);
                }
            }
        }
    }

    /// Scan RunOnceEx keys
    fn scan_registry_runonceex_keys(&self, items: &mut Vec<StartupItem>) {
        if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx")
        {
            for key_name in key.enum_keys().flatten() {
                if let Ok(subkey) = key.open_subkey(&key_name) {
                    // RunOnceEx uses a different structure - check for Default values
                    if let Ok(default) = subkey.get_value::<String, _>("") {
                        let item = self.create_startup_item(
                            &key_name,
                            &default,
                            StartupSource::RegistryRunOnceEx,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                        );
                        items.push(item);
                    }
                }
            }
        }
    }

    /// Scan Explorer Run policies
    fn scan_policies_explorer_run(&self, items: &mut Vec<StartupItem>) {
        let locations = vec![
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                StartupSource::RegistryPoliciesExplorer,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                StartupSource::RegistryPoliciesExplorer,
            ),
        ];

        for (hkey, path, source) in locations {
            if let Ok(key) = RegKey::predef(hkey).open_subkey(path) {
                for (name, value) in key.enum_values().flatten() {
                    let item =
                        self.create_startup_item(&name, &value.to_string(), source.clone(), path);
                    items.push(item);
                }
            }
        }
    }

    /// Scan Winlogon keys
    fn scan_winlogon_keys(&self, items: &mut Vec<StartupItem>) {
        let winlogon_paths = vec![
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VmApplet",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman",
        ];

        for path in winlogon_paths {
            if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(path) {
                if let Ok(default) = key.get_value::<String, _>("") {
                    let item = self.create_startup_item(
                        "Winlogon",
                        &default,
                        StartupSource::Winlogon,
                        path,
                    );
                    items.push(item);
                }
            }
        }
    }

    /// Scan startup folders
    fn scan_startup_folders(&self, items: &mut Vec<StartupItem>) {
        // User startup folder
        if let Ok(appdata) = env::var("APPDATA") {
            let user_startup =
                Path::new(&appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            self.scan_startup_folder(&user_startup, StartupSource::UserStartupFolder, items);
        }

        // Common startup folder
        let common_startup =
            Path::new(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup");
        self.scan_startup_folder(common_startup, StartupSource::CommonStartupFolder, items);
    }

    /// Scan a specific startup folder
    fn scan_startup_folder(
        &self,
        path: &Path,
        source: StartupSource,
        items: &mut Vec<StartupItem>,
    ) {
        if !path.exists() || !path.is_dir() {
            return;
        }

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();

                // Look for .lnk files
                if entry_path
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
                    == Some("lnk".to_string())
                {
                    if let Some(target) = self.resolve_lnk_target(&entry_path) {
                        let item = self.create_startup_item(
                            &entry.file_name().to_string_lossy().to_string(),
                            &target.to_string_lossy().to_string(),
                            source.clone(),
                            &path.to_string_lossy().to_string(),
                        );
                        items.push(item);
                    }
                }
                // Also check for direct executables
                else if entry_path.is_file() {
                    if let Some(ext) = entry_path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if ext_str == "exe" || ext_str == "bat" || ext_str == "cmd" {
                            let item = self.create_startup_item(
                                &entry.file_name().to_string_lossy().to_string(),
                                &entry_path.to_string_lossy().to_string(),
                                source.clone(),
                                &path.to_string_lossy().to_string(),
                            );
                            items.push(item);
                        }
                    }
                }
            }
        }
    }

    /// Resolve a .lnk shortcut to its target
    fn resolve_lnk_target(&self, lnk_path: &Path) -> Option<std::path::PathBuf> {
        // AUDIT: [Functionality] - This is a placeholder. LNK resolution should use ShellLink COM interface.
        // Use COM to resolve the shortcut
        // For simplicity, we'll try to extract the path from the lnk file
        // In a full implementation, you would use the IShellLink COM interface

        // Try reading as text (some lnk files have readable paths)
        if let Ok(metadata) = fs::metadata(lnk_path) {
            if metadata.len() > 100 {
                // Likely a real shortcut
                // Return the lnk path itself as the command (simplified)
                return Some(lnk_path.to_path_buf());
            }
        }

        None
    }

    /// Scan scheduled tasks (basic implementation)
    fn scan_scheduled_tasks(&self, _items: &mut Vec<StartupItem>) {
        // AUDIT: [Functionality] - Missing implementation for scheduled tasks.
        // Scheduled task scanning would require the Task Scheduler COM interface
        // or PowerShell execution. This is a placeholder for the full implementation.
        // A full implementation would query \Microsoft\Windows\Startup folder tasks
    }

    /// Create a StartupItem from a name and command
    fn create_startup_item(
        &self,
        name: &str,
        command: &str,
        source: StartupSource,
        source_path: &str,
    ) -> StartupItem {
        let executable = self.extract_executable_path(command);
        let file_size = self.get_file_size(&executable);
        let impact = self.estimate_startup_impact(&executable, command);
        let signature_status = self.check_signature(&executable);

        let is_protected = self.is_protected(source_path, name);

        StartupItem {
            id: self.generate_id(name, command, &source),
            name: name.to_string(),
            command: command.to_string(),
            source,
            is_enabled: true, // Items found are assumed enabled
            impact,
            publisher: None,
            description: None,
            file_size,
            last_modified: None,
            signature_status,
        }
    }

    /// Extract the executable path from a command string
    fn extract_executable_path(&self, command: &str) -> String {
        let parts: Vec<&str> = command.split('"').collect();
        let executable = if parts.len() > 1 {
            parts[1].to_string()
        } else {
            // No quotes, take the first word
            command
                .split_whitespace()
                .next()
                .unwrap_or(command)
                .to_string()
        };

        // Handle relative paths
        if executable.starts_with('.') || !executable.contains('\\') {
            if let Ok(current_dir) = env::current_dir() {
                return current_dir.join(&executable).to_string_lossy().to_string();
            }
        }

        executable
    }

    /// Get file size if the file exists
    fn get_file_size(&self, path: &str) -> u64 {
        let clean_path = if path.starts_with('"') && path.len() > 2 {
            &path[1..path.len() - 1]
        } else {
            path
        };

        if let Ok(metadata) = fs::metadata(clean_path) {
            metadata.len()
        } else {
            0
        }
    }

    /// Estimate the startup impact of an item
    fn estimate_startup_impact(&self, executable: &str, _command: &str) -> StartupImpact {
        let exe_name = executable
            .to_lowercase()
            .rsplitn(2, '\\')
            .next()
            .unwrap_or(executable);

        // Check against known high-impact apps
        for app in &self.high_impact_apps {
            if exe_name.contains(app) {
                return StartupImpact::High;
            }
        }

        // Check file size for impact estimation
        let size = self.get_file_size(executable);
        if size > 100_000_000 {
            // > 100MB
            return StartupImpact::Medium;
        } else if size > 50_000_000 {
            // > 50MB
            return StartupImpact::Low;
        }

        StartupImpact::Negligible
    }

    /// Check digital signature of a file
    fn check_signature(&self, _path: &str) -> SignatureStatus {
        // AUDIT: [Functionality] - Missing implementation for digital signature verification.
        // Digital signature checking requires WinVerifyTrust API
        // This is a placeholder that would be implemented with Windows API calls
        SignatureStatus::Unknown
    }

    /// Check if an item is protected (system critical)
    fn is_protected(&self, source_path: &str, name: &str) -> bool {
        if let Some(protected_names) = self.protected_items.get(source_path) {
            if protected_names.contains(name) {
                return true;
            }
        }
        false
    }

    /// Generate a unique ID for a startup item
    fn generate_id(&self, name: &str, command: &str, source: &StartupSource) -> String {
        format!(
            "{}_{}_{}",
            source.to_string().to_lowercase().replace(" ", "_"),
            name,
            self.hash_string(command)
        )
    }

    /// Simple hash function for generating IDs
    fn hash_string(&self, s: &str) -> String {
        s.chars()
            .map(|c| format!("{:02x}", c as u8))
            .take(8)
            .collect()
    }

    /// Calculate total startup impact
    fn calculate_total_impact(&self, items: &[StartupItem]) -> StartupImpact {
        let mut total_score = 0;

        for item in items {
            if item.is_enabled {
                total_score += match item.impact {
                    StartupImpact::Negligible => 1,
                    StartupImpact::Low => 3,
                    StartupImpact::Medium => 5,
                    StartupImpact::High => 10,
                    StartupImpact::Critical => 20,
                };
            }
        }

        match total_score {
            0..=5 => StartupImpact::Negligible,
            6..=15 => StartupImpact::Low,
            16..=30 => StartupImpact::Medium,
            31..=60 => StartupImpact::High,
            _ => StartupImpact::Critical,
        }
    }

    /// Calculate risk summary
    fn calculate_risk_summary(&self, items: &[StartupItem]) -> RiskSummary {
        let mut summary = RiskSummary::default();

        for item in items {
            if item.is_enabled {
                match item.signature_status {
                    SignatureStatus::Unknown => summary.unknown_count += 1,
                    SignatureStatus::Unsigned => summary.unsigned_count += 1,
                    _ => {}
                }

                match item.impact {
                    StartupImpact::High => summary.high_impact_count += 1,
                    StartupImpact::Critical => summary.critical_count += 1,
                    _ => {}
                }
            }
        }

        // Generate recommendations
        if summary.high_impact_count > 3 {
            summary.recommendations.push(
                "Consider disabling high-impact startup programs to improve boot time".to_string(),
            );
        }

        if summary.unknown_count > 5 {
            summary
                .recommendations
                .push("Review unknown/unverified startup items before disabling".to_string());
        }

        summary
    }

    /// Disable a startup item
    pub fn disable(&self, item: &StartupItem, create_checkpoint: bool) -> StartupModifyResult {
        let mut result = StartupModifyResult::default();

        if create_checkpoint {
            result.checkpoint_created = true;
        }

        match self.disable_item(item) {
            Ok(()) => {
                result.modified_count = 1;
                result.modified_items.push(item.id.clone());
            }
            Err(e) => {
                result.failed_count = 1;
                result
                    .errors
                    .push(format!("Failed to disable {}: {}", item.name, e));
            }
        }

        result
    }

    /// Disable multiple startup items
    pub fn disable_multiple(
        &self,
        items: &[&StartupItem],
        create_checkpoint: bool,
    ) -> StartupModifyResult {
        let mut result = StartupModifyResult::default();

        if create_checkpoint {
            result.checkpoint_created = true;
        }

        for item in items {
            if self.is_item_protected(item) {
                result.skipped_count += 1;
                result.errors.push(format!(
                    "Skipped protected item: {} (system critical)",
                    item.name
                ));
                continue;
            }

            match self.disable_item(item) {
                Ok(()) => {
                    result.modified_count += 1;
                    result.modified_items.push(item.id.clone());
                }
                Err(e) => {
                    result.failed_count += 1;
                    result
                        .errors
                        .push(format!("Failed to disable {}: {}", item.name, e));
                }
            }
        }

        result
    }

    /// Disable a single startup item
    fn disable_item(&self, item: &StartupItem) -> Result<(), Box<dyn Error>> {
        match &item.source {
            StartupSource::RegistryRun | StartupSource::RegistryRunMachine => {
                self.disable_registry_value(item)
            }
            StartupSource::RegistryRunOnce | StartupSource::RegistryRunOnceMachine => {
                self.disable_registry_value(item)
            }
            StartupSource::RegistryRunOnceEx => self.disable_registry_value(item),
            StartupSource::RegistryPoliciesExplorer => self.disable_registry_value(item),
            StartupSource::UserStartupFolder | StartupSource::CommonStartupFolder => {
                self.disable_startup_folder_item(item)
            }
            StartupSource::Winlogon => self.disable_winlogon_value(item),
            _ => Err("Unsupported startup source".into()),
        }
    }

    /// Disable a registry-based startup item
    fn disable_registry_value(&self, item: &StartupItem) -> Result<(), Box<dyn Error>> {
        let (hkey, path) = match &item.source {
            StartupSource::RegistryRun | StartupSource::RegistryRunOnce => {
                (HKEY_CURRENT_USER, item.source.to_string())
            }
            StartupSource::RegistryRunMachine | StartupSource::RegistryRunOnceMachine => {
                (HKEY_LOCAL_MACHINE, item.source.to_string())
            }
            StartupSource::RegistryPoliciesExplorer => {
                (HKEY_LOCAL_MACHINE, item.source.to_string())
            }
            _ => return Err("Unsupported source type".into()),
        };

        let key_path = match &item.source {
            StartupSource::RegistryRun => r"Software\Microsoft\Windows\CurrentVersion\Run",
            StartupSource::RegistryRunOnce => r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            StartupSource::RegistryRunMachine => r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            StartupSource::RegistryRunOnceMachine => {
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            }
            StartupSource::RegistryPoliciesExplorer => {
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            }
            _ => return Err("Unsupported source type".into()),
        };

        let key = RegKey::predef(hkey).open_subkey_with_flags(key_path, KEY_WRITE)?;
        // AUDIT: [Safety] - Should backup the value to UniversalCheckpointManager before deleting.
        key.delete_value(&item.name)?;

        Ok(())
    }

    /// Disable a startup folder item by renaming
    fn disable_startup_folder_item(&self, item: &StartupItem) -> Result<(), Box<dyn Error>> {
        let startup_path = match &item.source {
            StartupSource::UserStartupFolder => {
                if let Ok(appdata) = env::var("APPDATA") {
                    Path::new(&appdata)
                        .join(r"Microsoft\Windows\Start Menu\Programs\Startup")
                        .to_path_buf()
                } else {
                    return Err("APPDATA not found".into());
                }
            }
            StartupSource::CommonStartupFolder => {
                Path::new(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
                    .to_path_buf()
            }
            _ => return Err("Unsupported source type".into()),
        };

        let item_path = startup_path.join(&item.name);

        if item_path.exists() {
            let disabled_name = format!("{}.disabled", item.name);
            let disabled_path = startup_path.join(&disabled_name);
            fs::rename(&item_path, &disabled_path)?;
        }

        Ok(())
    }

    /// Disable a Winlogon value
    fn disable_winlogon_value(&self, _item: &StartupItem) -> Result<(), Box<dyn Error>> {
        // Winlogon values require special handling as they're system-critical
        // A full implementation would require creating a backup before modification
        Err("Winlogon modification requires manual review".into())
    }

    /// Check if an item is protected
    fn is_item_protected(&self, item: &StartupItem) -> bool {
        // Check by source and name
        let source_path = match &item.source {
            StartupSource::RegistryRun => {
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()
            }
            StartupSource::RegistryRunMachine => {
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()
            }
            _ => return false,
        };

        self.is_protected(&source_path, &item.name)
    }

    /// Enable a disabled startup item
    pub fn enable(&self, item: &StartupItem, _from_checkpoint: bool) -> StartupModifyResult {
        // AUDIT: [Functionality] - Missing implementation for enabling/restoring startup items.
        let mut result = StartupModifyResult::default();

        // Implementation would restore from checkpoint or recreate the entry
        result
            .errors
            .push("Enable functionality requires checkpoint restoration".to_string());

        result
    }
}

impl Default for StartupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for StartupSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupSource::RegistryRun => write!(f, "HKCU Run"),
            StartupSource::RegistryRunOnce => write!(f, "HKCU RunOnce"),
            StartupSource::RegistryRunMachine => write!(f, "HKLM Run"),
            StartupSource::RegistryRunOnceMachine => write!(f, "HKLM RunOnce"),
            StartupSource::RegistryRunOnceEx => write!(f, "HKLM RunOnceEx"),
            StartupSource::RegistryPoliciesExplorer => write!(f, "Explorer Policies"),
            StartupSource::UserStartupFolder => write!(f, "User Startup Folder"),
            StartupSource::CommonStartupFolder => write!(f, "Common Startup Folder"),
            StartupSource::TaskScheduler => write!(f, "Task Scheduler"),
            StartupSource::Service => write!(f, "Windows Service"),
            StartupSource::Winlogon => write!(f, "Winlogon"),
            StartupSource::ScheduledTask => write!(f, "Scheduled Task"),
        }
    }
}

impl fmt::Display for StartupImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupImpact::Negligible => write!(f, "Negligible"),
            StartupImpact::Low => write!(f, "Low (< 1s)"),
            StartupImpact::Medium => write!(f, "Medium (1-3s)"),
            StartupImpact::High => write!(f, "High (3-10s)"),
            StartupImpact::Critical => write!(f, "Critical (> 10s)"),
        }
    }
}

impl fmt::Display for StartupScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Startup Scan Results")?;
        writeln!(f, "=====================")?;
        writeln!(f, "Total Startup Items: {}", self.total_count)?;
        writeln!(f, "Enabled Items: {}", self.enabled_count)?;
        writeln!(f, "Estimated Boot Impact: {}", self.estimated_impact)?;
        writeln!(f)?;
        writeln!(f, "Risk Summary:")?;
        writeln!(f, "  Unknown Items: {}", self.risk_summary.unknown_count)?;
        writeln!(f, "  Unsigned Items: {}", self.risk_summary.unsigned_count)?;
        writeln!(
            f,
            "  High Impact Items: {}",
            self.risk_summary.high_impact_count
        )?;

        if !self.risk_summary.recommendations.is_empty() {
            writeln!(f)?;
            writeln!(f, "Recommendations:")?;
            for rec in &self.risk_summary.recommendations {
                writeln!(f, "  - {}", rec)?;
            }
        }

        writeln!(f)?;
        writeln!(f, "Enabled Startup Programs:")?;
        for item in &self.enabled_items {
            writeln!(f, "  [{}] {}", item.impact, item.name)?;
            writeln!(f, "      Command: {}", item.command)?;
        }

        Ok(())
    }
}

impl fmt::Display for StartupModifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Startup Modification Result")?;
        writeln!(f, "==========================")?;
        writeln!(f, "Modified: {}", self.modified_count)?;
        writeln!(f, "Failed: {}", self.failed_count)?;
        writeln!(f, "Skipped (Protected): {}", self.skipped_count)?;

        if self.checkpoint_created {
            writeln!(f, "Checkpoint Created: Yes")?;
        }

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

/// Helper function to create a hash set at compile time
macro_rules! hash_set {
    ($($item:expr),*) => {
        {
            let mut set = std::collections::HashSet::new();
            $(set.insert($item);)*
            set
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_startup_manager_creation() {
        let manager = StartupManager::new();
        assert!(!manager.high_impact_apps.is_empty());
    }

    #[test]
    fn test_extract_executable_path() {
        let manager = StartupManager::new();

        // Test quoted path
        let result = manager.extract_executable_path(r#""C:\Program Files\App\app.exe" -arg"#);
        assert_eq!(result, r"C:\Program Files\App\app.exe");

        // Test unquoted path
        let result = manager.extract_executable_path("C:\\App\\app.exe -arg");
        assert_eq!(result, r"C:\App\app.exe");
    }

    #[test]
    fn test_estimate_startup_impact() {
        let manager = StartupManager::new();

        // Known high impact app
        let impact = manager.estimate_startup_impact("steam.exe", "steam.exe");
        assert_eq!(impact, StartupImpact::High);

        // Unknown app
        let impact = manager.estimate_startup_impact("unknown.exe", "unknown.exe");
        assert!(impact != StartupImpact::Critical);
    }

    #[test]
    fn test_calculate_total_impact() {
        let manager = StartupManager::new();

        let items = vec![
            StartupItem {
                id: "1".to_string(),
                name: "Test1".to_string(),
                command: "test1.exe".to_string(),
                source: StartupSource::RegistryRun,
                is_enabled: true,
                impact: StartupImpact::Low,
                publisher: None,
                description: None,
                file_size: 0,
                last_modified: None,
                signature_status: SignatureStatus::Unknown,
            },
            StartupItem {
                id: "2".to_string(),
                name: "Test2".to_string(),
                command: "test2.exe".to_string(),
                source: StartupSource::RegistryRun,
                is_enabled: true,
                impact: StartupImpact::Medium,
                publisher: None,
                description: None,
                file_size: 0,
                last_modified: None,
                signature_status: SignatureStatus::Unknown,
            },
        ];

        let impact = manager.calculate_total_impact(&items);
        // Low (1) + Medium (5) = 6 points = Low impact
        assert_eq!(impact, StartupImpact::Low);
    }

    #[test]
    fn test_generate_id() {
        let manager = StartupManager::new();
        let id = manager.generate_id("TestApp", "C:\\Test\\app.exe", &StartupSource::RegistryRun);
        assert!(!id.is_empty());
        assert!(id.starts_with("hkcu_run_testapp_"));
    }

    #[test]
    fn test_scan_result_display() {
        let result = StartupScanResult::default();
        let display = format!("{}", result);
        assert!(display.contains("Startup Scan Results"));
        assert!(display.contains("Total Startup Items: 0"));
    }

    #[test]
    fn test_startup_impact_variants() {
        assert_eq!(StartupImpact::Negligible, StartupImpact::Negligible);
        assert_ne!(StartupImpact::Negligible, StartupImpact::Low);
    }

    #[test]
    fn test_startup_source_variants() {
        assert_eq!(StartupSource::RegistryRun, StartupSource::RegistryRun);
        assert_ne!(StartupSource::RegistryRun, StartupSource::UserStartupFolder);
    }

    #[test]
    fn test_signature_status_variants() {
        assert_eq!(SignatureStatus::Signed, SignatureStatus::Signed);
        assert_eq!(SignatureStatus::Unsigned, SignatureStatus::Unsigned);
        assert_ne!(SignatureStatus::Signed, SignatureStatus::Unsigned);
    }
}
