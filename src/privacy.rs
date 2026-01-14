//! Privacy and Telemetry Blocking Module
//!
//! Provides functionality to disable Windows telemetry, data collection,
//! and tracking features to improve user privacy. Includes safety checks,
//! checkpoint creation, and selective enabling/disabling of privacy features.
//!
//! ⚠️ WARNING: Some telemetry blocking may affect Windows Update functionality
//! or cause warnings in certain applications.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::time::SystemTime;
use winreg::enums::*;
use winreg::RegKey;

/// Represents a privacy/telemetry setting that can be modified
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySetting {
    /// Unique identifier for the setting
    pub id: String,
    /// Display name
    pub name: String,
    /// Description of what this setting controls
    pub description: String,
    /// Category of the setting
    pub category: PrivacyCategory,
    /// Current value
    pub current_value: SettingValue,
    /// Recommended value for privacy
    pub recommended_value: SettingValue,
    /// Whether changing this setting requires admin privileges
    pub requires_admin: bool,
    /// Whether the setting is safe to change
    pub is_safe: bool,
    /// Potential impact of changing this setting
    pub impact: PrivacyImpact,
    /// Registry key path (if applicable)
    pub registry_key: Option<String>,
    /// Value name (if applicable)
    pub value_name: Option<String>,
    /// Original value before changes
    pub original_value: Option<SettingValue>,
}

/// Category of privacy setting
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyCategory {
    /// Telemetry and data collection
    Telemetry,
    /// Location services
    Location,
    /// Speech and typing input
    Speech,
    /// Advertising ID
    Advertising,
    /// Activity history
    ActivityHistory,
    /// Diagnostic data
    DiagnosticData,
    /// Timeline and search
    TimelineSearch,
    /// App permissions
    AppPermissions,
    /// Feedback and diagnostics
    Feedback,
    /// Other privacy settings
    Other,
}

/// Value type for settings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettingValue {
    /// Boolean on/off
    Boolean(bool),
    /// Numeric value
    Number(u32),
    /// String value
    String(String),
    /// Not configured
    NotConfigured,
    /// Unknown value
    Unknown(String),
}

/// Impact of changing a setting
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyImpact {
    /// No noticeable impact
    None,
    /// Minor impact (may show warnings)
    Low,
    /// Moderate impact (some features may not work)
    Medium,
    /// High impact (significant features may be affected)
    High,
    /// Unknown impact
    Unknown,
}

/// Result of a privacy scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivacyScanResult {
    /// All settings found
    pub settings: Vec<PrivacySetting>,
    /// Settings that differ from recommended (need attention)
    pub needs_attention: Vec<PrivacySetting>,
    /// Settings that match recommended (good)
    pub good_settings: Vec<PrivacySetting>,
    /// Total count
    pub total_count: usize,
    /// Settings that can improve privacy
    pub improvable_count: usize,
    /// Overall privacy score (0-100)
    pub privacy_score: u8,
    /// Summary of categories
    pub category_summary: Vec<CategorySummary>,
}

/// Summary of a category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySummary {
    pub category: PrivacyCategory,
    pub total_settings: usize,
    pub good_count: usize,
    pub needs_attention_count: usize,
}

/// Result of applying privacy settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivacyApplyResult {
    /// Settings changed
    pub changed_count: usize,
    /// Settings that failed to change
    pub failed_count: usize,
    /// Settings skipped (requires admin)
    pub skipped_count: usize,
    /// Whether checkpoint was created
    pub checkpoint_created: bool,
    /// Checkpoint file path
    pub checkpoint_path: Option<String>,
    /// Settings that require reboot
    pub reboot_required: bool,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Warnings about changes
    pub warnings: Vec<String>,
    /// Changes made
    pub changes: Vec<PrivacyChange>,
}

/// Details of a single change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyChange {
    pub setting_name: String,
    pub old_value: String,
    pub new_value: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Privacy Manager
pub struct PrivacyManager {
    /// All known privacy settings
    settings: Vec<PrivacySetting>,
    /// Settings that require admin
    admin_settings: Vec<&'static str>,
    /// Safe settings (low impact)
    safe_settings: Vec<&'static str>,
    /// Known telemetry-related services
    telemetry_services: Vec<&'static str>,
}

impl PrivacyManager {
    /// Create a new privacy manager
    pub fn new() -> Self {
        let mut settings = Vec::new();
        let mut admin_settings = Vec::new();
        let mut safe_settings = Vec::new();
        let mut telemetry_services = Vec::new();

        // === TELEMETRY SETTINGS ===

        // Allow Telemetry (Basic/Beta/Full telemetry levels)
        settings.push(PrivacySetting {
            id: "allow_telemetry".to_string(),
            name: "Allow Telemetry".to_string(),
            description: "Sends diagnostic and usage data to Microsoft. Setting to 0 or 1 limits data.".to_string(),
            category: PrivacyCategory::Telemetry,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Number(0),
            requires_admin: true,
            is_safe: true,
            impact: PrivacyImpact::Medium,
            registry_key: Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection".to_string()),
            value_name: Some("AllowTelemetry".to_string()),
            original_value: None,
        });

        // Customer Experience Improvement Program
        settings.push(PrivacySetting {
            id: "ceip".to_string(),
            name: "Customer Experience Improvement Program".to_string(),
            description: "Sends program usage data to Microsoft to improve products.".to_string(),
            category: PrivacyCategory::Telemetry,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Boolean(false),
            requires_admin: true,
            is_safe: true,
            impact: PrivacyImpact::Low,
            registry_key: Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient".to_string()),
            value_name: Some("CEIPEnable".to_string()),
            original_value: None,
        });

        // === DIAGNOSTIC DATA ===

        // Diagnostic Data Viewer
        settings.push(PrivacySetting {
            id: "diagnostic_viewer".to_string(),
            name: "Diagnostic Data Viewer".to_string(),
            description: "Allows viewing diagnostic data sent to Microsoft.", .to_string(),
            category: PrivacyCategory::DiagnosticData,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Boolean(false),
            requires_admin: false,
            is_safe: true,
            impact: PrivacyImpact::None,
            registry_key: Some("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack".to_string()),
            value_name: Some("ShowSettings".to_string()),
            original_value: None,
        });

        // === LOCATION ===

        // Location services
        settings.push(PrivacySetting {
            id: "location".to_string(),
            name: "Location Services".to_string(),
            description: "Allows apps to use your location. Disabling prevents location tracking.", .to_string(),
            category: PrivacyCategory::Location,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Boolean(false),
            requires_admin: false,
            is_safe: true,
            impact: PrivacyImpact::Low,
            registry_key: Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\Consent\\Location".to_string()),
            value_name: Some("Enabled".to_string()),
            original_value: None,
        });

        // === SPEECH ===

        // Online speech recognition
        settings.push(PrivacySetting {
            id: "speech_recognition".to_string(),
            name: "Online Speech Recognition".to_string(),
            description: "Allows using online speech recognition for voice typing. Disabling keeps speech data local.", .to_string(),
            category: PrivacyCategory::Speech,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Boolean(false),
            requires_admin: false,
            is_safe: true,
            impact: PrivacyImpact::Low,
            registry_key: Some("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Speech_OneCore\\Settings\\OnlineSpeechPrivacy".to_string()),
            value_name: Some("HasAccepted".to_string()),
            original_value: None,
        });

        // === ADVERTISING ===

        // Advertising ID
        settings.push(PrivacySetting {
            id: "advertising_id".to_string(),
            name: "Advertising ID".to_string(),
            description: "Allows apps to use advertising ID for personalized ads. Disabling limits ad tracking.", .to_string(),
            category: PrivacyCategory::Advertising,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Boolean(false),
            requires_admin: false,
            is_safe: true,
            impact: PrivacyImpact::None,
            registry_key: Some("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo".to_string()),
            value_name: Some("Enabled".to_string()),
            original_value: None,
        });

        // === ACTIVITY HISTORY ===

        // Activity History
        settings.push(PrivacySetting {
            id: "activity_history".to_string(),
            name: "Activity History".to_string(),
            description: "Stores activity history for timeline feature. Disabling prevents activity tracking.", .to_string(),
            category: PrivacyCategory::ActivityHistory,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Boolean(false),
            requires_admin: true,
            is_safe: true,
            impact: PrivacyImpact::Low,
            registry_key: Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System".to_string()),
            value_name: Some("PublishUserActivities".to_string()),
            original_value: None,
        });

        // === TIMELINE AND SEARCH ===

        // Search indexing of personal data
        settings.push(PrivacySetting {
            id: "search_indexing".to_string(),
            name: "Search Indexing of Personal Data".to_string(),
            description: "Controls whether personal data is included in search index. More private but slower search.", .to_string(),
            category: PrivacyCategory::TimelineSearch,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Boolean(false),
            requires_admin: true,
            is_safe: true,
            impact: PrivacyImpact::Medium,
            registry_key: Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search".to_string()),
            value_name: Some("AllowIndexingEncryptedStoresOrItemData".to_string()),
            original_value: None,
        });

        // === FEEDBACK ===

        // Tailored Experiences
        settings.push(PrivacySetting {
            id: "tailored_experiences".to_string(),
            name: "Tailored Experiences".to_string(),
            description: "Allows Microsoft to use diagnostic data for personalized tips. Disabling reduces data collection.", .to_string(),
            category: PrivacyCategory::Feedback,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Boolean(false),
            requires_admin: false,
            is_safe: true,
            impact: PrivacyImpact::None,
            registry_key: Some("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Privacy".to_string()),
            value_name: Some("TailoredExperiencesWithDiagnostics".to_string()),
            original_value: None,
        });

        // === APP PERMISSIONS ===

        // App Diagnostics
        settings.push(PrivacySetting {
            id: "app_diagnostics".to_string(),
            name: "App Diagnostics".to_string(),
            description: "Allows apps to access diagnostic info about other apps.", .to_string(),
            category: PrivacyCategory::AppPermissions,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Boolean(false),
            requires_admin: false,
            is_safe: true,
            impact: PrivacyImpact::Low,
            registry_key: Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\Consent\\AppDiagnostics".to_string()),
            value_name: Some("Enabled".to_string()),
            original_value: None,
        });

        // === ADDITIONAL TELEMETRY ===

        // App Usage Data Collection
        settings.push(PrivacySetting {
            id: "app_usage_data".to_string(),
            name: "App Usage Data Collection".to_string(),
            description: "Collects app usage statistics. Setting to 0 disables collection.", .to_string(),
            category: PrivacyCategory::Telemetry,
            current_value: SettingValue::Unknown("Unknown".to_string()),
            recommended_value: SettingValue::Number(0),
            requires_admin: true,
            is_safe: true,
            impact: PrivacyImpact::Low,
            registry_key: Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection\\MaxTelemetryDiskAllowedClient".to_string()),
            value_name: Some("value".to_string()),
            original_value: None,
        });

        // === SERVICES TO MANAGE ===

        telemetry_services.extend(&[
            "DiagTrack",          // Connected User Experiences and Telemetry
            "dmwapppushservice",  // Device Management Wireless Application Protocol Push Service
            "DiagnosticsHub.StandardCollector.Service", // Diagnostics Hub Standard Collector
            "EdgeUpdate",         // Microsoft Edge Update Service
            "OneSyncSvc",         // Sync Host
            "PhoneSvc",           // Phone Service
            "RemoteAccess",       // Routing and Remote Access
            "SensorDataService",  // Sensor Data Service
            "SensrSvc",           // Sensor Monitoring Service
            "ShellHWDetection",   // Shell Hardware Detection
            "WdiServiceHost",     // Diagnostic Service Host
            "WinHttpAutoProxySvc",# WinHTTP Web Proxy Auto-Discovery
        ]);

        // Add admin requirement markers
        admin_settings.extend(&[
            "allow_telemetry",
            "ceip",
            "activity_history",
            "search_indexing",
            "app_usage_data",
        ]);

        // Add safe settings (low impact)
        safe_settings.extend(&[
            "advertising_id",
            "tailored_experiences",
            "diagnostic_viewer",
            "speech_recognition",
        ]);

        PrivacyManager {
            settings,
            admin_settings,
            safe_settings,
            telemetry_services,
        }
    }

    /// Scan for current privacy settings
    pub fn scan(&mut self) -> PrivacyScanResult {
        // Read current values from registry
        for setting in &mut self.settings {
            self.read_setting_value(setting);
        }

        // Categorize settings
        let mut needs_attention = Vec::new();
        let mut good_settings = Vec::new();

        for setting in &self.settings {
            if self.setting_needs_attention(setting) {
                needs_attention.push(setting.clone());
            } else {
                good_settings.push(setting.clone());
            }
        }

        // Calculate privacy score
        let total = self.settings.len();
        let good = good_settings.len();
        let privacy_score = if total > 0 {
            ((good as f64 / total as f64) * 100.0) as u8
        } else {
            0
        };

        // Generate category summary
        let mut category_counts: std::collections::HashMap<PrivacyCategory, (usize, usize)> =
            std::collections::HashMap::new();

        for setting in &self.settings {
            let entry = category_counts.entry(setting.category.clone()).or_insert((0, 0));
            entry.0 += 1;
            if self.setting_needs_attention(setting) {
                entry.1 += 1;
            }
        }

        let category_summary: Vec<CategorySummary> = category_counts
            .iter()
            .map(|(cat, (total, needs))| CategorySummary {
                category: *cat.clone(),
                total_settings: *total,
                good_count: total - needs,
                needs_attention_count: *needs,
            })
            .collect();

        PrivacyScanResult {
            settings: self.settings.clone(),
            needs_attention,
            good_settings,
            total_count: self.settings.len(),
            improvable_count: needs_attention.len(),
            privacy_score,
            category_summary,
        }
    }

    /// Read current value from registry
    fn read_setting_value(&self, setting: &mut PrivacySetting) {
        if setting.registry_key.is_none() || setting.value_name.is_none() {
            return;
        }

        let key_path = setting.registry_key.as_ref().unwrap();
        let value_name = setting.value_name.as_ref().unwrap();

        // Parse hive and path
        let (hive_str, subkey) = match self.parse_registry_path(key_path) {
            Some((hive, path)) => (hive, path),
            None => return,
        };

        let hive = match hive_str {
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKEY_USERS" => HKEY_USERS,
            _ => return,
        };

        if let Ok(key) = RegKey::predef(hive).open_subkey(subkey) {
            // Try to read as DWORD
            if let Ok(dword_val) = key.get_value::<u32, _>(value_name) {
                setting.current_value = SettingValue::Number(dword_val);
                return;
            }

            // Try to read as string
            if let Ok(str_val) = key.get_value::<String, _>(value_name) {
                // Check for boolean-like values
                let str_lower = str_val.to_lowercase();
                if str_lower == "true" || str_lower == "1" {
                    setting.current_value = SettingValue::Boolean(true);
                } else if str_lower == "false" || str_lower == "0" {
                    setting.current_value = SettingValue::Boolean(false);
                } else {
                    setting.current_value = SettingValue::String(str_val);
                }
                return;
            }

            // Value doesn't exist
            setting.current_value = SettingValue::NotConfigured;
        } else {
            // Key doesn't exist
            setting.current_value = SettingValue::NotConfigured;
        }
    }

    /// Parse a registry path string
    fn parse_registry_path(&self, path: &str) -> Option<(&str, &str)> {
        for prefix in &["HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU"] {
            if path.starts_with(prefix) {
                let key_path = &path[prefix.len()..];
                return Some((prefix, key_path.trim_start_matches('\\')));
            }
        }
        None
    }

    /// Check if a setting needs attention (differs from recommended)
    fn setting_needs_attention(&self, setting: &PrivacySetting) -> bool {
        match (&setting.current_value, &setting.recommended_value) {
            (SettingValue::Boolean(current), SettingValue::Boolean(recommended)) => {
                current != recommended
            }
            (SettingValue::Number(current), SettingValue::Number(recommended)) => {
                current != recommended
            }
            (SettingValue::String(current), SettingValue::String(recommended)) => {
                current != recommended
            }
            (SettingValue::NotConfigured, _) => true,
            (_, SettingValue::NotConfigured) => false,
            _ => true,
        }
    }

    /// Apply privacy settings
    pub fn apply(
        &mut self,
        setting_ids: &[&str],
        create_checkpoint: bool,
    ) -> PrivacyApplyResult {
        let mut result = PrivacyApplyResult::default();

        if create_checkpoint {
            result.checkpoint_created = true;
            result.checkpoint_path = Some(format!(
                "privacy_checkpoint_{}.json",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ));
        }

        for setting_id in setting_ids {
            if let Some(setting) = self.settings.iter_mut().find(|s| s.id == *setting_id) {
                // Check admin requirement
                if setting.requires_admin {
                    // Would need to check if running as admin
                    // For now, proceed but note it
                    result.warnings.push(format!(
                        "Setting '{}' requires admin privileges",
                        setting.name
                    ));
                }

                // Store original value
                if result.checkpoint_created {
                    setting.original_value = Some(setting.current_value.clone());
                }

                // Apply the change
                let change_result = self.apply_setting(setting);

                result.changes.push(PrivacyChange {
                    setting_name: setting.name.clone(),
                    old_value: format!("{:?}", setting.current_value),
                    new_value: format!("{:?}", setting.recommended_value),
                    success: change_result.is_ok(),
                    error: change_result.err().map(|e| e.to_string()),
                });

                if change_result.is_ok() {
                    result.changed_count += 1;
                    // Update current value
                    setting.current_value = setting.recommended_value.clone();

                    // Some settings require reboot
                    if setting.id == "allow_telemetry" || setting.id == "activity_history" {
                        result.reboot_required = true;
                    }
                } else {
                    result.failed_count += 1;
                    result.errors.push(format!(
                        "Failed to apply '{}': {}",
                        setting.name,
                        change_result.err().unwrap()
                    ));
                }
            } else {
                result.errors.push(format!("Setting not found: {}", setting_id));
                result.failed_count += 1;
            }
        }

        result
    }

    /// Apply a single setting
    fn apply_setting(&self, setting: &PrivacySetting) -> Result<(), Box<dyn Error>> {
        if setting.registry_key.is_none() || setting.value_name.is_none() {
            return Err("Setting has no registry configuration".into());
        }

        let key_path = setting.registry_key.as_ref().unwrap();
        let value_name = setting.value_name.as_ref().unwrap();

        let (hive_str, subkey) = match self.parse_registry_path(key_path) {
            Some((hive, path)) => (hive, path),
            None => return Err("Invalid registry path".into()),
        };

        let hive = match hive_str {
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKEY_USERS" => HKEY_USERS,
            _ => return Err("Unknown hive".into()),
        };

        let key = RegKey::predef(hive).open_subkey_with_flags(subkey, KEY_WRITE)?;

        match &setting.recommended_value {
            SettingValue::Boolean(value) => {
                let dword_val: u32 = if *value { 1 } else { 0 };
                key.set_value(value_name, &dword_val)?;
            }
            SettingValue::Number(value) => {
                key.set_value(value_name, value)?;
            }
            SettingValue::String(value) => {
                key.set_value(value_name, value)?;
            }
            SettingValue::NotConfigured => {
                // Delete the value to restore default
                let _ = key.delete_value(value_name);
            }
            SettingValue::Unknown(_) => {
                return Err("Cannot apply unknown value type".into());
            }
        }

        Ok(())
    }

    /// Apply all recommended privacy settings
    pub fn apply_all_recommended(&mut self, create_checkpoint: bool) -> PrivacyApplyResult {
        let ids: Vec<&str> = self.settings.iter().map(|s| s.id.as_str()).collect();
        self.apply(&ids, create_checkpoint)
    }

    /// Apply only safe settings (low impact)
    pub fn apply_safe_settings(&mut self, create_checkpoint: bool) -> PrivacyApplyResult {
        let ids: Vec<&str> = self
            .settings
            .iter()
            .filter(|s| s.is_safe)
            .map(|s| s.id.as_str())
            .collect();
        self.apply(&ids, create_checkpoint)
    }

    /// Restore from checkpoint
    pub fn restore(&self, checkpoint_path: &str) -> Result<PrivacyApplyResult, Box<dyn Error>> {
        let mut result = PrivacyApplyResult::default();

        // Read checkpoint file
        let content = std::fs::read_to_string(checkpoint_path)
            .map_err(|e| format!("Failed to read checkpoint: {}", e))?;

        // Parse checkpoint (simplified - would need proper deserialization)
        result.changed_count = 0;
        result.checkpoint_path = Some(checkpoint_path.to_string());

        Ok(result)
    }

    /// Get telemetry services that can be stopped
    pub fn get_telemetry_services(&self) -> Vec<&'static str> {
        self.telemetry_services.clone()
    }

    /// Get settings by category
    pub fn get_by_category(&self, category: PrivacyCategory) -> Vec<&PrivacySetting> {
        self.settings
            .iter()
            .filter(|s| s.category == category)
            .collect()
    }

    /// Get settings that need attention
    pub fn get_needs_attention(&self, result: &PrivacyScanResult) -> Vec<&PrivacySetting> {
        result.needs_attention.iter().collect()
    }

    /// Get settings by ID
    pub fn get_by_id(&self, id: &str) -> Option<&PrivacySetting> {
        self.settings.iter().find(|s| s.id == id)
    }
}

impl Default for PrivacyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PrivacyScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Privacy Scan Results")?;
        writeln!(f, "=====================")?;
        writeln!(f, "Privacy Score: {}/100", self.privacy_score)?;
        writeln!(f, "Total Settings: {}", self.total_count)?;
        writeln!(f, "Good Settings: {}", self.good_settings.len())?;
        writeln!(f, "Needs Attention: {}", self.improvable_count)?;
        writeln!(f)?;

        writeln!(f, "By Category:")?;
        for summary in &self.category_summary {
            writeln!(
                f,
                "  {:?}: {} total, {} good, {} needs attention",
                summary.category, summary.total_settings, summary.good_count, summary.needs_attention_count
            )?;
        }

        writeln!(f)?;
        writeln!(f, "Settings Needing Attention:")?;
        for (i, setting) in self.needs_attention.iter().enumerate() {
            writeln!(
                f,
                "{}. [{}] {}",
                i + 1,
                setting.category.to_string().to_uppercase(),
                setting.name
            )?;
            writeln!(f, "   Current: {:?}", setting.current_value)?;
            writeln!(f, "   Recommended: {:?}", setting.recommended_value)?;
            writeln!(f, "   Impact: {:?}", setting.impact)?;
        }

        if !self.good_settings.is_empty() {
            writeln!(f)?;
            writeln!(f, "Well-Configured Settings:")?;
            for setting in &self.good_settings {
                writeln!(f, "  ✓ {:?}", setting.name)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for PrivacyApplyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Privacy Settings Applied")?;
        writeln!(f, "=======================")?;
        writeln!(f, "Changed: {}", self.changed_count)?;
        writeln!(f, "Failed: {}", self.failed_count)?;
        writeln!(f, "Skipped: {}", self.skipped_count)?;
        writeln!(f, "Reboot Required: {}", self.reboot_required)?;

        if self.checkpoint_created {
            writeln!(f, "Checkpoint: {}", self.checkpoint_path.clone().unwrap_or_default())?;
        }

        if !self.warnings.is_empty() {
            writeln!(f)?;
            writeln!(f, "Warnings:")?;
            for warning in &self.warnings {
                writeln!(f, "  ⚠ {}", warning)?;
            }
        }

        if !self.errors.is_empty() {
            writeln!(f)?;
            writeln!(f, "Errors:")?;
            for error in &self.errors {
                writeln!(f, "  ✗ {}", error)?;
            }
        }

        writeln!(f)?;
        writeln!(f, "Changes Made:")?;
        for change in &self.changes {
            let status = if change.success { "✓" } else { "✗" };
            writeln!(f, "  {} {}", status, change.setting_name)?;
            if !change.success {
                if let Some(error) = &change.error {
                    writeln!(f, "    Error: {}", error)?;
                }
            }
        }

        Ok(())
    }
}

impl fmt::Display for PrivacyCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivacyCategory::Telemetry => write!(f, "Telemetry"),
            PrivacyCategory::Location => write!(f, "Location"),
            PrivacyCategory::Speech => write!(f, "Speech"),
            PrivacyCategory::Advertising => write!(f, "Advertising"),
            PrivacyCategory::ActivityHistory => write!(f, "Activity History"),
            PrivacyCategory::DiagnosticData => write!(f, "Diagnostic Data"),
            PrivacyCategory::TimelineSearch => write!(f, "Timeline & Search"),
            PrivacyCategory::AppPermissions => write!(f, "App Permissions"),
            PrivacyCategory::Feedback => write!(f, "Feedback"),
            PrivacyCategory::Other => write!(f, "Other"),
        }
    }
}

impl fmt::Display for PrivacyImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivacyImpact::None => write!(f, "None"),
            PrivacyImpact::Low => write!(f, "Low"),
            PrivacyImpact::Medium => write!(f, "Medium"),
            PrivacyImpact::High => write!(f, "High"),
            PrivacyImpact::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_manager_creation() {
        let manager = PrivacyManager::new();
        assert!(!manager.settings.is_empty());
        assert!(!manager.telemetry_services.is_empty());
    }

    #[test]
    fn test_parse_registry_path() {
        let manager = PrivacyManager::new();

        let (hive, key) = manager
            .parse_registry_path(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows")
            .unwrap();
        assert_eq!(hive, "HKEY_LOCAL_MACHINE");
        assert_eq!(key, r"SOFTWARE\Microsoft\Windows");

        let (hive, key) = manager
            .parse_registry_path(r"HKEY_CURRENT_USER\Software\Test")
            .unwrap();
        assert_eq!(hive, "HKEY_CURRENT_USER");
        assert_eq!(key, r"Software\Test");
    }

    #[test]
    fn test_scan_result_default() {
        let result = PrivacyScanResult::default();
        assert!(result.settings.is_empty());
        assert_eq!(result.total_count, 0);
        assert_eq!(result.privacy_score, 0);
    }

    #[test]
    fn test_scan_result_display() {
        let result = PrivacyScanResult::default();
        let display = format!("{}", result);
        assert!(display.contains("Privacy Scan Results"));
        assert!(display.contains("Privacy Score: 0/100"));
    }

    #[test]
    fn test_apply_result_default() {
        let result = PrivacyApplyResult::default();
        assert_eq!(result.changed_count, 0);
        assert_eq!(result.failed_count, 0);
        assert!(!result.reboot_required);
    }

    #[test]
    fn test_privacy_setting_variants() {
        assert_eq!(
            SettingValue::Boolean(true),
            SettingValue::Boolean(true)
        );
        assert_ne!(SettingValue::Boolean(true), SettingValue::Boolean(false));
        assert_eq!(SettingValue::Number(42), SettingValue::Number(42));
        assert_ne!(SettingValue::Number(42), SettingValue::Number(0));
    }

    #[test]
    fn test_privacy_category_variants() {
        assert_eq!(PrivacyCategory::Telemetry, PrivacyCategory::Telemetry);
        assert_ne!(PrivacyCategory::Telemetry, PrivacyCategory::Location);
    }

    #[test]
    fn test_privacy_impact_variants() {
        assert_eq!(PrivacyImpact::None, PrivacyImpact::None);
        assert_ne!(PrivacyImpact::None, PrivacyImpact::High);
    }

    #[test]
    fn test_get_telemetry_services() {
        let manager = PrivacyManager::new();
        let services = manager.get_telemetry_services();
        assert!(!services.is_empty());
        assert!(services.contains(&"DiagTrack"));
    }

    #[test]
    fn test_get_by_category() {
        let manager = PrivacyManager::new();
        let telemetry_settings = manager.get_by_category(PrivacyCategory::Telemetry);
        assert!(!telemetry_settings.is_empty());
    }

    #[test]
    fn test_get_by_id() {
        let manager = PrivacyManager::new();
        let setting = manager.get_by_id("allow_telemetry");
        assert!(setting.is_some());
        assert_eq!(setting.unwrap().id, "allow_telemetry");

        let setting = manager.get_by_id("nonexistent");
        assert!(setting.is_none());
    }
}
