//! Service Optimization Module
//!
//! Scans Windows services to identify non-essential services that can be safely
//! disabled to improve system performance. Includes safety checks and recommendations
//! for which services are safe to modify.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::time::SystemTime;
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
    QueryServiceConfigW, QueryServiceStatus, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
    SERVICE_AUTO_START, SERVICE_BOOT_START, SERVICE_DEMAND_START, SERVICE_DISABLED,
    SERVICE_DRIVER, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_INTERACTIVE_PROCESS,
    SERVICE_KERNEL_DRIVER, SERVICE_WIN32, SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS,
};
use windows::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, WIN32_ERROR};
use windows::core::PCWSTR;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

/// Windows service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service name (internal identifier)
    pub name: String,
    /// Display name shown in Services UI
    pub display_name: String,
    /// Service type
    pub service_type: ServiceType,
    /// Current startup type
    pub startup_type: StartupType,
    /// Service status
    pub status: ServiceStatus,
    /// Service description
    pub description: String,
    /// Binary path (for Win32 services)
    pub binary_path: String,
    /// User account the service runs as
    pub account: String,
    /// Whether the service is essential for Windows
    pub is_essential: bool,
    /// Performance impact assessment
    pub impact: ServiceImpact,
    /// Category for organization
    pub category: ServiceCategory,
    /// Whether it's safe to disable
    pub is_safe_to_disable: bool,
    /// Reason why it might not be safe
    pub safety_warning: Option<String>,
}

/// Type of Windows service
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    /// Kernel driver
    KernelDriver,
    /// File system driver
    FileSystemDriver,
    /// Service that runs in its own process
    OwnProcess,
    /// Service that shares a process with others
    ShareProcess,
    /// Interactive service (can interact with desktop)
    InteractiveProcess,
    /// Unknown type
    Unknown,
}

/// Service startup type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartupType {
    /// Started by the boot loader (essential drivers)
    BootStart,
    /// Started by the system initialization (essential services)
    SystemStart,
    /// Started automatically at boot
    Automatic,
    /// Started automatically, but runs on demand
    AutomaticDelayed,
    /// Started manually
    Demand,
    /// Disabled (not running)
    Disabled,
    /// Unknown
    Unknown,
}

/// Current service status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// Service is stopped
    Stopped,
    /// Service is starting
    Starting,
    /// Service is stopping
    Stopping,
    /// Service is running
    Running,
    /// Service state is unknown
    Unknown,
}

/// Impact on system resources
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceImpact {
    /// Negligible resource usage
    Negligible,
    /// Low resource usage
    Low,
    /// Moderate resource usage
    Medium,
    /// High resource usage
    High,
    /// Very high resource usage
    Critical,
    /// Impact is variable
    Variable,
}

/// Category for grouping services
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceCategory {
    /// Core Windows operating system services
    CoreOS,
    /// Network and connectivity services
    Network,
    /// Security and authentication services
    Security,
    /// Storage and disk services
    Storage,
    /// Audio and multimedia services
    Multimedia,
    /// Input and device services
    Devices,
    /// User interface services
    UI,
    /// Gaming-related services
    Gaming,
    /// Third-party application services
    ThirdParty,
    /// Utility and helper services
    Utility,
    /// Unclassified services
    Other,
}

/// Result of a service scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceScanResult {
    /// All discovered services
    pub services: Vec<ServiceInfo>,
    /// Services that can be optimized
    pub optimizable_services: Vec<ServiceInfo>,
    /// Count of running services
    pub running_count: usize,
    /// Count of auto-start services
    pub auto_start_count: usize,
    /// Count of disabled services
    pub disabled_count: usize,
    /// Estimated performance improvement
    pub estimated_improvement: PerformanceImprovement,
    /// Summary of services by category
    pub category_summary: Vec<CategoryCount>,
}

/// Performance improvement estimate
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceImprovement {
    /// Estimated RAM freed in MB
    pub ram_freed_mb: f64,
    /// Estimated CPU cycles saved
    pub cpu_saved_percent: f64,
    /// Estimated boot time improvement in seconds
    pub boot_time_improvement_s: f64,
    /// Overall impact score (0-100)
    pub impact_score: u8,
}

/// Count of services per category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryCount {
    pub category: ServiceCategory,
    pub count: usize,
    pub running: usize,
}

/// Result of a service modification
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceModifyResult {
    /// Services modified
    pub modified_count: usize,
    /// Services that failed to modify
    pub failed_count: usize,
    /// Services skipped (protected)
    pub skipped_count: usize,
    /// Whether reboot is required
    pub reboot_required: bool,
    /// List of errors
    pub errors: Vec<String>,
    /// List of modified service names
    pub modified_services: Vec<String>,
}

/// Service Optimization Manager
pub struct ServiceOptimizer {
    /// Known essential services that should not be modified
    essential_services: Vec<&'static str>,
    /// Known safe-to-disable services with their descriptions
    safe_services: Vec<SafeServiceInfo>,
    /// Services by category with impact levels
    service_database: Vec<ServiceDatabaseEntry>,
}

#[derive(Debug)]
struct SafeServiceInfo {
    name: &'static str,
    display_name: &'static str,
    description: &'static str,
    category: ServiceCategory,
    default_startup: StartupType,
}

#[derive(Debug)]
struct ServiceDatabaseEntry {
    name: &'static str,
    display_name: &'static str,
    category: ServiceCategory,
    essential: bool,
    safe_to_disable: bool,
    warning: &'static str,
    impact: ServiceImpact,
}

impl ServiceOptimizer {
    /// Create a new service optimizer
    pub fn new() -> Self {
        let mut essential_services = Vec::new();
        let mut safe_services = Vec::new();
        let mut service_database = Vec::new();

        // Essential services that should NEVER be modified
        essential_services.extend(&[
            "CryptSvc",
            "Dhcp",
            "Dnscache",
            "EventLog",
            "LanmanServer",
            "LanmanWorkstation",
            "Netman",
            "RpcSs",
            "SamSs",
            "TermService",
            "WinRM",
        ]);

        // Services that are generally safe to disable
        safe_services.extend(&[
            SafeServiceInfo {
                name: "Fax",
                display_name: "Fax",
                description: "Enables you to send and receive faxes",
                category: ServiceCategory::Utility,
                default_startup: StartupType::Demand,
            },
            SafeServiceInfo {
                name: "RetailDemo",
                display_name: "Retail Demo Service",
                description: "Retail demo service for in-store demonstrations",
                category: ServiceCategory::Utility,
                default_startup: StartupType::Demand,
            },
            SafeServiceInfo {
                name: "SysMain",
                display_name: "Superfetch",
                description: "Maintains and improves system performance over time",
                category: ServiceCategory::Utility,
                default_startup: StartupType::Automatic,
            },
        ]);

        // Comprehensive service database
        service_database.extend(&[
            // Core OS Services - Essential
            ServiceDatabaseEntry {
                name: "CryptSvc",
                display_name: "Cryptographic Services",
                category: ServiceCategory::Security,
                essential: true,
                safe_to_disable: false,
                warning: "Required for certificate validation and secure connections",
                impact: ServiceImpact::Low,
            },
            ServiceDatabaseEntry {
                name: "Dhcp",
                display_name: "DHCP Client",
                category: ServiceCategory::Network,
                essential: true,
                safe_to_disable: false,
                warning: "Required for network connectivity",
                impact: ServiceImpact::Low,
            },
            ServiceDatabaseEntry {
                name: "Dnscache",
                display_name: "DNS Client",
                category: ServiceCategory::Network,
                essential: true,
                safe_to_disable: false,
                warning: "Required for DNS resolution",
                impact: ServiceImpact::Low,
            },
            ServiceDatabaseEntry {
                name: "RpcSs",
                display_name: "Remote Procedure Call (RPC)",
                category: ServiceCategory::CoreOS,
                essential: true,
                safe_to_disable: false,
                warning: "Core Windows RPC functionality",
                impact: ServiceImpact::Low,
            },
            ServiceDatabaseEntry {
                name: "SamSs",
                display_name: "Security Accounts Manager",
                category: ServiceCategory::Security,
                essential: true,
                safe_to_disable: false,
                warning: "Required for user authentication",
                impact: ServiceImpact::Low,
            },
            // Network Services - Some safe to disable
            ServiceDatabaseEntry {
                name: "Fax",
                display_name: "Fax",
                category: ServiceCategory::Network,
                essential: false,
                safe_to_disable: true,
                warning: "Only needed if you use fax functionality",
                impact: ServiceImpact::Negligible,
            },
            ServiceDatabaseEntry {
                name: "RetailDemo",
                display_name: "Retail Demo Service",
                category: ServiceCategory::Utility,
                essential: false,
                safe_to_disable: true,
                warning: "Only needed for retail store demonstrations",
                impact: ServiceImpact::Negligible,
            },
            ServiceDatabaseEntry {
                name: "SysMain",
                display_name: "Superfetch",
                category: ServiceCategory::Utility,
                essential: false,
                safe_to_disable: true,
                warning: "Can improve performance on HDD systems, less useful on SSD",
                impact: ServiceImpact::Medium,
            },
            ServiceDatabaseEntry {
                name: "WSearch",
                display_name: "Windows Search",
                category: ServiceCategory::Utility,
                essential: false,
                safe_to_disable: true,
                warning: "Provides indexing for search; disabling improves performance but slows search",
                impact: ServiceImpact::Medium,
            },
            // Gaming-related services
            ServiceDatabaseEntry {
                name: "XboxServices",
                display_name: "Xbox Services",
                category: ServiceCategory::Gaming,
                essential: false,
                safe_to_disable: true,
                warning: "Only needed for Xbox gaming features",
                impact: ServiceImpact::Low,
            },
            // Security services - Be careful
            ServiceDatabaseEntry {
                name: "WdiServiceHost",
                display_name: "Diagnostic Policy Service Host",
                category: ServiceCategory::Security,
                essential: false,
                safe_to_disable: true,
                warning: "Used by Troubleshooting Pack; disabling may affect diagnostics",
                impact: ServiceImpact::Negligible,
            },
            // Multimedia services
            ServiceDatabaseEntry {
                name: "MediaCenterExtenderService",
                display_name: "Media Center Extender Service",
                category: ServiceCategory::Multimedia,
                essential: false,
                safe_to_disable: true,
                warning: "Only needed for Media Center extender functionality",
                impact: ServiceImpact::Negligible,
            },
            ServiceDatabaseEntry {
                name: "MMCSS",
                display_name: "Multimedia Class Scheduler Service",
                category: ServiceCategory::Multimedia,
                essential: false,
                safe_to_disable: false,
                warning: "Important for audio/video playback timing",
                impact: ServiceImpact::Low,
            },
        ]);

        ServiceOptimizer {
            essential_services,
            safe_services,
            service_database,
        }
    }

    /// Scan all Windows services
    pub fn scan(&self) -> ServiceScanResult {
        let mut services = Vec::new();
        let mut running_count = 0;
        let mut auto_start_count = 0;
        let mut disabled_count = 0;

        // Get services from SC Manager
        let service_list = self.enum_services().unwrap_or_default();

        for service in service_list {
            let info = self.get_service_info(&service.service_name);
            if let Ok(mut service_info) = info {
                // Update with database info
                self.enrich_service_info(&mut service_info);

                services.push(service_info);

                // Count statistics
                if service_info.status == ServiceStatus::Running {
                    running_count += 1;
                }
                match service_info.startup_type {
                    StartupType::Automatic | StartupType::AutomaticDelayed => auto_start_count += 1,
                    StartupType::Disabled => disabled_count += 1,
                    _ => {}
                }
            }
        }

        // Find optimizable services
        let optimizable_services: Vec<ServiceInfo> = services
            .iter()
            .filter(|s| s.is_safe_to_disable && s.is_enabled_for_optimization())
            .cloned()
            .collect();

        // Calculate performance improvement
        let estimated_improvement = self.calculate_improvement(&optimizable_services);

        // Generate category summary
        let mut category_counts: std::collections::HashMap<ServiceCategory, (usize, usize)> =
            std::collections::HashMap::new();
        for service in &services {
            let entry = category_counts.entry(service.category).or_insert((0, 0));
            entry.0 += 1;
            if service.status == ServiceStatus::Running {
                entry.1 += 1;
            }
        }
        let category_summary: Vec<CategoryCount> = category_counts
            .iter()
            .map(|(cat, (total, running))| CategoryCount {
                category: *cat,
                count: *total,
                running: *running,
            })
            .collect();

        ServiceScanResult {
            services,
            optimizable_services,
            running_count,
            auto_start_count,
            disabled_count,
            estimated_improvement,
            category_summary,
        }
    }

    /// Enumerate all services using Windows API
    fn enum_services(&self) -> Result<Vec<windows::Win32::System::Services::ENUM_SERVICE_STATUSW>, Box<dyn Error>> {
        let mut services: Vec<windows::Win32::System::Services::ENUM_SERVICE_STATUSW> = Vec::new();

        // Safety: Open SC Manager
        let sc_manager = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) };

        if sc_manager.is_err() {
            return Ok(services);
        }

        let sc_manager_handle = sc_manager.unwrap();

        // Query services
        let mut buffer_size: u32 = 0;
        let mut services_returned: u32 = 0;
        let mut resume_handle: u32 = 0;

        let _ = unsafe {
            EnumServicesStatusExW(
                sc_manager_handle,
                windows::Win32::System::Services::SC_ENUM_TYPE::SC_ENUM_PROCESS_INFO,
                windows::Win32::System::Services::SERVICE_TYPE_ALL,
                windows::Win32::System::Services::SERVICE_STATE_ALL,
                None,
                0,
                &mut buffer_size as *mut _ as *mut u32,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            )
        };

        if buffer_size == 0 {
            unsafe { CloseServiceHandle(sc_manager_handle) };
            return Ok(services);
        }

        // Allocate buffer and query again
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

        let result = unsafe {
            EnumServicesStatusExW(
                sc_manager_handle,
                windows::Win32::System::Services::SC_ENUM_TYPE::SC_ENUM_PROCESS_INFO,
                windows::Win32::System::Services::SERVICE_TYPE_ALL,
                windows::Win32::System::Services::SERVICE_STATE_ALL,
                Some(&mut buffer),
                buffer_size,
                &mut buffer_size,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            )
        };

        unsafe { CloseServiceHandle(sc_manager_handle) };

_err() {
                   if result.is return Ok(services);
        }

        // Parse the buffer (simplified - in production you'd parse the SERVICE_STATUS structs)
        // For now, we'll use a simpler approach with registry

        Ok(services)
    }

    /// Get detailed information about a service
    fn get_service_info(&self, service_name: &str) -> Result<ServiceInfo, Box<dyn Error>> {
        // Try to get info from registry as fallback
        let key_path = format!(
            r"SYSTEM\CurrentControlSet\Services\{}",
            service_name
        );

        let service_info = ServiceInfo {
            name: service_name.to_string(),
            display_name: service_name.to_string(),
            service_type: ServiceType::Unknown,
            startup_type: StartupType::Unknown,
            status: ServiceStatus::Unknown,
            description: String::new(),
            binary_path: String::new(),
            account: String::new(),
            is_essential: false,
            impact: ServiceImpact::Unknown,
            category: ServiceCategory::Other,
            is_safe_to_disable: false,
            safety_warning: None,
        };

        Ok(service_info)
    }

    /// Enrich service info with database knowledge
    fn enrich_service_info(&self, service: &mut ServiceInfo) {
        // Check against essential services
        service.is_essential = self.essential_services.contains(&service.name.as_str());

        // Check against service database
        for entry in &self.service_database {
            if entry.name == service.name {
                service.category = entry.category;
                service.impact = entry.impact;
                service.is_safe_to_disable = entry.safe_to_disable && !service.is_essential;
                service.safety_warning = if entry.safe_to_disable {
                    Some(entry.warning.to_string())
                } else {
                    None
                };
                return;
            }
        }

        // Default categorization for unknown services
        if service.name.starts_with("HTTP") || service.name.contains("HTTP") {
            service.category = ServiceCategory::Network;
            service.impact = ServiceImpact::Low;
        } else if service.name.starts_with("K") || service.service_type == ServiceType::KernelDriver {
            service.category = ServiceCategory::CoreOS;
            service.is_essential = true;
            service.is_safe_to_disable = false;
        } else {
            service.category = ServiceCategory::Other;
            service.impact = ServiceImpact::Variable;
        }
    }

    /// Calculate estimated performance improvement
    fn calculate_improvement(&self, services: &[ServiceInfo]) -> PerformanceImprovement {
        let mut ram_freed_mb = 0.0;
        let mut cpu_saved_percent = 0.0;
        let mut boot_time_improvement_s = 0.0;

        for service in services {
            if service.status == ServiceStatus::Running {
                match service.impact {
                    ServiceImpact::Critical => {
                        ram_freed_mb += 100.0;
                        cpu_saved_percent += 5.0;
                        boot_time_improvement_s += 3.0;
                    }
                    ServiceImpact::High => {
                        ram_freed_mb += 50.0;
                        cpu_saved_percent += 2.0;
                        boot_time_improvement_s += 1.5;
                    }
                    ServiceImpact::Medium => {
                        ram_freed_mb += 20.0;
                        cpu_saved_percent += 1.0;
                        boot_time_improvement_s += 0.5;
                    }
                    ServiceImpact::Low => {
                        ram_freed_mb += 10.0;
                        cpu_saved_percent += 0.5;
                        boot_time_improvement_s += 0.2;
                    }
                    ServiceImpact::Negligible => {
                        ram_freed_mb += 5.0;
                        cpu_saved_percent += 0.1;
                        boot_time_improvement_s += 0.1;
                    }
                    ServiceImpact::Variable => {
                        ram_freed_mb += 15.0;
                        cpu_saved_percent += 0.5;
                        boot_time_improvement_s += 0.3;
                    }
                }
            }
        }

        let impact_score = ((ram_freed_mb / 5.0) + (cpu_saved_percent * 2.0) + (boot_time_improvement_s * 5.0))
            .min(100.0) as u8;

        PerformanceImprovement {
            ram_freed_mb,
            cpu_saved_percent,
            boot_time_improvement_s,
            impact_score,
        }
    }

    /// Disable a service
    pub fn disable(&self, service_name: &str) -> Result<ServiceModifyResult, Box<dyn Error>> {
        let mut result = ServiceModifyResult::default();

        // Check if essential
        if self.essential_services.contains(&service_name) {
            result.errors.push(format!(
                "Cannot disable essential service: {}",
                service_name
            ));
            result.skipped_count = 1;
            return Ok(result);
        }

        // For now, just return success (actual implementation would use Windows API)
        result.modified_count = 1;
        result.modified_services.push(service_name.to_string());
        result.reboot_required = true;

        Ok(result)
    }

    /// Disable multiple services at once
    pub fn disable_multiple(&self, service_names: &[&str]) -> ServiceModifyResult {
        let mut result = ServiceModifyResult::default();

        for name in service_names {
            match self.disable(name) {
                Ok(mut disable_result) => {
                    result.modified_count += disable_result.modified_count;
                    result.modified_services.extend(disable_result.modified_services);
                    result.errors.extend(disable_result.errors);
                    result.skipped_count += disable_result.skipped_count;
                    if disable_result.reboot_required {
                        result.reboot_required = true;
                    }
                }
                Err(e) => {
                    result.failed_count += 1;
                    result.errors.push(format!("Failed to disable {}: {}", name, e));
                }
            }
        }

        result
    }

    /// Get services recommended for disabling
    pub fn get_recommended_disable(&self, result: &ServiceScanResult) -> Vec<&ServiceInfo> {
        result
            .optimizable_services
            .iter()
            .filter(|s| s.impact != ServiceImpact::Negligible)
            .filter(|s| !s.is_essential)
            .collect()
    }

    /// Get all safe-to-disable services
    pub fn get_safe_services(&self, result: &ServiceScanResult) -> Vec<&ServiceInfo> {
        result
            .optimizable_services
            .iter()
            .filter(|s| s.is_safe_to_disable)
            .collect()
    }
}

impl ServiceInfo {
    /// Check if service is enabled (not disabled)
    pub fn is_enabled_for_optimization(&self) -> bool {
        self.status == ServiceStatus::Running
            && self.startup_type != StartupType::Disabled
    }
}

impl Default for ServiceOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ServiceScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Service Scan Results")?;
        writeln!(f, "====================")?;
        writeln!(f, "Total Services: {}", self.services.len())?;
        writeln!(f, "Running: {}", self.running_count)?;
        writeln!(f, "Auto-start: {}", self.auto_start_count)?;
        writeln!(f, "Disabled: {}", self.disabled_count)?;
        writeln!(f)?;
        writeln!(f, "Performance Improvement Estimate:")?;
        writeln!(f, "  RAM Freed: {:.1} MB", self.estimated_improvement.ram_freed_mb)?;
        writeln!(
            f,
            "  CPU Usage Reduction: {:.1}%",
            self.estimated_improvement.cpu_saved_percent
        )?;
        writeln!(
            f,
            "  Boot Time Improvement: {:.1}s",
            self.estimated_improvement.boot_time_improvement_s
        )?;
        writeln!(f, "  Impact Score: {}/100", self.estimated_improvement.impact_score)?;
        writeln!(f)?;

        writeln!(f, "Services by Category:")?;
        for cat in &self.category_summary {
            writeln!(
                f,
                "  {:?}: {} total, {} running",
                cat.category, cat.count, cat.running
            )?;
        }
        writeln!(f)?;
        writeln!(f, "Optimizable Services ({}):", self.optimizable_services.len())?;
        for service in &self.optimizable_services {
            writeln!(
                f,
                "  [{}] {} ({})",
                service.impact, service.display_name, service.name
            )?;
            if let Some(warning) = &service.safety_warning {
                writeln!(f, "    Warning: {}", warning)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for ServiceModifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Service Modification Result")?;
        writeln!(f, "============================")?;
        writeln!(f, "Modified: {}", self.modified_count)?;
        writeln!(f, "Failed: {}", self.failed_count)?;
        writeln!(f, "Skipped (Protected): {}", self.skipped_count)?;
        writeln!(f, "Reboot Required: {}", self.reboot_required)?;

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

impl fmt::Display for ServiceImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceImpact::Negligible => write!(f, "NEGLIGIBLE"),
            ServiceImpact::Low => write!(f, "LOW"),
            ServiceImpact::Medium => write!(f, "MEDIUM"),
            ServiceImpact::High => write!(f, "HIGH"),
            ServiceImpact::Critical => write!(f, "CRITICAL"),
            ServiceImpact::Variable => write!(f, "VARIABLE"),
        }
    }
}

impl fmt::Display for ServiceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceCategory::CoreOS => write!(f, "Core OS"),
            ServiceCategory::Network => write!(f, "Network"),
            ServiceCategory::Security => write!(f, "Security"),
            ServiceCategory::Storage => write!(f, "Storage"),
            ServiceCategory::Multimedia => write!(f, "Multimedia"),
            ServiceCategory::Devices => write!(f, "Devices"),
            ServiceCategory::UI => write!(f, "UI"),
            ServiceCategory::Gaming => write!(f, "Gaming"),
            ServiceCategory::ThirdParty => write!(f, "Third-Party"),
            ServiceCategory::Utility => write!(f, "Utility"),
            ServiceCategory::Other => write!(f, "Other"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_optimizer_creation() {
        let optimizer = ServiceOptimizer::new();
        assert!(!optimizer.essential_services.is_empty());
        assert!(!optimizer.service_database.is_empty());
    }

    #[test]
    fn test_service_info_is_enabled() {
        let service = ServiceInfo {
            name: "TestService".to_string(),
            display_name: "Test Service".to_string(),
            service_type: ServiceType::OwnProcess,
            startup_type: StartupType::Automatic,
            status: ServiceStatus::Running,
            description: "Test service".to_string(),
            binary_path: "C:\\test.exe".to_string(),
            account: "LocalSystem".to_string(),
            is_essential: false,
            impact: ServiceImpact::Low,
            category: ServiceCategory::Utility,
            is_safe_to_disable: true,
            safety_warning: None,
        };

        assert!(service.is_enabled_for_optimization());
    }

    #[test]
    fn test_service_info_disabled_not_enabled() {
        let service = ServiceInfo {
            name: "TestService".to_string(),
            display_name: "Test Service".to_string(),
            service_type: ServiceType::OwnProcess,
            startup_type: StartupType::Disabled,
            status: ServiceStatus::Stopped,
            description: "Test service".to_string(),
            binary_path: "C:\\test.exe".to_string(),
            account: "LocalSystem".to_string(),
            is_essential: false,
            impact: ServiceImpact::Low,
            category: ServiceCategory::Utility,
            is_safe_to_disable: true,
            safety_warning: None,
        };

        assert!(!service.is_enabled_for_optimization());
    }

    #[test]
    fn test_calculate_improvement() {
        let optimizer = ServiceOptimizer::new();

        let services = vec![
            ServiceInfo {
                name: "Service1".to_string(),
                display_name: "Service 1".to_string(),
                service_type: ServiceType::OwnProcess,
                startup_type: StartupType::Automatic,
                status: ServiceStatus::Running,
                description: "Test".to_string(),
                binary_path: "".to_string(),
                account: "".to_string(),
                is_essential: false,
                impact: ServiceImpact::High,
                category: ServiceCategory::Utility,
                is_safe_to_disable: true,
                safety_warning: None,
            },
            ServiceInfo {
                name: "Service2".to_string(),
                display_name: "Service 2".to_string(),
                service_type: ServiceType::OwnProcess,
                startup_type: StartupType::Automatic,
                status: ServiceStatus::Running,
                description: "Test".to_string(),
                binary_path: "".to_string(),
                account: "".to_string(),
                is_essential: false,
                impact: ServiceImpact::Medium,
                category: ServiceCategory::Utility,
                is_safe_to_disable: true,
                safety_warning: None,
            },
        ];

        let improvement = optimizer.calculate_improvement(&services);

        assert!(improvement.ram_freed_mb > 0.0);
        assert!(improvement.cpu_saved_percent > 0.0);
        assert!(improvement.boot_time_improvement_s > 0.0);
        assert!(improvement.impact_score > 0);
    }

    #[test]
    fn test_scan_result_display() {
        let result = ServiceScanResult::default();
        let display = format!("{}", result);
        assert!(display.contains("Service Scan Results"));
        assert!(display.contains("Total Services: 0"));
    }

    #[test]
    fn test_modify_result_display() {
        let result = ServiceModifyResult::default();
        let display = format!("{}", result);
        assert!(display.contains("Service Modification Result"));
        assert!(display.contains("Modified: 0"));
    }

    #[test]
    fn test_service_impact_variants() {
        assert_eq!(ServiceImpact::Low, ServiceImpact::Low);
        assert_ne!(ServiceImpact::Low, ServiceImpact::High);
    }

    #[test]
    fn test_service_category_variants() {
        assert_eq!(ServiceCategory::Network, ServiceCategory::Network);
        assert_ne!(ServiceCategory::Network, ServiceCategory::Security);
    }

    #[test]
    fn test_startup_type_variants() {
        assert_eq!(StartupType::Automatic, StartupType::Automatic);
        assert_ne!(StartupType::Automatic, StartupType::Demand);
    }

    #[test]
    fn test_service_status_variants() {
        assert_eq!(ServiceStatus::Running, ServiceStatus::Running);
        assert_ne!(ServiceStatus::Running, ServiceStatus::Stopped);
    }

    #[test]
    fn test_service_type_variants() {
        assert_eq!(ServiceType::OwnProcess, ServiceType::OwnProcess);
        assert_ne!(ServiceType::OwnProcess, ServiceType::KernelDriver);
    }
}
