//! RigShift v2.0.0 - Complete Windows System Optimization CLI Tool
//!
//! A comprehensive command-line utility for optimizing Windows systems
//! including registry cleaning, startup management, service optimization,
//! large file finding, uninstallation, and privacy protection.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

// Local modules
mod checkpoint;
mod engine;
mod scanner;
mod universal_checkpoint;

// New feature modules
mod registry;
mod startup;
mod services;
mod large_files;
mod uninstaller;
mod privacy;

// Re-export for use in commands
use checkpoint::{Checkpoint, CheckpointManager};
use engine::{Engine, ApplyResult, UndoResult};
use scanner::{FileType, Scanner, ScanResult};

// New feature exports
use registry::{RegistryScanner, RegistryCleaner, RegistryScanResult, RegistryCleanupResult};
use startup::{StartupManager, StartupScanResult, StartupModifyResult};
use services::{ServiceOptimizer, ServiceScanResult, ServiceModifyResult};
use large_files::{LargeFileFinder, LargeFileScanResult, FileCategory};
use uninstaller::{Uninstaller, ProgramScanResult, LeftoverAnalysis};
use privacy::{PrivacyManager, PrivacyScanResult, PrivacyApplyResult};

// Universal checkpoint system
use universal_checkpoint::{
    UniversalCheckpointManager,
    CheckpointType,
    BackupEntry,
    BackupData,
    EntryType,
    CheckpointResult,
    RestoreCheckpointResult,
    CheckpointInfo,
};

/// The main CLI struct parsed by clap
#[derive(Parser)]
#[command(name = "rigshift")]
#[command(author = "RigShift")]
#[command(version = "2.0.0")]
#[command(about = "Complete Windows System Optimization CLI Tool", long_about = None)]
struct Cli {
    /// Enable dry-run mode (no changes are made)
    #[arg(long, global = true)]
    dry_run: bool,

    /// Output results in JSON format
    #[arg(long, global = true)]
    json: bool,

    /// Enable verbose output
    #[arg(long, global = true, short = 'v')]
    verbose: bool,

    /// The command to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available commands for RigShift
#[derive(Subcommand)]
enum Commands {
    /// Scan for issues (run without arguments for full system scan)
    #[command(subcommand)]
    Scan(ScanCommands),

    /// Apply cleanup and optimizations
    #[command(subcommand)]
    Apply(ApplyCommands),

    /// Undo previous operations using checkpoints
    #[command(subcommand)]
    Undo(UndoCommands),

    /// Show system status and checkpoints
    #[command(subcommand)]
    Status(StatusCommands),

    /// Registry cleaning commands
    #[command(subcommand)]
    Registry(RegistryCommands),

    /// Startup manager commands
    #[command(subcommand)]
    Startup(StartupCommands),

    /// Service optimization commands
    #[command(subcommand)]
    Services(ServicesCommands),

    /// Large file finder commands
    #[command(subcommand)]
    LargeFiles(LargeFilesCommands),

    /// Program uninstaller commands
    #[command(subcommand)]
    Uninstall(UninstallCommands),

    /// Privacy and telemetry blocking commands
    #[command(subcommand)]
    Privacy(PrivacyCommands),

    /// Run all optimizations (comprehensive system tune-up)
    #[command(name = "optimize")]
    Optimize {
        /// Include registry cleaning (requires admin)
        #[arg(long)]
        registry: bool,

        /// Include startup optimization
        #[arg(long)]
        startup: bool,

        /// Include service optimization
        #[arg(long)]
        services: bool,

        /// Include privacy blocking
        #[arg(long)]
        privacy: bool,

        /// Create checkpoint before changes
        #[arg(long)]
        checkpoint: bool,
    },
}

/// Scan subcommands
#[derive(Subcommand)]
enum ScanCommands {
    /// Scan for temporary files and browser caches (default behavior)
    Scan,

    /// Scan for registry issues
    Registry {
        /// Include broken uninstallers
        #[arg(long)]
        include_uninstallers: bool,

        /// Include orphaned extensions
        #[arg(long)]
        include_extensions: bool,

        /// Include invalid keys
        #[arg(long)]
        include_invalid_keys: bool,

        /// Enable safe mode (recommended for first scan)
        #[arg(long, default_value = "true")]
        safe_mode: bool,
    },

    /// Scan for startup programs
    Startup,

    /// Scan for services
    Services,

    /// Scan for large files
    LargeFiles {
        /// Minimum file size (e.g., "100MB", "1GB")
        #[arg(short, long, default_value = "100MB")]
        min_size: String,

        /// Drive to scan (default: system drive)
        #[arg(short, long)]
        drive: Option<String>,
    },

    /// Scan for installed programs
    Programs,

    /// Scan for privacy settings
    Privacy,

    /// Run a comprehensive system scan
    All {
        /// Include large file scan
        #[arg(long)]
        large_files: bool,

        /// Include installed programs
        #[arg(long)]
        programs: bool,
    },
}

/// Apply subcommands
#[derive(Subcommand)]
enum ApplyCommands {
    /// Apply cleanup by deleting found files
    Clean {
        /// Clean temp files only
        #[arg(long)]
        temp_only: bool,

        /// Clean browser caches only
        #[arg(long)]
        cache_only: bool,
    },

    /// Apply registry cleanup
    Registry {
        /// Include broken uninstallers
        #[arg(long)]
        include_uninstallers: bool,

        /// Include orphaned extensions
        #[arg(long)]
        include_extensions: bool,

        /// Create checkpoint before changes
        #[arg(long)]
        checkpoint: bool,

        /// Force unsafe operations (not recommended)
        #[arg(long)]
        force: bool,
    },

    /// Disable startup programs
    Startup {
        /// Disable all high-impact programs
        #[arg(long)]
        high_impact: bool,

        /// Disable specific programs by index or name
        #[arg(short, long)]
        disable: Vec<String>,

        /// Create checkpoint before changes
        #[arg(long)]
        checkpoint: bool,
    },

    /// Optimize services
    Services {
        /// Disable safe services only
        #[arg(long)]
        safe_only: bool,

        /// Disable all optimizable services
        #[arg(long)]
        all: bool,

        /// Create checkpoint before changes
        #[arg(long)]
        checkpoint: bool,
    },

    /// Apply privacy settings
    Privacy {
        /// Apply only safe settings (low impact)
        #[arg(long)]
        safe_only: bool,

        /// Apply all recommendations
        #[arg(long)]
        all: bool,

        /// Create checkpoint before changes
        #[arg(long)]
        checkpoint: bool,
    },

    /// Remove large files (requires confirmation)
    LargeFiles {
        /// Delete files without confirmation (dangerous!)
        #[arg(long)]
        force: bool,

        /// Minimum file size to delete
        #[arg(short, long, default_value = "100MB")]
        min_size: String,
    },
}

/// Undo subcommands
#[derive(Subcommand)]
enum UndoCommands {
    /// Undo the last operation
    Last {
        /// Show what would be restored without actually restoring
        #[arg(long)]
        preview: bool,
    },

    /// Undo using a specific checkpoint
    Checkpoint {
        /// Path to checkpoint file
        checkpoint: PathBuf,
    },

    /// List available checkpoints
    List,
}

/// Status subcommands
#[derive(Subcommand)]
enum StatusCommands {
    /// Show overall system status
    System,

    /// Show checkpoint status
    Checkpoints,

    /// Show temp file statistics
    Temp,

    /// Show startup items
    Startup,

    /// Show service status
    Services,

    /// Show privacy status
    Privacy,
}

/// Registry subcommands
#[derive(Subcommand)]
enum RegistryCommands {
    /// Scan for registry issues
    Scan {
        /// Include broken uninstallers
        #[arg(long)]
        include_uninstallers: bool,

        /// Include orphaned extensions
        #[arg(long)]
        include_extensions: bool,

        /// Enable safe mode
        #[arg(long, default_value = "true")]
        safe_mode: bool,
    },

    /// Clean registry issues
    Clean {
        /// Create checkpoint before cleaning
        #[arg(long)]
        checkpoint: bool,

        /// Include specific finding types
        #[arg(long)]
        include_uninstallers: bool,

        #[arg(long)]
        include_extensions: bool,
    },

    /// Show registry backup/recovery options
    Backup,
}

/// Startup subcommands
#[derive(Subcommand)]
enum StartupCommands {
    /// Scan for startup programs
    Scan,

    /// List startup programs
    List,

    /// Disable startup programs
    Disable {
        /// Disable high-impact programs
        #[arg(long)]
        high_impact: bool,

        /// Disable all non-essential programs
        #[arg(long)]
        all: bool,

        /// Program name or index to disable
        #[arg(short, long)]
        program: Vec<String>,
    },

    /// Enable disabled startup programs
    Enable {
        /// Enable specific program
        #[arg(short, long)]
        program: Vec<String>,
    },
}

/// Services subcommands
#[derive(Subcommand)]
enum ServicesCommands {
    /// Scan services
    Scan,

    /// List optimizable services
    List,

    /// Disable services
    Disable {
        /// Disable safe services only
        #[arg(long)]
        safe: bool,

        /// Disable all optimizable services
        #[arg(long)]
        all: bool,

        /// Service name to disable
        #[arg(short, long)]
        service: Vec<String>,
    },

    /// Show service details
    Info {
        /// Service name
        name: String,
    },
}

/// Large Files subcommands
#[derive(Subcommand)]
enum LargeFilesCommands {
    /// Scan for large files
    Scan {
        /// Minimum file size
        #[arg(short, long, default_value = "100MB")]
        min_size: String,

        /// Drive to scan
        #[arg(short, long)]
        drive: Option<String>,

        /// Include video files
        #[arg(long)]
        video: bool,

        /// Include disk images
        #[arg(long)]
        images: bool,

        /// Include archives
        #[arg(long)]
        archives: bool,

        /// Include game files
        #[arg(long)]
        games: bool,
    },

    /// Show largest files
    Largest {
        /// Number of files to show
        #[arg(short, long, default_value = "20")]
        count: usize,
    },

    /// Show oldest files
    Oldest {
        /// Minimum age in days
        #[arg(short, long, default_value = "30")]
        days: usize,
    },
}

/// Uninstall subcommands
#[derive(Subcommand)]
enum UninstallCommands {
    /// List installed programs
    List,

    /// Scan for programs
    Scan,

    /// Analyze leftovers after uninstall
    Leftovers {
        /// Program name to analyze
        program: String,
    },

    /// Remove leftovers
    Clean {
        /// Remove all safe leftovers
        #[arg(long)]
        all: bool,

        /// Remove specific leftovers
        #[arg(short, long)]
        remove: Vec<String>,
    },
}

/// Privacy subcommands
#[derive(Subcommand)]
enum PrivacyCommands {
    /// Scan privacy settings
    Scan,

    /// Show privacy score
    Score,

    /// Apply privacy settings
    Apply {
        /// Apply only safe settings
        #[arg(long)]
        safe: bool,

        /// Apply all recommendations
        #[arg(long)]
        all: bool,

        /// Create checkpoint first
        #[arg(long)]
        checkpoint: bool,
    },

    /// List telemetry services
    Services,
}

/// Format bytes to human-readable string
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format file category
fn format_category(category: &FileCategory) -> String {
    match category {
        FileCategory::Video => "Video".to_string(),
        FileCategory::Audio => "Audio".to_string(),
        FileCategory::DiskImage => "Disk Image".to_string(),
        FileCategory::Archive => "Archive".to_string(),
        FileCategory::Installer => "Installer".to_string(),
        FileCategory::GameFiles => "Game Files".to_string(),
        FileCategory::Database => "Database".to_string(),
        FileCategory::Document => "Document".to_string(),
        FileCategory::Image => "Image".to_string(),
        FileCategory::Other => "Other".to_string(),
    }
}

/// Handle scan commands
fn handle_scan(cli: &Cli, scan_cmd: &ScanCommands, verbose: bool) {
    match scan_cmd {
        ScanCommands::Scan {} => {
            let scanner = Scanner::new();
            let results = scanner.scan();

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&results).unwrap());
            } else {
                println!("\n=== Temporary Files and Cache Scan ===");
                println!("Files found: {}", results.len());
                println!("Total size: {}", format_size(Scanner::calculate_total_size(&results)));

                // Group by type
                let mut by_type: std::collections::HashMap<FileType, usize> = std::collections::HashMap::new();
                for result in &results {
                    *by_type.entry(result.file_type.clone()).or_insert(0) += 1;
                }

                for (file_type, count) in &by_type {
                    println!("  {:?}: {} files", file_type, count);
                }

                if verbose {
                    println!("\nDetailed findings:");
                    for (i, result) in results.iter().enumerate().take(20) {
                        println!("{}. {} ({})", i + 1, result.file_path.display(), format_size(result.file_size));
                    }
                    if results.len() > 20 {
                        println!("... and {} more files", results.len() - 20);
                    }
                }
            }
        }

        ScanCommands::Registry { include_uninstallers, include_extensions, include_invalid_keys, safe_mode } => {
            let mut scanner = RegistryScanner::new()
                .with_safe_mode(*safe_mode)
                .with_broken_uninstallers(*include_uninstallers)
                .with_orphaned_extensions(*include_extensions);

            let result = scanner.scan();

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                println!("\n=== Registry Scan Results ===");
                println!("Invalid Keys: {}", result.invalid_keys);
                println!("Broken Uninstallers: {}", result.broken_uninstallers);
                println!("Orphaned Extensions: {}", result.orphaned_extensions);
                println!("\nDetailed Findings:");
                for (i, finding) in result.findings.iter().enumerate().take(20) {
                    println!("{}. [{}] {}", i + 1, finding.impact.to_string().to_uppercase(), finding.key_path);
                    println!("   {}", finding.description);
                }
            }
        }

        ScanCommands::Startup {} => {
            let manager = StartupManager::new();
            let result = manager.scan();

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                println!("\n=== Startup Programs Scan ===");
                println!("{}", result);
            }
        }

        ScanCommands::Services {} => {
            let optimizer = ServiceOptimizer::new();
            let result = optimizer.scan();

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                println!("\n=== Services Scan ===");
                println!("{}", result);
            }
        }

        ScanCommands::LargeFiles { min_size, drive } => {
            let mut finder = LargeFileFinder::new();
            let _ = finder.with_min_size_str(min_size);

            let scan_path = match drive {
                Some(d) => PathBuf::from(d),
                None => PathBuf::from("C:\\"),
            };

            let result = finder.scan_directory(&scan_path);

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                println!("\n=== Large Files Scan ===");
                println!("{}", result);
            }
        }

        ScanCommands::Programs {} => {
            let uninstaller = Uninstaller::new();
            let result = uninstaller.scan_programs();

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                println!("\n=== Installed Programs ===");
                println!("{}", result);
            }
        }

        ScanCommands::Privacy {} => {
            let mut manager = PrivacyManager::new();
            let result = manager.scan();

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                println!("\n=== Privacy Scan Results ===");
                println!("{}", result);
            }
        }

        ScanCommands::All { large_files, programs } => {
            println!("\n=== Comprehensive System Scan ===\n");

            // Temp files
            let scanner = Scanner::new();
            let temp_results = scanner.scan();
            println!("Temporary Files: {} ({})", temp_results.len(), format_size(Scanner::calculate_total_size(&temp_results)));

            // Registry
            let mut reg_scanner = RegistryScanner::new();
            let reg_result = reg_scanner.scan();
            println!("Registry Issues: {}", reg_result.findings.len());

            // Startup
            let startup_mgr = StartupManager::new();
            let startup_result = startup_mgr.scan();
            println!("Startup Programs: {}", startup_result.enabled_count);

            // Services
            let svc_optimizer = ServiceOptimizer::new();
            let svc_result = svc_optimizer.scan();
            println!("Optimizable Services: {}", svc_result.optimizable_services.len());

            // Privacy
            let mut privacy_mgr = PrivacyManager::new();
            let privacy_result = privacy_mgr.scan();
            println!("Privacy Score: {}/100", privacy_result.privacy_score);

            if *large_files {
                let mut finder = LargeFileFinder::new();
                let _ = finder.with_min_size_str("100MB");
                let lf_result = finder.scan_directory(&PathBuf::from("C:\\"));
                println!("Large Files: {} ({})", lf_result.file_count, format_size(lf_result.total_size_bytes));
            }

            if *programs {
                let uninstaller = Uninstaller::new();
                let prog_result = uninstaller.scan_programs();
                println!("Installed Programs: {}", prog_result.total_count);
            }
        }
    }
}

/// Handle apply commands
fn handle_apply(cli: &Cli, apply_cmd: &ApplyCommands) {
    match apply_cmd {
        ApplyCommands::Clean { temp_only, cache_only } => {
            let mut scanner = Scanner::new();

            if *temp_only {
                scanner = scanner.with_chrome(false).with_edge(false).with_firefox(false);
            }
            if *cache_only {
                scanner = scanner.with_temp(false);
            }

            let results = scanner.scan();

            if cli.dry_run {
                println!("[DRY RUN] Would delete {} files ({})", results.len(), format_size(Scanner::calculate_total_size(&results)));
            } else {
                let mut engine = Engine::new().unwrap();
                engine.set_dry_run(false);
                let result = engine.apply(&results, cli.dry_run);

                println!("\n=== Cleanup Results ===");
                println!("Files deleted: {}", result.files_deleted);
                println!("Files skipped: {}", result.files_skipped);
                println!("Space freed: {}", format_size(result.bytes_freed));

                if let Some(path) = &result.checkpoint_path {
                    println!("Checkpoint: {}", path);
                }

                if result.has_errors() {
                    println!("\nErrors:");
                    for error in &result.errors {
                        println!("  - {}", error);
                    }
                }
            }
        }

        ApplyCommands::Registry { include_uninstallers, include_extensions, checkpoint, force } => {
            let mut scanner = RegistryScanner::new()
                .with_safe_mode(!*force)
                .with_broken_uninstallers(*include_uninstallers)
                .with_orphaned_extensions(*include_extensions);

            let scan_result = scanner.scan();

            if cli.dry_run {
                println!("[DRY RUN] Would clean {} registry issues", scan_result.findings.len());
                for finding in &scan_result.findings {
                    println!("  - {}", finding.key_path);
                }
            } else {
                let cleaner = RegistryCleanup::new();
                let safe_findings: Vec<_> = if *force {
                    scan_result.findings.clone()
                } else {
                    scan_result.findings.iter().filter(|f| f.is_safe).cloned().collect()
                };

                let result = cleaner.clean(&safe_findings, *checkpoint);

                println!("\n=== Registry Cleanup Results ===");
                println!("Keys deleted: {}", result.keys_deleted);
                println!("Keys failed: {}", result.keys_failed);
                println!("Bytes freed (est): {}", result.bytes_freed);

                if let Some(path) = &result.checkpoint_path {
                    println!("Checkpoint: {}", path);
                }
            }
        }

        ApplyCommands::Startup { high_impact, disable, checkpoint } => {
            let manager = StartupManager::new();
            let scan_result = manager.scan();

            let to_disable: Vec<_> = if *high_impact {
                manager.get_high_impact_items(&scan_result)
            } else if !disable.is_empty() {
                // Filter by name
                scan_result.items.iter()
                    .filter(|i| disable.iter().any(|d| i.name.to_lowercase().contains(&d.to_lowercase())))
                    .collect()
            } else {
                Vec::new()
            };

            if cli.dry_run {
                println!("[DRY RUN] Would disable {} startup programs", to_disable.len());
                for item in &to_disable {
                    println!("  - {}", item.name);
                }
            } else {
                let result = manager.disable_multiple(&to_disable, *checkpoint);
                println!("\n=== Startup Modification Results ===");
                println!("Disabled: {}", result.modified_count);
                println!("Failed: {}", result.failed_count);
                println!("Reboot Required: {}", result.reboot_required);
            }
        }

        ApplyCommands::Services { safe, all, checkpoint } => {
            let optimizer = ServiceOptimizer::new();
            let scan_result = optimizer.scan();

            let to_disable = if *all {
                optimizer.get_recommended_disable(&scan_result)
            } else if *safe {
                optimizer.get_safe_services(&scan_result)
            } else {
                Vec::new()
            };

            if cli.dry_run {
                println!("[DRY RUN] Would disable {} services", to_disable.len());
                for svc in &to_disable {
                    println!("  - {}", svc.display_name);
                }
            } else {
                let names: Vec<&str> = to_disable.iter().map(|s| s.name.as_str()).collect();
                let result = optimizer.disable_multiple(&names);
                println!("\n=== Service Modification Results ===");
                println!("Disabled: {}", result.modified_count);
                println!("Failed: {}", result.failed_count);
                println!("Reboot Required: {}", result.reboot_required);
            }
        }

        ApplyCommands::Privacy { safe_only, all, checkpoint } => {
            let mut manager = PrivacyManager::new();
            let scan_result = manager.scan();

            if cli.dry_run {
                let to_apply = if *all {
                    scan_result.needs_attention.clone()
                } else if *safe_only {
                    scan_result.needs_attention.iter()
                        .filter(|s| s.impact == privacy::PrivacyImpact::None || s.impact == privacy::PrivacyImpact::Low)
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                };
                println!("[DRY RUN] Would apply {} privacy settings", to_apply.len());
            } else {
                let result = if *all {
                    manager.apply_all_recommended(*checkpoint)
                } else if *safe_only {
                    manager.apply_safe_settings(*checkpoint)
                } else {
                    PrivacyApplyResult::default()
                };

                println!("\n=== Privacy Settings Applied ===");
                println!("Changed: {}", result.changed_count);
                println!("Failed: {}", result.failed_count);
                println!("Reboot Required: {}", result.reboot_required);
            }
        }

        ApplyCommands::LargeFiles { force, min_size } => {
            if !*force {
                println!("This command requires --force to delete files. Use --dry-run to preview first.");
                return;
            }

            let mut finder = LargeFileFinder::new();
            let _ = finder.with_min_size_str(min_size);

            let result = finder.scan_directory(&PathBuf::from("C:\\"));

            println!("\n=== Large Files Deletion ===");
            println!("Found {} large files", result.files.len());

            if cli.dry_run {
                println!("[DRY RUN] Would delete {} files", result.files.len());
            } else {
                let mut deleted = 0;
                let mut failed = 0;
                for file in &result.files {
                    match std::fs::remove_file(&file.path) {
                        Ok(()) => deleted += 1,
                        Err(_) => failed += 1,
                    }
                }
                println!("Deleted: {}", deleted);
                println!("Failed: {}", failed);
            }
        }
    }
}

/// Handle undo commands
fn handle_undo(undo_cmd: &UndoCommands) {
    match undo_cmd {
        UndoCommands::Last { preview } => {
            let mut manager = CheckpointManager::new().unwrap();

            match manager.get_latest_checkpoint() {
                Ok(Some(path)) => {
                    let checkpoint = manager.load(&path).unwrap();

                    if *preview {
                        println!("Would restore from: {}", path.display());
                        println!("Files to restore: {}", checkpoint.len());
                        println!("Total size: {}", format_size(checkpoint.total_size()));
                    } else {
                        let result = manager.restore(&checkpoint, false);
                        println!("Restored {} files ({} bytes)", result.files_restored, result.size_restored);
                    }
                }
                Ok(None) => {
                    println!("No checkpoints found");
                }
                Err(e) => {
                    println!("Error: {}", e);
                }
            }
        }

        UndoCommands::Checkpoint { checkpoint } => {
            let mut manager = CheckpointManager::new().unwrap();
            let result = manager.restore_file(checkpoint, false);

            match result {
                Ok(r) => {
                    println!("Restored {} files", r.files_restored);
                }
                Err(e) => {
                    println!("Error restoring: {}", e);
                }
            }
        }

        UndoCommands::List => {
            let manager = CheckpointManager::new().unwrap();
            match manager.list_checkpoints() {
                Ok(checkpoints) => {
                    if checkpoints.is_empty() {
                        println!("No checkpoints found");
                    } else {
                        println!("Available checkpoints:");
                        for (i, cp) in checkpoints.iter().enumerate() {
                            println!("{}. {}", i + 1, cp.display());
                        }
                    }
                }
                Err(e) => {
                    println!("Error listing checkpoints: {}", e);
                }
            }
        }
    }
}

/// Handle status commands
fn handle_status(status_cmd: &StatusCommands) {
    match status_cmd {
        StatusCommands::System {} => {
            let mut engine = Engine::new().unwrap();
            let status = engine.status();

            println!("\n=== System Status ===");
            println!("Temp directory exists: {}", status.system_info.temp_dir_exists);
            if status.system_info.temp_dir_exists {
                println!("Temp files count: {}", status.system_info.temp_files_count);
            }
            println!("Chrome cache exists: {}", status.system_info.chrome_cache_exists);
            println!("Edge cache exists: {}", status.system_info.edge_cache_exists);
            println!("Firefox cache exists: {}", status.system_info.firefox_cache_exists);

            println!("\nCheckpoints:");
            println!("  Available: {}", status.available_checkpoints);
            if let Some(cp) = &status.last_checkpoint {
                println!("  Latest: {}", cp.path);
                println!("  Created: {}", cp.created_at);
                println!("  Files: {}", cp.file_count);
            }
        }

        StatusCommands::Checkpoints {} => {
            let manager = CheckpointManager::new().unwrap();
            match manager.list_checkpoints() {
                Ok(checkpoints) => {
                    println!("\n=== Checkpoints ===");
                    println!("Total: {}", checkpoints.len());

                    for cp in checkpoints {
                        if let Ok(loaded) = manager.load(&cp) {
                            println!("\n{}", cp.display());
                            println!("  Files: {}", loaded.len());
                            println!("  Size: {}", format_size(loaded.total_size()));
                            println!("  Description: {}", loaded.description);
                        }
                    }
                }
                Err(e) => {
                    println!("Error: {}", e);
                }
            }
        }

        StatusCommands::Temp {} => {
            let scanner = Scanner::new();
            let results = scanner.scan();

            println!("\n=== Temporary Files Status ===");
            println!("Total files: {}", results.len());
            println!("Total size: {}", format_size(Scanner::calculate_total_size(&results)));
        }

        StatusCommands::Startup {} => {
            let manager = StartupManager::new();
            let result = manager.scan();

            println!("\n=== Startup Status ===");
            println!("Total items: {}", result.total_count);
            println!("Enabled: {}", result.enabled_count);
            println!("Estimated boot impact: {}", result.estimated_impact);
        }

        StatusCommands::Services {} => {
            let optimizer = ServiceOptimizer::new();
            let result = optimizer.scan();

            println!("\n=== Services Status ===");
            println!("Total services: {}", result.services.len());
            println!("Running: {}", result.running_count);
            println!("Optimizable: {}", result.optimizable_services.len());
        }

        StatusCommands::Privacy {} => {
            let mut manager = PrivacyManager::new();
            let result = manager.scan();

            println!("\n=== Privacy Status ===");
            println!("Privacy score: {}/100", result.privacy_score);
            println!("Risk level: {:?}", result.risk_level);
            println!("Settings needing attention: {}", result.improvable_count);
        }
    }
}

/// Handle registry commands
fn handle_registry(cli: &Cli, cmd: &RegistryCommands) {
    match cmd {
        RegistryCommands::Scan { include_uninstallers, include_extensions, safe_mode } => {
            let mut scanner = RegistryScanner::new()
                .with_safe_mode(*safe_mode)
                .with_broken_uninstallers(*include_uninstallers)
                .with_orphaned_extensions(*include_extensions);

            let result = scanner.scan();
            println!("\n=== Registry Scan ===");
            println!("{}", result);
        }

        RegistryCommands::Clean { checkpoint, include_uninstallers, include_extensions } => {
            let scanner = RegistryScanner::new();
            let scan_result = scanner.scan();

            let cleaner = RegistryCleanup::new();
            let result = cleaner.clean(&scan_result.findings, *checkpoint);

            println!("\n=== Registry Cleanup ===");
            println!("{}", result);
        }

        RegistryCommands::Backup => {
            println!("Registry backup is automatically created as checkpoints before cleanup operations.");
            println!("Use 'rigshift undo list' to see available restore points.");
        }
    }
}

/// Handle startup commands
fn handle_startup(cli: &Cli, cmd: &StartupCommands) {
    match cmd {
        StartupCommands::Scan {} | StartupCommands::List {} => {
            let manager = StartupManager::new();
            let result = manager.scan();
            println!("\n=== Startup Programs ===");
            println!("{}", result);
        }

        StartupCommands::Disable { high_impact, all, program } => {
            let manager = StartupManager::new();
            let scan_result = manager.scan();

            let to_disable: Vec<&startup::StartupItem> = if *high_impact {
                manager.get_high_impact_items(&scan_result)
            } else if !program.is_empty() {
                scan_result.items.iter()
                    .filter(|i| program.iter().any(|p| i.name.to_lowercase().contains(&p.to_lowercase())))
                    .collect()
            } else if *all {
                scan_result.items.iter().filter(|i| i.is_enabled).collect()
            } else {
                Vec::new()
            };

            if cli.dry_run {
                println!("[DRY RUN] Would disable {} programs", to_disable.len());
            } else {
                let result = manager.disable_multiple(&to_disable, true);
                println!("\n=== Disable Startup Items ===");
                println!("{}", result);
            }
        }

        StartupCommands::Enable { program: _ } => {
            println!("Enable functionality requires checkpoint restoration. Use 'rigshift undo' to restore.");
        }
    }
}

/// Handle services commands
fn handle_services(cli: &Cli, cmd: &ServicesCommands) {
    match cmd {
        ServicesCommands::Scan {} | ServicesCommands::List {} => {
            let optimizer = ServiceOptimizer::new();
            let result = optimizer.scan();
            println!("\n=== Services Scan ===");
            println!("{}", result);
        }

        ServicesCommands::Disable { safe, all, service } => {
            let optimizer = ServiceOptimizer::new();
            let scan_result = optimizer.scan();

            let to_disable: Vec<&services::ServiceInfo> = if *safe {
                optimizer.get_safe_services(&scan_result)
            } else if *all {
                optimizer.get_recommended_disable(&scan_result)
            } else if !service.is_empty() {
                scan_result.services.iter()
                    .filter(|i| service.iter().any(|s| i.name.to_lowercase().contains(&s.to_lowercase())))
                    .collect()
            } else {
                Vec::new()
            };

            if cli.dry_run {
                println!("[DRY RUN] Would disable {} services", to_disable.len());
            } else {
                let names: Vec<&str> = to_disable.iter().map(|s| s.name.as_str()).collect();
                let result = optimizer.disable_multiple(&names);
                println!("\n=== Disable Services ===");
                println!("{}", result);
            }
        }

        ServicesCommands::Info { name } => {
            let optimizer = ServiceOptimizer::new();
            let scan_result = optimizer.scan();

            if let Some(svc) = scan_result.services.iter().find(|s| s.name.to_lowercase() == name.to_lowercase()) {
                println!("\n=== Service Info: {} ===", svc.name);
                println!("Display Name: {}", svc.display_name);
                println!("Description: {}", svc.description);
                println!("Status: {:?}", svc.status);
                println!("Startup Type: {:?}", svc.startup_type);
                println!("Safety Level: {:?}", svc.safety_level);
                println!("Impact: {:?}", svc.impact);
            } else {
                println!("Service not found: {}", name);
            }
        }
    }
}

/// Handle large files commands
fn handle_large_files(cli: &Cli, cmd: &LargeFilesCommands) {
    match cmd {
        LargeFilesCommands::Scan { min_size, drive, video, images, archives, games } => {
            let mut finder = LargeFileFinder::new();
            let _ = finder.with_min_size_str(min_size);

            let scan_path = match drive {
                Some(d) => PathBuf::from(d),
                None => PathBuf::from("C:\\"),
            };

            let result = finder.scan_directory(&scan_path);

            println!("\n=== Large Files Scan ===");
            println!("{}", result);
        }

        LargeFilesCommands::Largest { count } => {
            let mut finder = LargeFileFinder::new();
            let _ = finder.with_min_size_str("1MB");

            let result = finder.scan_directory(&PathBuf::from("C:\\"));
            let largest = finder.get_largest(&result, *count);

            println!("\n=== Largest Files ===");
            for (i, file) in largest.iter().enumerate() {
                println!("{}. {} - {} ({})", i + 1, file.name, file.size_formatted, file.path.display());
            }
        }

        LargeFilesCommands::Oldest { days } => {
            let mut finder = LargeFileFinder::new();
            let _ = finder.with_min_size_str("1MB");

            let result = finder.scan_directory(&PathBuf::from("C:\\"));
            let oldest = finder.get_oldest(&result, *days);

            println!("\n=== Oldest Files (>{} days) ===", days);
            for (i, file) in oldest.iter().enumerate() {
                println!("{}. {} - {} ({} days old)", i + 1, file.name, file.size_formatted, file.age_days);
            }
        }
    }
}

/// Handle uninstall commands
fn handle_uninstall(cli: &Cli, cmd: &UninstallCommands) {
    match cmd {
        UninstallCommands::List {} | UninstallCommands::Scan {} => {
            let uninstaller = Uninstaller::new();
            let result = uninstaller.scan_programs();
            println!("\n=== Installed Programs ===");
            println!("{}", result);
        }

        UninstallCommands::Leftovers { program } => {
            let uninstaller = Uninstaller::new();
            let scan_result = uninstaller.scan_programs();

            if let Some(pg) = scan_result.programs.iter().find(|p| p.display_name.to_lowercase().contains(&program.to_lowercase())) {
                let leftovers = uninstaller.analyze_leftovers(pg);
                println!("\n=== Leftovers for: {} ===", pg.display_name);
                println!("{}", leftovers);
            } else {
                println!("Program not found: {}", program);
            }
        }

        UninstallCommands::Clean { all, remove:
