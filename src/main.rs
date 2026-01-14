//! RigShift v1.0.0 - Windows System Optimization CLI Tool
//!
//! A command-line utility for scanning and cleaning temporary files
//! and browser caches on Windows systems.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

use crate::engine::Engine;
use crate::scanner::{FileType, Scanner};

/// The main CLI struct parsed by clap
#[derive(Parser)]
#[command(name = "rigshift")]
#[command(author = "RigShift")]
#[command(version = "1.0.0")]
#[command(about = "Windows system optimization CLI tool", long_about = None)]
struct Cli {
    /// Enable dry-run mode (no changes are made)
    #[arg(long, global = true)]
    dry_run: bool,

    /// Output results in JSON format
    #[arg(long, global = true)]
    json: bool,

    /// The command to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available commands for RigShift
#[derive(Subcommand)]
enum Commands {
    /// Scan for temporary files and browser caches
    Scan,

    /// Apply cleanup by deleting found files
    Apply,

    /// Undo the last cleanup operation
    Undo,

    /// Show system status and checkpoint information
    Status,
}

/// Formats a file size in human-readable format
fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size >= GB {
        format!("{:.2} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else {
        format!("{} B", size)
    }
}

/// Formats a category name for display
fn format_category(category: &FileType) -> String {
    match category {
        FileType::Temp => "Temporary Files".to_string(),
        FileType::ChromeCache => "Chrome Cache".to_string(),
        FileType::EdgeCache => "Edge Cache".to_string(),
        FileType::FirefoxCache => "Firefox Cache".to_string(),
    }
}

/// Escapes a string for JSON output
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c => result.push(c),
        }
    }
    result
}

/// Handles the scan command
fn handle_scan(scanner: &Scanner, _dry_run: bool, json: bool) {
    let scan_result = scanner.scan();

    if json {
        let mut lines: Vec<String> = Vec::new();
        lines.push("{".to_string());
        lines.push("  \"command\": \"scan\",".to_string());
        lines.push("  \"success\": true,".to_string());
        lines.push(format!("  \"file_count\": {},", scan_result.len()));

        let total_size = Scanner::calculate_total_size(&scan_result);
        lines.push(format!("  \"total_size\": {},", total_size));
        lines.push(format!(
            "  \"total_size_human\": \"{}\",",
            format_size(total_size).replace('"', "\\\"")
        ));
        lines.push("  \"files\": [".to_string());

        for (i, file) in scan_result.iter().enumerate() {
            lines.push("    {".to_string());
            lines.push(format!(
                "      \"path\": \"{}\",",
                escape_json_string(&file.file_path.to_string_lossy())
            ));
            lines.push(format!("      \"size\": {},", file.file_size));
            lines.push(format!(
                "      \"size_human\": \"{}\",",
                format_size(file.file_size).replace('"', "\\\"")
            ));
            lines.push(format!(
                "      \"category\": \"{}\"",
                escape_json_string(&format_category(&file.file_type))
            ));
            lines.push("    }".to_string());
            if i < scan_result.len() - 1 {
                lines.last_mut().unwrap().push(',');
            }
        }

        lines.push("  ]".to_string());
        lines.push("}".to_string());

        for line in &lines {
            println!("{}", line);
        }
    } else {
        println!("=== RigShift Scan Results ===");
        println!();

        if scan_result.is_empty() {
            println!("No cleanable files found.");
            return;
        }

        let total_size = Scanner::calculate_total_size(&scan_result);
        println!(
            "Found {} file(s) totaling {}",
            scan_result.len(),
            format_size(total_size)
        );
        println!();

        let mut categories: Vec<(FileType, Vec<&crate::scanner::ScanResult>)> = Vec::new();
        for file in &scan_result {
            if let Some(existing) = categories
                .iter_mut()
                .find(|(cat, _)| *cat == file.file_type)
            {
                existing.1.push(file);
            } else {
                categories.push((file.file_type.clone(), vec![file]));
            }
        }

        for (category, files) in categories {
            let cat_size: u64 = files.iter().map(|f| f.file_size).sum();
            println!("  [{}]", format_category(&category));
            println!("    Files: {}", files.len());
            println!("    Total: {}", format_size(cat_size));
            println!();
        }

        println!("Run 'rigshift apply' to delete these files.");
    }
}

/// Handles the apply command
fn handle_apply(scanner: &Scanner, engine: &mut Engine, dry_run: bool, json: bool) {
    let scan_result = scanner.scan();

    if json {
        let mut lines: Vec<String> = Vec::new();
        lines.push("{".to_string());
        lines.push("  \"command\": \"apply\",".to_string());

        if scan_result.is_empty() {
            lines.push("  \"success\": true,".to_string());
            lines.push("  \"message\": \"No files to clean\",".to_string());
            lines.push("  \"files_scanned\": 0,".to_string());
            lines.push("  \"files_deleted\": 0,".to_string());
            lines.push("  \"files_skipped\": 0,".to_string());
            lines.push("  \"bytes_freed\": 0,".to_string());
            lines.push("  \"bytes_freed_human\": \"0 B\"".to_string());
            lines.push("}".to_string());

            for line in &lines {
                println!("{}", line);
            }
            return;
        }

        let result = engine.apply(&scan_result, dry_run);

        let message = if dry_run {
            format!("[DRY-RUN] Would delete {} files", result.files_deleted)
        } else {
            format!("Deleted {} files", result.files_deleted)
        };

        lines.push(format!("  \"success\": {},", !result.has_errors()));
        lines.push(format!(
            "  \"message\": \"{}\",",
            escape_json_string(&message)
        ));
        lines.push(format!("  \"files_scanned\": {},", scan_result.len()));
        lines.push(format!("  \"files_deleted\": {},", result.files_deleted));
        lines.push(format!("  \"files_skipped\": {},", result.files_skipped));
        lines.push(format!("  \"bytes_freed\": {},", result.bytes_freed));
        lines.push(format!(
            "  \"bytes_freed_human\": \"{}\"",
            format_size(result.bytes_freed).replace('"', "\\\"")
        ));
        lines.push("}".to_string());

        for line in &lines {
            println!("{}", line);
        }
    } else {
        println!("=== RigShift Apply ===");
        println!();

        if scan_result.is_empty() {
            println!("No cleanable files found.");
            return;
        }

        let total_size = Scanner::calculate_total_size(&scan_result);
        println!("Scanning for files...");
        println!(
            "Found {} file(s) totaling {}",
            scan_result.len(),
            format_size(total_size)
        );
        println!();

        if dry_run {
            println!("[DRY-RUN MODE]");
            println!("The following actions would be performed:");
            println!();

            for file in &scan_result {
                println!("  Delete: {}", file.file_path.display());
            }

            println!();
            println!("Total: {} would be freed", format_size(total_size));
        } else {
            println!("Applying cleanup...");

            let result = engine.apply(&scan_result, false);

            if result.files_deleted > 0 {
                println!("Successfully deleted {} file(s)", result.files_deleted);
                println!("Freed {}", format_size(result.bytes_freed));
            }

            if result.files_skipped > 0 {
                println!("Skipped {} file(s)", result.files_skipped);
            }

            if !result.errors.is_empty() {
                println!();
                println!("Errors:");
                for error in &result.errors {
                    println!("  - {}", error);
                }
            }

            if let Some(ref checkpoint_path) = result.checkpoint_path {
                println!();
                println!("Checkpoint saved for undo operation.");
                println!("Checkpoint path: {}", checkpoint_path);
            }
        }
    }
}

/// Handles the undo command
fn handle_undo(engine: &mut Engine, dry_run: bool, json: bool) {
    let checkpoint_result = engine.get_latest_checkpoint();

    if json {
        let mut lines: Vec<String> = Vec::new();
        lines.push("{".to_string());
        lines.push("  \"command\": \"undo\",".to_string());

        let checkpoint_path: Option<PathBuf> = match checkpoint_result {
            Ok(Some(p)) => Some(p),
            _ => None,
        };

        if checkpoint_path.is_none() {
            lines.push("  \"success\": true,".to_string());
            lines.push("  \"message\": \"No checkpoints found\",".to_string());
            lines.push("  \"files_restored\": 0,".to_string());
            lines.push("  \"bytes_restored\": 0,".to_string());
            lines.push("  \"bytes_restored_human\": \"0 B\"".to_string());
            lines.push("}".to_string());

            for line in &lines {
                println!("{}", line);
            }
            return;
        }

        let result = if dry_run {
            let cp = engine
                .checkpoint_manager()
                .load(checkpoint_path.as_ref().unwrap());
            match cp {
                Ok(checkpoint_data) => crate::engine::UndoResult {
                    files_restored: checkpoint_data.len(),
                    bytes_restored: checkpoint_data.total_size(),
                    checkpoint_path: checkpoint_path.unwrap().to_string_lossy().to_string(),
                    errors: Vec::new(),
                },
                Err(_) => crate::engine::UndoResult::new(),
            }
        } else {
            engine.undo(checkpoint_path.as_ref().map(|p| p.as_path()), false)
        };

        let message = if dry_run {
            format!("[DRY-RUN] Would restore {} files", result.files_restored)
        } else {
            format!("Restored {} file(s)", result.files_restored)
        };

        lines.push(format!("  \"success\": {},", !result.has_errors()));
        lines.push(format!(
            "  \"message\": \"{}\",",
            escape_json_string(&message)
        ));
        lines.push(format!("  \"files_restored\": {},", result.files_restored));
        lines.push(format!("  \"bytes_restored\": {},", result.bytes_restored));
        lines.push(format!(
            "  \"bytes_restored_human\": \"{}\"",
            format_size(result.bytes_restored).replace('"', "\\\"")
        ));
        lines.push("}".to_string());

        for line in &lines {
            println!("{}", line);
        }
    } else {
        println!("=== RigShift Undo ===");
        println!();

        let checkpoint_path: Option<PathBuf> = match engine.get_latest_checkpoint() {
            Ok(Some(p)) => Some(p),
            _ => {
                println!("No checkpoints found. Nothing to undo.");
                return;
            }
        };

        if dry_run {
            println!("[DRY-RUN MODE]");
            println!("The following actions would be performed:");
            println!();

            let cp = engine
                .checkpoint_manager()
                .load(checkpoint_path.as_ref().unwrap());
            match cp {
                Ok(checkpoint_data) => {
                    println!("  Restore {} file(s)", checkpoint_data.len());
                    println!(
                        "  Total size: {}",
                        format_size(checkpoint_data.total_size())
                    );
                    println!();
                    println!("Files to restore:");
                    for entry in &checkpoint_data.entries {
                        println!("  {}", entry.path.display());
                    }
                }
                Err(e) => {
                    println!("  Failed to load checkpoint: {}", e);
                }
            }
        } else {
            println!("Restoring files from checkpoint...");

            let result = engine.undo(checkpoint_path.as_ref().map(|p| p.as_path()), false);

            if result.files_restored > 0 {
                println!("Successfully restored {} file(s)", result.files_restored);
            }

            if result.has_errors() {
                println!();
                println!("Errors:");
                for error in &result.errors {
                    println!("  - {}", error);
                }
            }
        }
    }
}

/// Handles the status command
fn handle_status(engine: &mut Engine, json: bool) {
    let status = engine.status();

    if json {
        let mut lines: Vec<String> = Vec::new();
        lines.push("{".to_string());
        lines.push("  \"command\": \"status\",".to_string());
        lines.push("  \"success\": true,".to_string());
        lines.push("  \"system_info\": {".to_string());
        lines.push(format!(
            "    \"temp_directory_exists\": {},",
            status.system_info.temp_dir_exists
        ));
        lines.push(format!(
            "    \"temp_files_count\": {},",
            status.system_info.temp_files_count
        ));
        lines.push(format!(
            "    \"chrome_cache_exists\": {},",
            status.system_info.chrome_cache_exists
        ));
        lines.push(format!(
            "    \"edge_cache_exists\": {},",
            status.system_info.edge_cache_exists
        ));
        lines.push(format!(
            "    \"firefox_cache_exists\": {}",
            status.system_info.firefox_cache_exists
        ));
        lines.push("  },".to_string());
        lines.push("  \"checkpoints\": {".to_string());

        if let Some(ref cp) = status.last_checkpoint {
            lines.push(format!(
                "    \"available\": {},",
                status.available_checkpoints
            ));
            lines.push("    \"latest\": {".to_string());
            lines.push(format!(
                "      \"path\": \"{}\"",
                escape_json_string(&cp.path)
            ));
            lines.push("    }".to_string());
        } else {
            lines.push(format!(
                "    \"available\": {},",
                status.available_checkpoints
            ));
            lines.push("    \"latest\": null".to_string());
        }

        lines.push("  }".to_string());
        lines.push("}".to_string());

        for line in &lines {
            println!("{}", line);
        }
    } else {
        println!("=== RigShift Status ===");
        println!();

        println!("System Information:");
        println!(
            "  Temp Directory: {}",
            if status.system_info.temp_dir_exists {
                "Found"
            } else {
                "Not Found"
            }
        );
        println!(
            "  Chrome Cache:   {}",
            if status.system_info.chrome_cache_exists {
                "Found"
            } else {
                "Not Found"
            }
        );
        println!(
            "  Edge Cache:     {}",
            if status.system_info.edge_cache_exists {
                "Found"
            } else {
                "Not Found"
            }
        );
        println!(
            "  Firefox Cache:  {}",
            if status.system_info.firefox_cache_exists {
                "Found"
            } else {
                "Not Found"
            }
        );
        println!();

        println!("Checkpoints:");
        println!("  Available: {}", status.available_checkpoints);

        if let Some(cp) = status.last_checkpoint {
            println!();
            println!("Latest Checkpoint:");
            println!("  Path:        {}", cp.path);
            println!("  Files:       {}", cp.file_count);
            println!("  Total Size:  {}", format_size(cp.total_size));
            println!("  Description: {}", cp.description);
        } else {
            println!("  No checkpoints available.");
        }
    }
}

/// Main entry point
fn main() {
    let cli = Cli::parse();
    let scanner = Scanner::new();

    let mut engine = match Engine::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error initializing engine: {}", e);
            if cli.json {
                println!("{{");
                println!("  \"success\": false,");
                println!("  \"error\": \"{}\"", escape_json_string(&e.to_string()));
                println!("}}");
            }
            process::exit(1);
        }
    };

    engine.set_dry_run(cli.dry_run);

    match &cli.command {
        Commands::Scan => handle_scan(&scanner, cli.dry_run, cli.json),
        Commands::Apply => handle_apply(&scanner, &mut engine, cli.dry_run, cli.json),
        Commands::Undo => handle_undo(&mut engine, cli.dry_run, cli.json),
        Commands::Status => handle_status(&mut engine, cli.json),
    }
}

// Module declarations
mod checkpoint;
mod engine;
mod scanner;
