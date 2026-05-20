use clap::{Parser, Subcommand};
use std::path::Path;
use colored::*;
use aegis::engine::{Engine, generate_sarif};
use aegis::rule::{self, RuleConfig};

#[derive(Parser)]
#[command(name = "aegis")]
#[command(about = "AI-Era Secure Coding Infrastructure & Linter", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit a directory or file for AI anti-patterns
    Audit {
        /// Path to the directory or file to scan
        path: String,
        /// Path to the rules directory
        #[arg(short, long, default_value = "./rules")]
        rules: String,
        /// Output format (text, json, sarif)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Audit { path, rules, format } => {
            if format.to_lowercase() != "json" {
                println!("{} Loading rules from {}", "[INFO]".blue(), rules);
            }
            let loaded_rules = RuleConfig::load_all_from_dir(rules)?;
            if format.to_lowercase() != "json" {
                println!("{} Loaded {} rules", "[INFO]".blue(), loaded_rules.len());
            }

            if loaded_rules.is_empty() {
                println!("{} No rules found in {}", "[WARNING]".yellow(), rules);
                return Ok(());
            }

            let mut scan_engine = Engine::new()?;
            
            if format.to_lowercase() != "json" {
                println!("{} Scanning {}", "[INFO]".blue(), path);
            }
            
            // Read .aegisignore if exists
            let mut ignored_paths = vec!["node_modules".to_string(), "dist".to_string(), "build".to_string(), "coverage".to_string(), ".git".to_string()];
            if let Ok(ignore_content) = std::fs::read_to_string(".aegisignore") {
                for line in ignore_content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        ignored_paths.push(trimmed.to_string());
                    }
                }
            }

            // Collect files
            let supported_extensions = ["ts", "tsx", "js", "jsx", "py", "go"];
            let mut files_to_scan = Vec::new();
            let target_path = Path::new(path);
            if target_path.is_file() {
                if let Some(ext) = target_path.extension().and_then(|s| s.to_str()) {
                    if supported_extensions.contains(&ext) {
                        files_to_scan.push(target_path.to_path_buf());
                    }
                }
            } else if target_path.is_dir() {
                let walker = walkdir::WalkDir::new(target_path).into_iter();
                for entry in walker.filter_entry(|e| {
                    let file_name = e.file_name().to_string_lossy();
                    !ignored_paths.iter().any(|ignored| file_name == *ignored || e.path().to_string_lossy().contains(ignored))
                }) {
                    let entry = entry.unwrap();
                    let p = entry.path();
                    if p.is_file() {
                        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                            if supported_extensions.contains(&ext) {
                                files_to_scan.push(p.to_path_buf());
                            }
                        }
                    }
                }
            }

            let mut total_violations = 0;
            let mut high_count = 0;
            let mut medium_count = 0;
            let mut low_count = 0;

            let mut all_violations = Vec::new();

            for file in files_to_scan {
                let file_str = file.to_string_lossy();
                match scan_engine.scan_file(&file_str, &loaded_rules) {
                    Ok(violations) => {
                        for v in violations {
                            total_violations += 1;
                            match v.rule.confidence {
                                rule::Confidence::HIGH => high_count += 1,
                                rule::Confidence::MEDIUM => medium_count += 1,
                                rule::Confidence::LOW => low_count += 1,
                            }
                            all_violations.push(v);
                        }
                    }
                    Err(e) => {
                        if format.to_lowercase() != "json" && format.to_lowercase() != "sarif" {
                            eprintln!("{} Failed to scan file '{}': {}", "[WARNING]".yellow(), file_str, e);
                        }
                    }
                }
            }

            if format.to_lowercase() == "json" {
                let json_output = serde_json::json!({
                    "summary": {
                        "total": total_violations,
                        "high": high_count,
                        "medium": medium_count,
                        "low": low_count,
                        "risk_score": calculate_risk_score(high_count, medium_count, low_count)
                    },
                    "violations": all_violations.iter().map(|v| {
                        serde_json::json!({
                            "rule_id": v.rule.id,
                            "confidence": format!("{:?}", v.rule.confidence),
                            "message": v.rule.message,
                            "explanation": v.rule.explanation,
                            "file": v.file_path,
                            "line": v.line_number
                        })
                    }).collect::<Vec<_>>()
                });
                println!("{}", serde_json::to_string_pretty(&json_output)?);
                return Ok(());
            }

            if format.to_lowercase() == "sarif" {
                let sarif = generate_sarif(&all_violations, "aegis");
                println!("{}", serde_json::to_string_pretty(&sarif)?);
                if high_count > 0 {
                    std::process::exit(1);
                }
                return Ok(());
            }

            if !all_violations.is_empty() {
                for v in &all_violations {
                    let conf_str = match v.rule.confidence {
                        rule::Confidence::HIGH => "[HIGH]".red().bold(),
                        rule::Confidence::MEDIUM => "[MEDIUM]".yellow().bold(),
                        rule::Confidence::LOW => "[LOW]".blue().bold(),
                    };
                    println!(
                        "{} {} in {}\n    {}",
                        conf_str,
                        v.rule.message.bold(),
                        format!("{}:{}", v.file_path, v.line_number).italic(),
                        format!("Explanation: {}", v.rule.explanation).dimmed()
                    );
                }
            }

            println!("\n{}", "Scan Summary".bold());
            println!("{}", "────────────".dimmed());
            println!("HIGH:   {}", high_count.to_string().red());
            println!("MEDIUM: {}", medium_count.to_string().yellow());
            println!("LOW:    {}", low_count.to_string().blue());
            
            let risk_score = calculate_risk_score(high_count, medium_count, low_count);
            let risk_color = if risk_score > 50 { risk_score.to_string().red().bold() } else { risk_score.to_string().green().bold() };
            println!("\nAI Risk Score: {}/100", risk_color);

            if total_violations == 0 {
                println!("\n{} No violations found! Great job.", "[SUCCESS]".green());
            } else {
                println!("\n{} Found {} violations", "[!]".red(), total_violations);
                // Exit with error code if there are HIGH violations, useful for CI
                if high_count > 0 {
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

fn calculate_risk_score(high: usize, medium: usize, low: usize) -> usize {
    let score = (high * 10) + (medium * 3) + (low * 1);
    std::cmp::min(score * 2, 100)
}
