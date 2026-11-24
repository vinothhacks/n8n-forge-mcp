//! `n8n-rs-mcp` CLI binary (`mcp`, `doctor --no-secret-output`, `capabilities`, `sync-catalog`, `reconcile`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use n8n_catalog_db::{CatalogDb, CatalogManifest};
use n8n_mcp_server::tools::execute_capabilities;
use n8n_mcp_server::{
    AppState, AppStateOptions, CapabilitiesParams, HttpGatewayConfig, HttpGatewayHandle,
    N8nMcpServer, resolve_and_open_catalog, run_doctor, serve_stdio,
};
use n8n_policy::{PolicyMode, load_workspace_config};
use n8n_test_harness::StartupReconciler;
use n8n_types::{DetailLevel, SecretValue, redact_json_value, redact_str};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "n8n-rs-mcp",
    version,
    about = "Governance-first Rust MCP server and operator CLI for n8n"
)]
struct Cli {
    /// Optional path to `instances.toml` multi-instance configuration.
    #[arg(long, global = true)]
    instances_config: Option<PathBuf>,

    /// Optional path to `policy.<mode>.toml` policy override file.
    #[arg(long, global = true)]
    policy_config: Option<PathBuf>,

    /// Optional explicit path to `catalog.sqlite.zst` offline node/template bundle.
    #[arg(long, global = true)]
    catalog_path: Option<PathBuf>,

    /// Optional explicit path to OS-ACL protected local state vault directory.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum McpTransport {
    Stdio,
    Http,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the MCP server (`stdio` default, or authenticated loopback `http` gateway).
    Mcp {
        /// Target n8n instance alias.
        #[arg(long)]
        instance: Option<String>,
        /// Policy profile (`read-only`, `staging-safe`, `production-guarded`, `full-dev`).
        #[arg(long)]
        policy: Option<String>,
        /// Transport mode (`stdio` default; `http` requires `N8N_MCP_HTTP_BEARER_TOKEN`).
        #[arg(long, value_enum, default_value_t = McpTransport::Stdio)]
        transport: McpTransport,
        /// Bind address when `--transport http` is used (must be loopback unless explicitly overridden).
        #[arg(long, default_value = "127.0.0.1:0")]
        bind: SocketAddr,
    },
    /// Run non-mutating connectivity, auth, SSRF, catalog, vault, and capability diagnostics without leaking secrets.
    Doctor {
        /// Target n8n instance alias.
        #[arg(long)]
        instance: Option<String>,
        /// Enforce strict redaction (always enabled; flag accepted for explicit CI/operator contract).
        #[arg(long, default_value_t = true)]
        no_secret_output: bool,
        /// Output format (`table` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
    },
    /// Resolve and display the live capability and route matrix for an n8n instance.
    Capabilities {
        /// Target n8n instance alias.
        #[arg(long)]
        instance: Option<String>,
        /// Output format (`table` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
    },
    /// Verify and inspect the offline `catalog.sqlite.zst` node/template bundle and sibling manifest.
    SyncCatalog {
        /// Bundle source identifier or path (e.g. `pinned-bundle` or `data/catalog.sqlite.zst`).
        #[arg(long, default_value = "pinned-bundle")]
        from: String,
    },
    /// Inspect and reconcile uncertain mutating operations or abandoned `[MCP-E2E-TEST]` cleanup leases.
    Reconcile {
        /// Target n8n instance alias.
        #[arg(long)]
        instance: Option<String>,
        /// Report pending reconciliation items without performing writes.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        dry_run: bool,
    },
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    // Always route logs to stderr so MCP `stdio` stdout JSON-RPC framing stays pure!
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Mcp {
            instance,
            policy,
            transport,
            bind,
        } => {
            let parsed_policy = policy
                .as_deref()
                .map(PolicyMode::from_str)
                .transpose()
                .map_err(|e| anyhow::anyhow!(redact_str(&e.to_string())))?;
            let state = build_state(
                cli.instances_config.as_deref(),
                cli.policy_config.as_deref(),
                cli.catalog_path.clone(),
                cli.state_dir.clone(),
                instance.as_deref(),
                parsed_policy,
            )?;

            // Run dry-run startup journal inspection so any pending cleanup lease is surfaced on stderr!
            if let Ok(rt) = state.instance(instance.as_deref()) {
                let reconciler = StartupReconciler::new(&rt.config.alias);
                let mut journal = state.journal.lock().await;
                if let Ok(rep) = reconciler
                    .reconcile_startup(&mut journal, rt.api_client.as_ref(), true)
                    .await
                    && (!rep.lease_entries.is_empty() || !rep.operation_entries.is_empty())
                {
                    tracing::warn!(
                        leases = rep.lease_entries.len(),
                        uncertain_ops = rep.operation_entries.len(),
                        "startup journal inspection found pending reconciliation items; run `n8n-rs-mcp reconcile --dry-run=false` if needed"
                    );
                }
            }

            match transport {
                McpTransport::Stdio => {
                    serve_stdio(state)
                        .await
                        .map_err(|e| anyhow::anyhow!(redact_str(&e.to_string())))?;
                }
                McpTransport::Http => {
                    let bearer = std::env::var("N8N_MCP_HTTP_BEARER_TOKEN")
                        .ok()
                        .filter(|s| !s.trim().is_empty())
                        .map(SecretValue::new);
                    let cfg = HttpGatewayConfig::loopback(bind, bearer);
                    let server = N8nMcpServer::new(state);
                    let handle = HttpGatewayHandle::start(server, cfg)
                        .await
                        .map_err(|e| anyhow::anyhow!(redact_str(&e.to_string())))?;
                    eprintln!(
                        "n8n-rs-mcp authenticated HTTP gateway listening on http://{}/mcp",
                        handle.local_addr()
                    );
                    tokio::signal::ctrl_c()
                        .await
                        .context("wait for Ctrl+C shutdown signal")?;
                    handle.shutdown().await;
                }
            }
        }
        Commands::Doctor {
            instance,
            no_secret_output,
            format,
        } => {
            let state = build_state(
                cli.instances_config.as_deref(),
                cli.policy_config.as_deref(),
                cli.catalog_path.clone(),
                cli.state_dir.clone(),
                instance.as_deref(),
                None,
            )?;
            let report = run_doctor(&state, instance.as_deref(), no_secret_output).await;
            let redacted = report.to_redacted_json();
            match format {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&redacted)
                            .context("serialize doctor report")?
                    );
                }
                OutputFormat::Table => {
                    println!(
                        "n8n-rs-mcp doctor | instance={} | env={} | policy={} | healthy={}",
                        report.instance, report.environment, report.policy_mode, report.healthy
                    );
                    println!("{:<28} {:<8} SUMMARY", "CHECK", "STATUS");
                    println!("{}", "-".repeat(88));
                    for check in &report.checks {
                        println!(
                            "{:<28} {:<8} {}",
                            check.name,
                            check.status.to_ascii_uppercase(),
                            redact_str(&check.summary)
                        );
                    }
                }
            }
            if !report.healthy {
                std::process::exit(1);
            }
        }
        Commands::Capabilities { instance, format } => {
            let state = build_state(
                cli.instances_config.as_deref(),
                cli.policy_config.as_deref(),
                cli.catalog_path.clone(),
                cli.state_dir.clone(),
                instance.as_deref(),
                None,
            )?;
            let envelope = execute_capabilities(
                &state,
                CapabilitiesParams {
                    instance,
                    detail: DetailLevel::Standard,
                    refresh: true,
                },
            )
            .await;
            match format {
                OutputFormat::Json => {
                    let pretty = envelope
                        .to_redacted_json_string_pretty()
                        .context("serialize capabilities envelope")?;
                    println!("{pretty}");
                }
                OutputFormat::Table => {
                    let val = envelope
                        .to_redacted_value()
                        .context("redact capabilities value")?;
                    println!(
                        "Instance: {} | Status: {:?} | Route: {:?}",
                        envelope.instance, envelope.status, envelope.route_used
                    );
                    if let Some(tools) = val
                        .get("data")
                        .and_then(|d| d.get("tools"))
                        .and_then(serde_json::Value::as_array)
                    {
                        println!("{:<26} {:<16} {:<14} REASON", "TOOL", "STATE", "ROUTE");
                        println!("{}", "-".repeat(96));
                        for t in tools {
                            let name = t.get("toolName").and_then(|v| v.as_str()).unwrap_or("-");
                            let st = t.get("state").and_then(|v| v.as_str()).unwrap_or("-");
                            let rt = t
                                .get("preferredRoute")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");
                            let reason = t.get("reason").and_then(|v| v.as_str()).unwrap_or("-");
                            println!("{name:<26} {st:<16} {rt:<14} {reason}");
                        }
                    } else {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&val)
                                .context("serialize error envelope")?
                        );
                    }
                }
            }
        }
        Commands::SyncCatalog { from } => {
            let explicit = if from == "pinned-bundle" {
                cli.catalog_path.as_deref()
            } else {
                Some(Path::new(&from))
            };
            let (db, resolved_path, warning) = resolve_and_open_catalog(explicit);
            if let Some(bundle_path) = resolved_path {
                let hash = CatalogDb::verify_bundle_hash(&bundle_path)
                    .map_err(|e| anyhow::anyhow!(redact_str(&e.to_string())))?;
                let manifest_opt = bundle_path
                    .parent()
                    .map(|p| p.join("catalog.manifest.json"))
                    .filter(|p| p.is_file())
                    .and_then(|p| CatalogManifest::from_path(&p).ok());
                let sync_report = if let Some(ref manifest) = manifest_opt {
                    db.sync_catalog_with_manifest(manifest)
                } else {
                    db.sync_catalog()
                }
                .map_err(|e| anyhow::anyhow!(redact_str(&e.to_string())))?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "verified",
                        "bundlePath": bundle_path.display().to_string(),
                        "compressedBlake3": hash,
                        "manifestVerified": manifest_opt.is_some(),
                        "report": sync_report,
                    }))?
                );
            } else {
                anyhow::bail!(
                    "Catalog bundle could not be resolved ({})",
                    warning.unwrap_or_else(|| "file not found".to_owned())
                );
            }
        }
        Commands::Reconcile { instance, dry_run } => {
            let state = build_state(
                cli.instances_config.as_deref(),
                cli.policy_config.as_deref(),
                cli.catalog_path.clone(),
                cli.state_dir.clone(),
                instance.as_deref(),
                None,
            )?;
            let rt = state
                .instance(instance.as_deref())
                .map_err(|e| anyhow::anyhow!(redact_str(&e.to_string())))?;
            let reconciler = StartupReconciler::new(&rt.config.alias);
            let report = {
                let mut journal = state.journal.lock().await;
                reconciler
                    .reconcile_startup(&mut journal, rt.api_client.as_ref(), dry_run)
                    .await
                    .map_err(|e| anyhow::anyhow!(redact_str(&e.to_string())))?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&redact_json_value(&serde_json::to_value(report)?))?
            );
        }
    }

    Ok(())
}

fn build_state(
    instances_toml: Option<&Path>,
    policy_toml: Option<&Path>,
    catalog_path: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    instance: Option<&str>,
    policy: Option<PolicyMode>,
) -> anyhow::Result<AppState> {
    let ws = load_workspace_config(instances_toml, policy_toml, instance, policy, |k| {
        std::env::var(k).ok()
    })
    .map_err(|e| anyhow::anyhow!(redact_str(&e.to_string())))?;
    AppState::from_workspace_config_with_options(
        ws,
        Duration::from_secs(60),
        AppStateOptions::persistent_cli(catalog_path, state_dir),
    )
    .map_err(|e| anyhow::anyhow!(redact_str(&e.to_string())))
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use crate::{Cli, Commands, McpTransport};

    #[test]
    fn cli_command_factory_and_subcommands_parse_cleanly() {
        Cli::command().debug_assert();

        let doc = Cli::try_parse_from([
            "n8n-rs-mcp",
            "doctor",
            "--instance",
            "staging",
            "--no-secret-output",
            "--format",
            "json",
        ])
        .expect("parse doctor");
        assert!(matches!(
            doc.command,
            Commands::Doctor {
                no_secret_output: true,
                ..
            }
        ));

        let cap = Cli::try_parse_from([
            "n8n-rs-mcp",
            "capabilities",
            "--instance",
            "staging",
            "--format",
            "table",
        ])
        .expect("parse capabilities");
        assert!(matches!(cap.command, Commands::Capabilities { .. }));

        let mcp = Cli::try_parse_from([
            "n8n-rs-mcp",
            "--catalog-path",
            "data/catalog.sqlite.zst",
            "mcp",
            "--instance",
            "staging",
            "--policy",
            "staging-safe",
            "--transport",
            "http",
            "--bind",
            "127.0.0.1:0",
        ])
        .expect("parse mcp");
        assert!(matches!(
            mcp.command,
            Commands::Mcp {
                transport: McpTransport::Http,
                ..
            }
        ));

        let rec = Cli::try_parse_from(["n8n-rs-mcp", "reconcile", "--dry-run=false"])
            .expect("parse reconcile");
        assert!(matches!(
            rec.command,
            Commands::Reconcile { dry_run: false, .. }
        ));
    }
}
