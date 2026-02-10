//! Budget management commands

use crate::cli_config;
use crate::BudgetCommands;
use anyhow::Result;
use chrono::{Duration, Utc};
use soth_budget::BudgetStorage;
use std::path::PathBuf;

/// Run budget command
pub async fn run(action: BudgetCommands) -> Result<()> {
    match action {
        BudgetCommands::Status { detailed } => {
            show_status(detailed).await?;
        }
        BudgetCommands::Report { period, format } => {
            generate_report(&period, &format).await?;
        }
        BudgetCommands::Reset { budget_id } => {
            reset_budget(&budget_id).await?;
        }
        BudgetCommands::Set {
            scope,
            daily,
            weekly,
            monthly,
        } => {
            set_budget(&scope, daily, weekly, monthly).await?;
        }
    }
    Ok(())
}

/// Show current budget status
async fn show_status(detailed: bool) -> Result<()> {
    let storage = get_storage()?;

    // Get all budget states
    let budgets = storage.get_all_budget_states()?;

    if budgets.is_empty() {
        println!("No budgets configured");
        return Ok(());
    }

    println!("Budget Status");
    println!("═════════════\n");

    for budget in &budgets {
        let usage = budget.usage_percent().unwrap_or(0.0);
        let bar = create_progress_bar(usage, 30);

        println!("{} ({:?})", budget.id, budget.scope);

        if let Some(daily) = budget.daily_limit {
            println!(
                "  Daily:   ${:.2} / ${:.2} ({:.1}%)",
                budget.current_spend, daily, usage
            );
            println!("           {bar}");
        }
        if let Some(weekly) = budget.weekly_limit {
            println!("  Weekly:  ${:.2} / ${:.2}", budget.current_spend, weekly);
        }
        if let Some(monthly) = budget.monthly_limit {
            println!("  Monthly: ${:.2} / ${:.2}", budget.current_spend, monthly);
        }

        if detailed {
            println!("  Tokens:  {} total", budget.total_tokens);
            println!("  Requests: {}", budget.total_requests);
            println!(
                "  Period start: {}",
                budget.period_start.format("%Y-%m-%d %H:%M")
            );
        }
        println!();
    }

    // Summary
    let total_spend: f64 = budgets.iter().map(|b| b.current_spend).sum();
    let total_tokens: u64 = budgets.iter().map(|b| b.total_tokens).sum();
    let total_requests: u64 = budgets.iter().map(|b| b.total_requests).sum();

    println!("Summary");
    println!("───────");
    println!("  Total spend:    ${total_spend:.2}");
    println!("  Total tokens:   {total_tokens}");
    println!("  Total requests: {total_requests}");

    Ok(())
}

/// Create a progress bar string
fn create_progress_bar(percent: f64, width: usize) -> String {
    let filled = ((percent / 100.0) * width as f64).min(width as f64) as usize;
    let empty = width.saturating_sub(filled);

    let bar_char = if percent >= 100.0 {
        '█'
    } else if percent >= 80.0 {
        '▓'
    } else if percent >= 50.0 {
        '▒'
    } else {
        '░'
    };

    format!(
        "[{}{}]",
        std::iter::repeat_n(bar_char, filled).collect::<String>(),
        "░".repeat(empty)
    )
}

/// Generate spend report
async fn generate_report(period: &str, format: &str) -> Result<()> {
    let storage = get_storage()?;

    let since = match period {
        "daily" => Utc::now() - Duration::days(1),
        "weekly" => Utc::now() - Duration::weeks(1),
        "monthly" => Utc::now() - Duration::days(30),
        _ => anyhow::bail!("Invalid period: {period}. Use daily, weekly, or monthly"),
    };

    let records = storage.get_records_since(since)?;
    let total_spend = storage.get_total_spend_since(since)?;
    let by_model = storage.get_spend_by_model(since)?;
    let by_agent = storage.get_spend_by_agent(since)?;

    match format {
        "json" => {
            let report = serde_json::json!({
                "period": period,
                "since": since.to_rfc3339(),
                "total_spend": total_spend,
                "record_count": records.len(),
                "by_model": by_model.iter().map(|(m, c, t)| {
                    serde_json::json!({"model": m, "cost": c, "tokens": t})
                }).collect::<Vec<_>>(),
                "by_agent": by_agent.iter().map(|(a, c, r)| {
                    serde_json::json!({"agent": a, "cost": c, "requests": r})
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "csv" => {
            println!("model,cost,tokens");
            for (model, cost, tokens) in &by_model {
                println!("{model},{cost:.4},{tokens}");
            }
        }
        _ => {
            println!("Spend Report ({period})");
            println!("═══════════════════════════════════\n");
            println!(
                "Period: {} to {}",
                since.format("%Y-%m-%d"),
                Utc::now().format("%Y-%m-%d")
            );
            println!("Total spend: ${total_spend:.2}");
            println!("Total records: {}\n", records.len());

            if !by_model.is_empty() {
                println!("By Model:");
                println!("─────────");
                for (model, cost, tokens) in &by_model {
                    println!("  {model:<25} ${cost:>8.2}  ({tokens} tokens)");
                }
                println!();
            }

            if !by_agent.is_empty() {
                println!("By Agent:");
                println!("─────────");
                for (agent, cost, requests) in &by_agent {
                    println!("  {agent:<25} ${cost:>8.2}  ({requests} requests)");
                }
            }
        }
    }

    Ok(())
}

/// Reset budget counters
async fn reset_budget(budget_id: &str) -> Result<()> {
    let storage = get_storage()?;

    if budget_id == "all" {
        let budgets = storage.get_all_budget_states()?;
        for mut budget in budgets {
            budget.current_spend = 0.0;
            budget.total_tokens = 0;
            budget.total_requests = 0;
            budget.period_start = Utc::now();
            storage.save_budget_state(&budget)?;
        }
        println!("Reset all budgets");
    } else if let Some(mut budget) = storage.get_budget_state(budget_id)? {
        budget.current_spend = 0.0;
        budget.total_tokens = 0;
        budget.total_requests = 0;
        budget.period_start = Utc::now();
        storage.save_budget_state(&budget)?;
        println!("Reset budget: {budget_id}");
    } else {
        anyhow::bail!("Budget not found: {budget_id}");
    }

    Ok(())
}

/// Set budget limits
async fn set_budget(
    scope: &str,
    daily: Option<f64>,
    weekly: Option<f64>,
    monthly: Option<f64>,
) -> Result<()> {
    if daily.is_none() && weekly.is_none() && monthly.is_none() {
        anyhow::bail!("At least one limit must be specified (--daily, --weekly, or --monthly)");
    }

    let storage = get_storage()?;

    // Parse scope
    let (budget_id, budget_scope) = if scope == "global" {
        (
            "global".to_string(),
            soth_core::types::budget::BudgetScope::Global,
        )
    } else if scope.starts_with("agent:") {
        let agent_id = scope.strip_prefix("agent:").unwrap();
        (
            agent_id.to_string(),
            soth_core::types::budget::BudgetScope::PerAgent,
        )
    } else {
        anyhow::bail!("Invalid scope: {scope}. Use \'global\' or \'agent:<id>\'");
    };

    let mut budget = storage
        .get_budget_state(&budget_id)?
        .unwrap_or_else(|| soth_core::types::budget::BudgetState::new(&budget_id, budget_scope));

    if let Some(d) = daily {
        budget.daily_limit = Some(d);
    }
    if let Some(w) = weekly {
        budget.weekly_limit = Some(w);
    }
    if let Some(m) = monthly {
        budget.monthly_limit = Some(m);
    }

    budget.updated_at = Utc::now();
    storage.save_budget_state(&budget)?;

    println!("Set budget limits for {budget_id}");
    if let Some(d) = budget.daily_limit {
        println!("  Daily:   ${d:.2}");
    }
    if let Some(w) = budget.weekly_limit {
        println!("  Weekly:  ${w:.2}");
    }
    if let Some(m) = budget.monthly_limit {
        println!("  Monthly: ${m:.2}");
    }

    Ok(())
}

/// Get budget storage
fn get_storage() -> Result<BudgetStorage> {
    let db_path = resolve_budget_db_path();
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("Failed to create budget DB directory: {e}"))?;
    }

    BudgetStorage::new(&db_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to open budget storage at {}: {}",
            db_path.display(),
            e
        )
    })
}

fn resolve_budget_db_path() -> PathBuf {
    let configured = cli_config::load_effective_config(None, None)
        .ok()
        .and_then(|cfg| cfg.budget.db_path)
        .unwrap_or_else(|| PathBuf::from("~/.soth/budget.db"));
    cli_config::expand_tilde(configured)
}
