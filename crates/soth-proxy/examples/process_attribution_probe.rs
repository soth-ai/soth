use soth_proxy::process_attribution::probe_process_identity_by_pid;
use std::env;
use std::time::Duration;

fn print_usage() {
    eprintln!(
        "Usage:\n  cargo run -p soth-proxy --example process_attribution_probe -- --pid <PID> [--pid <PID> ...] [--timeout-ms <MS>]\n  cargo run -p soth-proxy --example process_attribution_probe -- <PID> [PID ...]"
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pids: Vec<u32> = Vec::new();
    let mut timeout_ms: u64 = 300;

    let mut args = env::args().skip(1).peekable();
    if args.peek().is_none() {
        print_usage();
        std::process::exit(2);
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            "--pid" => {
                let Some(value) = args.next() else {
                    eprintln!("Missing value for --pid");
                    std::process::exit(2);
                };
                let pid = value.parse::<u32>()?;
                pids.push(pid);
            }
            "--timeout-ms" => {
                let Some(value) = args.next() else {
                    eprintln!("Missing value for --timeout-ms");
                    std::process::exit(2);
                };
                timeout_ms = value.parse::<u64>()?;
            }
            other => {
                let pid = other.parse::<u32>()?;
                pids.push(pid);
            }
        }
    }

    if pids.is_empty() {
        print_usage();
        std::process::exit(2);
    }

    let timeout = Duration::from_millis(timeout_ms);
    let mut rows: Vec<serde_json::Value> = Vec::new();

    for pid in pids {
        let row = match probe_process_identity_by_pid(pid, timeout).await {
            Some(identity) => serde_json::json!({
                "pid_input": pid,
                "pid": identity.pid,
                "process_name": identity.name,
                "process_executable": identity.executable,
                "process_bundle_id": identity.bundle_id,
                "process_attribution_source": identity.attribution_source,
                "process_attribution_confidence": identity.attribution_confidence
            }),
            None => serde_json::json!({
                "pid_input": pid,
                "error": "not_found_or_not_supported"
            }),
        };
        rows.push(row);
    }

    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}
