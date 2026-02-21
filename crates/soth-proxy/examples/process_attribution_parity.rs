use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

const MAX_PARENT_WALK_DEPTH: usize = 10;

#[cfg(target_os = "macos")]
const RTLD_LAZY: c_int = 0x1;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}

#[derive(Debug, Clone, Default)]
struct ProcessInfo {
    pid: u32,
    ppid: Option<u32>,
    user: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Serialize)]
struct ParityResult {
    pid_input: u32,
    pid: Option<u32>,
    name: Option<String>,
    path: Option<String>,
    ppid: Option<u32>,
    parent_name: Option<String>,
    user: Option<String>,
    bundle_id: Option<String>,
    resolved_via: Option<String>,
    responsible_pid: Option<u32>,
    responsible_bundle_id: Option<String>,
    parent_walk_pid: Option<u32>,
    parent_walk_depth: Option<usize>,
}

fn print_usage() {
    eprintln!(
        "Usage:\n  cargo run -p soth-proxy --example process_attribution_parity -- --pid <PID> [--pid <PID> ...] [--timeout-ms <MS>]\n  cargo run -p soth-proxy --example process_attribution_parity -- <PID> [PID ...]"
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pids: Vec<u32> = Vec::new();
    let mut timeout_ms: u64 = 500;

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
                pids.push(value.parse::<u32>()?);
            }
            "--timeout-ms" => {
                let Some(value) = args.next() else {
                    eprintln!("Missing value for --timeout-ms");
                    std::process::exit(2);
                };
                timeout_ms = value.parse::<u64>()?;
            }
            other => {
                pids.push(other.parse::<u32>()?);
            }
        }
    }

    if pids.is_empty() {
        print_usage();
        std::process::exit(2);
    }

    let timeout_dur = Duration::from_millis(timeout_ms);
    let mut bundle_cache: HashMap<String, Option<String>> = HashMap::new();
    let mut rows: Vec<ParityResult> = Vec::new();

    for pid in pids {
        let row = resolve_process_parity_for_pid(pid, timeout_dur, &mut bundle_cache).await;
        rows.push(row);
    }

    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}

async fn resolve_process_parity_for_pid(
    pid_input: u32,
    timeout_dur: Duration,
    bundle_cache: &mut HashMap<String, Option<String>>,
) -> ParityResult {
    let original_info = match get_process_info(pid_input, timeout_dur).await {
        Some(info) => info,
        None => {
            return ParityResult {
                pid_input,
                pid: None,
                name: None,
                path: None,
                ppid: None,
                parent_name: None,
                user: None,
                bundle_id: None,
                resolved_via: Some("unknown_process".to_string()),
                responsible_pid: None,
                responsible_bundle_id: None,
                parent_walk_pid: None,
                parent_walk_depth: None,
            };
        }
    };

    let mut current_pid = original_info.pid;
    let mut final_info = original_info.clone();
    let mut name = extract_name(original_info.path.as_deref());
    let mut bundle_id =
        extract_bundle_id(original_info.path.as_deref(), timeout_dur, bundle_cache).await;

    let mut parent_name = None;
    if let Some(ppid) = original_info.ppid {
        if ppid > 1 {
            parent_name = get_process_info(ppid, timeout_dur)
                .await
                .and_then(|p| extract_name(p.path.as_deref()));
        }
    }

    let mut resolved_via = Some(if let Some(bid) = bundle_id.as_deref() {
        if is_macos_system_service(bid) {
            "system_service".to_string()
        } else {
            "app_delegation_check".to_string()
        }
    } else {
        "no_bundle_id".to_string()
    });

    let mut responsible_pid = None;
    let mut responsible_bundle_id = None;
    let mut parent_walk_pid = None;
    let mut parent_walk_depth = None;

    #[cfg(target_os = "macos")]
    if let Some(rpid) = macos_responsible_pid(current_pid) {
        responsible_pid = Some(rpid);
        let resp_path = macos_proc_pidpath(rpid);
        if let Some(path) = resp_path {
            let rb = extract_bundle_id(Some(path.as_str()), timeout_dur, bundle_cache).await;
            responsible_bundle_id = rb.clone();
            if rb.is_some() && rb != bundle_id {
                bundle_id = rb;
                current_pid = rpid;
                if let Some(resp_info) = get_process_info(rpid, timeout_dur).await {
                    final_info = resp_info;
                    name = extract_name(final_info.path.as_deref());
                } else {
                    final_info.path = Some(path);
                    final_info.pid = rpid;
                    name = extract_name(final_info.path.as_deref());
                }
                resolved_via = Some("responsible_pid".to_string());
            }
        } else if let Some(resp_info) = get_process_info(rpid, timeout_dur).await {
            let rb = extract_bundle_id(resp_info.path.as_deref(), timeout_dur, bundle_cache).await;
            responsible_bundle_id = rb.clone();
            if rb.is_some() && rb != bundle_id {
                bundle_id = rb;
                current_pid = rpid;
                final_info = resp_info;
                name = extract_name(final_info.path.as_deref());
                resolved_via = Some("responsible_pid_ps".to_string());
            }
        }
    }

    #[cfg(target_os = "macos")]
    if bundle_id.is_none() {
        let mut ancestor_pid = original_info.ppid;
        let mut depth = 0usize;
        while let Some(apid) = ancestor_pid {
            if apid <= 1 || depth >= MAX_PARENT_WALK_DEPTH {
                break;
            }
            let Some(ancestor_info) = get_process_info(apid, timeout_dur).await else {
                break;
            };
            let ancestor_bundle =
                extract_bundle_id(ancestor_info.path.as_deref(), timeout_dur, bundle_cache).await;
            if let Some(ab) = ancestor_bundle {
                bundle_id = Some(ab);
                parent_walk_pid = Some(apid);
                parent_walk_depth = Some(depth + 1);
                resolved_via = Some("parent_walk".to_string());
                break;
            }
            ancestor_pid = ancestor_info.ppid;
            depth += 1;
        }
    }

    #[cfg(target_os = "windows")]
    if bundle_id.is_none() {
        bundle_id = extract_exe_name(final_info.path.as_deref());
        if bundle_id.is_some() {
            resolved_via = Some("windows_exe_fallback".to_string());
        }
    }

    ParityResult {
        pid_input,
        pid: Some(current_pid),
        name,
        path: final_info.path,
        ppid: final_info.ppid,
        parent_name,
        user: final_info.user,
        bundle_id,
        resolved_via,
        responsible_pid,
        responsible_bundle_id,
        parent_walk_pid,
        parent_walk_depth,
    }
}

async fn get_process_info(pid: u32, timeout_dur: Duration) -> Option<ProcessInfo> {
    let ppid = ps_field(pid, "ppid", timeout_dur)
        .await
        .and_then(|v| v.parse::<u32>().ok());
    let user = ps_field(pid, "user", timeout_dur).await;

    #[cfg(target_os = "macos")]
    let path = macos_proc_pidpath(pid).or(ps_field(pid, "comm", timeout_dur).await);
    #[cfg(not(target_os = "macos"))]
    let path = ps_field(pid, "comm", timeout_dur).await;

    if path.is_none() && ppid.is_none() && user.is_none() {
        return None;
    }

    Some(ProcessInfo {
        pid,
        ppid,
        user,
        path,
    })
}

async fn ps_field(pid: u32, field: &str, timeout_dur: Duration) -> Option<String> {
    let selector = format!("{field}=");
    let mut cmd = Command::new("ps");
    cmd.args(["-p", &pid.to_string(), "-o", &selector]);
    let output = timeout(timeout_dur, cmd.output()).await.ok()?.ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let value = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)?;
    Some(value)
}

fn extract_name(path: Option<&str>) -> Option<String> {
    let raw = path?;
    let mut name = if raw.contains('\\') {
        raw.rsplit('\\').next().unwrap_or(raw).to_string()
    } else {
        raw.rsplit('/').next().unwrap_or(raw).to_string()
    };
    if name.to_ascii_lowercase().ends_with(".exe") {
        name.truncate(name.len().saturating_sub(4));
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(target_os = "windows")]
fn extract_exe_name(path: Option<&str>) -> Option<String> {
    let raw = path?;
    let name = if raw.contains('\\') {
        raw.rsplit('\\').next().unwrap_or(raw).to_string()
    } else {
        raw.rsplit('/').next().unwrap_or(raw).to_string()
    };
    if name.to_ascii_lowercase().ends_with(".exe") {
        Some(name)
    } else {
        None
    }
}

fn looks_like_bundle_id(name: &str) -> bool {
    if name.is_empty() || name.matches('.').count() < 2 {
        return false;
    }
    let parts: Vec<&str> = name.split('.').collect();
    let Some(prefix) = parts.first() else {
        return false;
    };
    let known_prefixes = ["com", "org", "net", "io", "app", "me", "co", "dev"];
    if !known_prefixes
        .iter()
        .any(|k| k.eq_ignore_ascii_case(prefix))
    {
        return false;
    }
    parts.iter().all(|p| {
        let sanitized = p.replace('-', "").replace('_', "");
        !sanitized.is_empty() && sanitized.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

async fn extract_bundle_id(
    path: Option<&str>,
    timeout_dur: Duration,
    cache: &mut HashMap<String, Option<String>>,
) -> Option<String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = timeout_dur;
        let _ = cache;
        let _ = path;
        return None;
    }

    #[cfg(target_os = "macos")]
    {
        let raw = path?;

        if let Some(app_idx) = raw.find(".app") {
            let app_path = format!("{}.app", &raw[..app_idx]);
            if let Some(cached) = cache.get(&app_path) {
                return cached.clone();
            }
            let plist_path = format!("{app_path}/Contents/Info.plist");
            let found = defaults_read_bundle_id(&plist_path, timeout_dur).await;
            cache.insert(app_path, found.clone());
            if found.is_some() {
                return found;
            }
        }

        if let Some(xpc_idx) = raw.find(".xpc") {
            let xpc_path = format!("{}.xpc", &raw[..xpc_idx]);
            if let Some(cached) = cache.get(&xpc_path) {
                return cached.clone();
            }
            let plist_path = format!("{xpc_path}/Contents/Info.plist");
            let found = defaults_read_bundle_id(&plist_path, timeout_dur).await;
            cache.insert(xpc_path, found.clone());
            if found.is_some() {
                return found;
            }
        }

        if let Some(name) = extract_name(Some(raw)) {
            if looks_like_bundle_id(&name) {
                return Some(name);
            }
        }
        None
    }
}

#[cfg(target_os = "macos")]
async fn defaults_read_bundle_id(plist_path: &str, timeout_dur: Duration) -> Option<String> {
    let mut cmd = Command::new("defaults");
    cmd.args(["read", plist_path, "CFBundleIdentifier"]);
    let output = timeout(timeout_dur, cmd.output()).await.ok()?.ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let value = text.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(target_os = "macos")]
fn is_macos_system_service(bundle_id: &str) -> bool {
    let lower = bundle_id.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "com.apple.webkit.networking"
            | "com.apple.webkit.webcontent"
            | "com.apple.webkit.gpu"
            | "com.apple.nsurlsessiond"
            | "com.apple.cfnetwork"
            | "com.apple.networkserviceproxy"
    )
}

#[cfg(not(target_os = "macos"))]
fn is_macos_system_service(_bundle_id: &str) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn macos_responsible_pid(pid: u32) -> Option<u32> {
    unsafe {
        let lib_name = CString::new("/usr/lib/libSystem.B.dylib").ok()?;
        let symbol = CString::new("responsibility_get_pid_responsible_for_pid").ok()?;
        let handle = dlopen(lib_name.as_ptr(), RTLD_LAZY);
        if handle.is_null() {
            return None;
        }
        let addr = dlsym(handle, symbol.as_ptr());
        if addr.is_null() {
            let _ = dlclose(handle);
            return None;
        }
        type ResponsibleFn = unsafe extern "C" fn(c_int) -> c_int;
        let func: ResponsibleFn = std::mem::transmute(addr);
        let result = func(pid as c_int);
        let _ = dlclose(handle);
        if result > 0 && result as u32 != pid {
            Some(result as u32)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn macos_responsible_pid(_pid: u32) -> Option<u32> {
    None
}

#[cfg(target_os = "macos")]
fn macos_proc_pidpath(pid: u32) -> Option<String> {
    unsafe {
        let lib_name = CString::new("/usr/lib/libproc.dylib").ok()?;
        let symbol = CString::new("proc_pidpath").ok()?;
        let handle = dlopen(lib_name.as_ptr(), RTLD_LAZY);
        if handle.is_null() {
            return None;
        }
        let addr = dlsym(handle, symbol.as_ptr());
        if addr.is_null() {
            let _ = dlclose(handle);
            return None;
        }
        type ProcPidPathFn = unsafe extern "C" fn(c_int, *mut c_char, u32) -> c_int;
        let func: ProcPidPathFn = std::mem::transmute(addr);
        let mut buf = vec![0 as c_char; 4096];
        let ret = func(pid as c_int, buf.as_mut_ptr(), buf.len() as u32);
        let _ = dlclose(handle);
        if ret <= 0 {
            return None;
        }
        let c = CStr::from_ptr(buf.as_ptr());
        c.to_str().ok().map(|s| s.to_string())
    }
}

#[cfg(not(target_os = "macos"))]
fn macos_proc_pidpath(_pid: u32) -> Option<String> {
    None
}
