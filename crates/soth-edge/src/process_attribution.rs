//! Runtime process attribution for edge proxy socket connections.

use crate::registry::{CaptureMode, EdgeRegistry, InterceptionAction};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MAX_PARENT_WALK_DEPTH: usize = 10;
const DEFAULT_LOOKUP_TIMEOUT: Duration = Duration::from_millis(750);
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const MIN_LOOKUP_TIMEOUT: Duration = Duration::from_millis(25);
const MAX_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const MIN_CACHE_TTL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppType {
    Host,
    NonHost,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessMatchKind {
    AppPolicy,
    BrowserPolicy,
    BrowserAllowedApp,
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub bundle_id: Option<String>,
    pub process_name: Option<String>,
}

impl ProcessIdentity {
    pub fn new(bundle_id: Option<String>, process_name: Option<String>) -> Self {
        Self {
            bundle_id,
            process_name,
        }
    }

    pub fn candidate_ids(&self) -> Vec<String> {
        let mut out = Vec::new();

        if let Some(bundle_id) = &self.bundle_id {
            let trimmed = bundle_id.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_ascii_lowercase());
            }
        }

        if let Some(name) = &self.process_name {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                let candidate = trimmed.to_ascii_lowercase();
                if !out.iter().any(|id| id == &candidate) {
                    out.push(candidate);
                }
            }
        }

        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessResolution {
    pub process_id: Option<String>,
    pub app_type: AppType,
    pub match_kind: ProcessMatchKind,
    pub action: InterceptionAction,
    pub capture_mode: Option<CaptureMode>,
    pub known_app: bool,
    pub browser: bool,
    pub host_allowlist_only: bool,
    pub host_list_ref: Option<String>,
}

impl ProcessResolution {
    pub fn is_known_non_host_app(&self) -> bool {
        self.known_app && self.app_type == AppType::NonHost
    }

    pub fn requires_host_origin_check(&self) -> bool {
        self.app_type == AppType::Host
    }
}

pub fn resolve_process(identity: &ProcessIdentity, registry: &EdgeRegistry) -> ProcessResolution {
    let candidates = identity.candidate_ids();

    for candidate in &candidates {
        if let Some(policy) = registry.app_policy_for(candidate) {
            if !policy.enabled {
                continue;
            }

            let app_type = parse_app_type(&policy.app_type);
            return ProcessResolution {
                process_id: Some(candidate.clone()),
                app_type,
                match_kind: ProcessMatchKind::AppPolicy,
                action: InterceptionAction::parse(&policy.action),
                capture_mode: policy.capture_mode.clone(),
                known_app: true,
                browser: app_type == AppType::Host,
                host_allowlist_only: policy.host_filter.eq_ignore_ascii_case("allowlist"),
                host_list_ref: Some(policy.host_list_ref.clone()),
            };
        }
    }

    for candidate in &candidates {
        if registry.is_browser_process(candidate) {
            return ProcessResolution {
                process_id: Some(candidate.clone()),
                app_type: AppType::Host,
                match_kind: ProcessMatchKind::BrowserPolicy,
                action: registry.browser_default_action(),
                capture_mode: Some(CaptureMode::MetadataOnly),
                known_app: false,
                browser: true,
                host_allowlist_only: true,
                host_list_ref: Some("ai_catalog".to_string()),
            };
        }
    }

    for candidate in &candidates {
        if registry.is_explicit_allowed_app(candidate) {
            return ProcessResolution {
                process_id: Some(candidate.clone()),
                app_type: AppType::NonHost,
                match_kind: ProcessMatchKind::BrowserAllowedApp,
                action: InterceptionAction::Intercept,
                capture_mode: Some(CaptureMode::MetadataOnly),
                known_app: true,
                browser: false,
                host_allowlist_only: true,
                host_list_ref: Some("ai_catalog".to_string()),
            };
        }
    }

    ProcessResolution {
        process_id: candidates.first().cloned(),
        app_type: AppType::Unknown,
        match_kind: ProcessMatchKind::Unknown,
        action: registry.unknown_app_action(),
        capture_mode: None,
        known_app: false,
        browser: false,
        host_allowlist_only: true,
        host_list_ref: Some("ai_catalog".to_string()),
    }
}

fn parse_app_type(value: &str) -> AppType {
    match value.trim().to_ascii_lowercase().as_str() {
        "host" => AppType::Host,
        "non_host" => AppType::NonHost,
        _ => AppType::Unknown,
    }
}

fn clamp_duration(value: Duration, min: Duration, max: Duration) -> Duration {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

#[derive(Debug, Clone)]
pub struct ProcessAttribution {
    enabled: bool,
    lookup_timeout: Duration,
    cache_ttl: Duration,
    cache: Arc<Mutex<HashMap<SocketAddr, CacheEntry>>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value: Option<ResolvedProcessIdentity>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct ResolvedProcessIdentity {
    name: String,
    bundle_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ProcessTableRow {
    ppid: u32,
    name: String,
}

impl ProcessAttribution {
    pub fn new(requested_enabled: bool, lookup_timeout: Duration, cache_ttl: Duration) -> Self {
        Self {
            enabled: requested_enabled
                && (cfg!(target_os = "macos")
                    || cfg!(target_os = "linux")
                    || cfg!(target_os = "windows")),
            lookup_timeout: clamp_duration(lookup_timeout, MIN_LOOKUP_TIMEOUT, MAX_LOOKUP_TIMEOUT),
            cache_ttl: cache_ttl.max(MIN_CACHE_TTL),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn resolve_process(&self, client_addr: SocketAddr) -> ProcessIdentity {
        if !self.enabled {
            return ProcessIdentity::default();
        }

        if let Some(cached) = self.get_cached(client_addr) {
            return as_process_identity(cached);
        }

        let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.resolve_uncached(client_addr)
        }))
        .ok()
        .flatten();
        self.put_cached(client_addr, resolved.clone());
        as_process_identity(resolved)
    }

    pub fn probe_process_by_pid(&self, pid: u32) -> Option<ProcessIdentity> {
        if !self.enabled {
            return None;
        }

        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let raw_name = native_process_name_for_pid(pid, self.lookup_timeout).or_else(|| {
                process_name_from_executable(lookup_executable(pid, self.lookup_timeout).as_deref())
            });
            let raw_name = raw_name.unwrap_or_else(|| "unknown".to_string());
            let resolved = build_process_identity(pid, raw_name, self.lookup_timeout);
            as_process_identity(Some(resolved))
        }))
        .ok()
    }

    fn get_cached(&self, client_addr: SocketAddr) -> Option<Option<ResolvedProcessIdentity>> {
        let now = Instant::now();
        let mut cache = lock_recover(&self.cache);
        match cache.get_mut(&client_addr) {
            Some(entry) if entry.expires_at > now => {
                entry.expires_at = now + self.cache_ttl;
                Some(entry.value.clone())
            }
            Some(_) => {
                cache.remove(&client_addr);
                None
            }
            None => None,
        }
    }

    fn put_cached(&self, client_addr: SocketAddr, value: Option<ResolvedProcessIdentity>) {
        let mut cache = lock_recover(&self.cache);
        cache.insert(
            client_addr,
            CacheEntry {
                value,
                expires_at: Instant::now() + self.cache_ttl,
            },
        );
    }

    fn resolve_uncached(&self, client_addr: SocketAddr) -> Option<ResolvedProcessIdentity> {
        let (pid, raw_name, _exact_socket_match) =
            resolve_with_native_socket_owner(client_addr, self.lookup_timeout)?;
        Some(build_process_identity(pid, raw_name, self.lookup_timeout))
    }
}

impl Default for ProcessAttribution {
    fn default() -> Self {
        Self::new(true, DEFAULT_LOOKUP_TIMEOUT, DEFAULT_CACHE_TTL)
    }
}

fn as_process_identity(resolved: Option<ResolvedProcessIdentity>) -> ProcessIdentity {
    let Some(identity) = resolved else {
        return ProcessIdentity::default();
    };

    ProcessIdentity::new(identity.bundle_id, Some(identity.name))
}

fn build_process_identity(
    pid: u32,
    raw_name: String,
    timeout: Duration,
) -> ResolvedProcessIdentity {
    let executable = lookup_executable(pid, timeout);
    let name = normalize_process_name(raw_name, executable.as_deref());
    let bundle_id = process_bundle_id_from_executable(executable.as_deref());
    let inferred_type = classify_app_type(name.as_str(), executable.as_deref());

    if should_attempt_parent_walk(name.as_str(), inferred_type.as_str()) {
        if let Some(parent_identity) = resolve_parent_process_identity(pid, timeout) {
            return parent_identity;
        }
    }

    ResolvedProcessIdentity { name, bundle_id }
}

fn resolve_with_native_socket_owner(
    client_addr: SocketAddr,
    timeout: Duration,
) -> Option<(u32, String, bool)> {
    #[cfg(target_os = "macos")]
    {
        resolve_with_macos_libproc(client_addr, timeout)
    }

    #[cfg(target_os = "linux")]
    {
        resolve_with_linux_inet_diag(client_addr, timeout)
    }

    #[cfg(target_os = "windows")]
    {
        resolve_with_windows_tcp_table(client_addr, timeout)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = client_addr;
        let _ = timeout;
        None
    }
}

fn native_process_name_for_pid(pid: u32, timeout: Duration) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        macos_process_name_for_pid(pid, timeout)
    }

    #[cfg(target_os = "linux")]
    {
        let _ = timeout;
        linux_process_name_for_pid(pid)
    }

    #[cfg(target_os = "windows")]
    {
        let _ = timeout;
        windows_process_name_for_pid(pid)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = pid;
        let _ = timeout;
        None
    }
}

fn should_attempt_parent_walk(name: &str, app_type: &str) -> bool {
    if matches!(app_type, "service") || is_system_helper_process_name(name) {
        return true;
    }
    if is_generic_shell_process(name) {
        return true;
    }
    app_type == "unknown" && is_low_signal_process_name(name)
}

fn is_low_signal_process_name(name: &str) -> bool {
    let trimmed = name.trim();
    trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("unknown")
        || looks_like_version_token(trimmed)
}

fn is_system_helper_process_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "webkit.networking",
        "webkit.webcontent",
        "webkit.gpu",
        "nsurlsessiond",
        "cfnetwork",
        "networkserviceproxy",
        "xpcproxy",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_generic_shell_process(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "sh" | "bash" | "zsh" | "fish" | "node" | "python" | "npm" | "pnpm" | "yarn" | "cargo"
    )
}

fn is_responsible_parent_candidate(name: &str, executable: Option<&str>) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("soth") {
        return false;
    }
    if is_system_helper_process_name(trimmed) {
        return false;
    }

    let app_type = classify_app_type(trimmed, executable);
    if matches!(app_type.as_str(), "browser" | "editor" | "desktop_app") {
        return true;
    }
    if app_type == "cli" {
        return !is_generic_shell_process(trimmed);
    }

    false
}

fn resolve_parent_process_identity(pid: u32, timeout: Duration) -> Option<ResolvedProcessIdentity> {
    let table = load_process_table(timeout)?;

    let per_hop_timeout = timeout
        .checked_div(8)
        .unwrap_or_else(|| Duration::from_millis(25))
        .max(Duration::from_millis(15))
        .min(Duration::from_millis(100));

    let mut current_pid = pid;
    for _ in 0..MAX_PARENT_WALK_DEPTH {
        let parent_pid = table.get(&current_pid)?.ppid;
        if parent_pid == 0 || parent_pid == current_pid {
            break;
        }

        let parent_row = table.get(&parent_pid)?;
        let parent_executable = lookup_executable(parent_pid, per_hop_timeout);
        let parent_name =
            normalize_process_name(parent_row.name.clone(), parent_executable.as_deref());
        let parent_bundle_id = process_bundle_id_from_executable(parent_executable.as_deref());

        if is_responsible_parent_candidate(parent_name.as_str(), parent_executable.as_deref()) {
            return Some(ResolvedProcessIdentity {
                name: parent_name,
                bundle_id: parent_bundle_id,
            });
        }

        current_pid = parent_pid;
    }

    None
}

fn load_process_table(timeout: Duration) -> Option<HashMap<u32, ProcessTableRow>> {
    #[cfg(target_os = "macos")]
    {
        load_macos_process_table(timeout)
    }

    #[cfg(target_os = "linux")]
    {
        load_linux_process_table(timeout)
    }

    #[cfg(target_os = "windows")]
    {
        let _ = timeout;
        load_windows_process_table()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = timeout;
        None
    }
}

fn normalize_process_name(raw_name: String, executable: Option<&str>) -> String {
    let trimmed = raw_name.trim();
    if !trimmed.is_empty() && !looks_like_version_token(trimmed) {
        return trimmed.to_string();
    }

    if let Some(candidate) = process_name_from_executable(executable) {
        if !looks_like_version_token(candidate.as_str()) {
            return candidate;
        }
    }

    "unknown".to_string()
}

fn process_name_from_executable(executable: Option<&str>) -> Option<String> {
    let executable = executable?.trim();
    if executable.is_empty() {
        return None;
    }

    let mut candidate = if executable.contains('/') {
        executable.rsplit('/').next().unwrap_or(executable).trim()
    } else if executable.contains('\\') {
        executable.rsplit('\\').next().unwrap_or(executable).trim()
    } else {
        executable
            .split_whitespace()
            .next()
            .unwrap_or(executable)
            .trim()
    }
    .trim_matches('"')
    .trim();

    if candidate.is_empty() {
        return None;
    }

    if candidate.ends_with(".app") {
        candidate = candidate.trim_end_matches(".app").trim();
    }
    if candidate.ends_with(".exe") {
        candidate = candidate.trim_end_matches(".exe").trim();
    }

    if candidate.is_empty() {
        None
    } else {
        Some(candidate.to_string())
    }
}

fn looks_like_version_token(value: &str) -> bool {
    let value = value.trim().trim_start_matches(['v', 'V']);
    if value.is_empty() || !value.contains('.') {
        return false;
    }

    let mut saw_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            saw_digit = true;
            continue;
        }

        if matches!(ch, '.' | '-' | '_' | '+') {
            continue;
        }

        return false;
    }

    saw_digit
}

fn lookup_executable(pid: u32, timeout: Duration) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let _ = timeout;
        lookup_executable_macos(pid)
    }

    #[cfg(target_os = "linux")]
    {
        let path = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
        if let Ok(target) = std::fs::read_link(path) {
            let value = target.to_string_lossy().trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        let _ = timeout;
        lookup_executable_windows(pid)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = pid;
        let _ = timeout;
        None
    }
}

fn classify_app_type(name: &str, executable: Option<&str>) -> String {
    let mut haystack = name.to_ascii_lowercase();
    if let Some(exec) = executable {
        haystack.push(' ');
        haystack.push_str(exec.to_ascii_lowercase().as_str());
    }

    let contains_any = |items: &[&str]| items.iter().any(|item| haystack.contains(item));

    if contains_any(&[
        "chrome", "firefox", "safari", "edge", "brave", "arc", "opera", "chromium",
    ]) {
        return "browser".to_string();
    }

    if contains_any(&[
        "terminal", "bash", "zsh", "fish", "sh ", "python", "node", "npm", "pnpm", "yarn", "cargo",
        "go ",
    ]) {
        return "cli".to_string();
    }

    if contains_any(&[
        "cursor",
        "code",
        "windsurf",
        "jetbrains",
        "zed",
        "xcode",
        "vim",
        "nvim",
    ]) {
        return "editor".to_string();
    }

    if contains_any(&["service", "daemon", "systemd", "launchd"]) {
        return "service".to_string();
    }

    if executable
        .map(|value| value.to_ascii_lowercase().contains(".app/"))
        .unwrap_or(false)
    {
        return "desktop_app".to_string();
    }

    "unknown".to_string()
}

fn process_bundle_id_from_executable(path: Option<&str>) -> Option<String> {
    let path = path?;
    node_package_id_from_executable_path(path)
        .or_else(|| macos_bundle_id_from_executable_path(path))
}

fn node_package_id_from_executable_path(path: &str) -> Option<String> {
    let normalized_path = path.replace('\\', "/");
    let lower = normalized_path.to_ascii_lowercase();
    let marker = "/node_modules/";
    let mut offset = 0usize;

    while let Some(found) = lower[offset..].find(marker) {
        let marker_start = offset + found;
        if let Some(parent_package) =
            scoped_parent_package_before_node_modules(&normalized_path, marker_start)
        {
            return Some(parent_package);
        }

        let start = marker_start + marker.len();
        let remainder = &normalized_path[start..];
        let mut segments = remainder.split('/');
        let first = segments.next().map(str::trim).unwrap_or_default();
        if first.is_empty() || first.starts_with('.') {
            offset = start;
            continue;
        }

        if first.starts_with('@') {
            let second = segments
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if let Some(second) = second {
                return Some(format!(
                    "{}/{}",
                    first.to_ascii_lowercase(),
                    second.to_ascii_lowercase()
                ));
            }
            offset = start;
            continue;
        }

        return Some(first.to_ascii_lowercase());
    }

    None
}

fn scoped_parent_package_before_node_modules(path: &str, marker_start: usize) -> Option<String> {
    let prefix = path.get(..marker_start)?;
    let mut segments = prefix.rsplit('/');
    let package = segments.next().map(str::trim).unwrap_or_default();
    let scope = segments.next().map(str::trim).unwrap_or_default();
    if package.is_empty() || !scope.starts_with('@') {
        return None;
    }

    Some(format!(
        "{}/{}",
        scope.to_ascii_lowercase(),
        package.to_ascii_lowercase()
    ))
}

fn macos_bundle_id_from_executable_path(path: &str) -> Option<String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        return None;
    }

    #[cfg(target_os = "macos")]
    {
        let normalized_path = path.replace('\\', "/");

        if let Some(bundle_id) =
            macos_bundle_id_from_bundle_marker(normalized_path.as_str(), ".app")
        {
            return Some(bundle_id);
        }
        if let Some(bundle_id) =
            macos_bundle_id_from_bundle_marker(normalized_path.as_str(), ".xpc")
        {
            return Some(bundle_id);
        }

        let leaf = normalized_path
            .rsplit('/')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_default();
        if looks_like_bundle_id(leaf) {
            return Some(leaf.to_string());
        }

        None
    }
}

#[cfg(target_os = "macos")]
fn macos_bundle_id_from_bundle_marker(path: &str, marker: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let idx = lower.find(marker)?;
    let bundle_root = format!("{}{}", &path[..idx], marker);
    read_macos_bundle_identifier(bundle_root.as_str())
}

#[cfg(target_os = "macos")]
fn read_macos_bundle_identifier(bundle_root: &str) -> Option<String> {
    use std::ffi::{c_char, c_void, CStr, CString};

    type CFAllocatorRef = *const c_void;
    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFURLRef = *const c_void;
    type CFBundleRef = *const c_void;
    type CFStringEncoding = u32;
    type CFURLPathStyle = i32;
    type Boolean = u8;
    type CFIndex = isize;

    const K_CFSTRING_ENCODING_UTF8: CFStringEncoding = 0x0800_0100;
    const K_CFURL_POSIX_PATH_STYLE: CFURLPathStyle = 0;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFAllocatorDefault: CFAllocatorRef;
        fn CFStringCreateWithCString(
            alloc: CFAllocatorRef,
            cStr: *const c_char,
            encoding: CFStringEncoding,
        ) -> CFStringRef;
        fn CFURLCreateWithFileSystemPath(
            allocator: CFAllocatorRef,
            filePath: CFStringRef,
            pathStyle: CFURLPathStyle,
            isDirectory: Boolean,
        ) -> CFURLRef;
        fn CFBundleCreate(allocator: CFAllocatorRef, bundleURL: CFURLRef) -> CFBundleRef;
        fn CFBundleGetIdentifier(bundle: CFBundleRef) -> CFStringRef;
        fn CFStringGetCString(
            theString: CFStringRef,
            buffer: *mut c_char,
            bufferSize: CFIndex,
            encoding: CFStringEncoding,
        ) -> Boolean;
        fn CFRelease(cf: CFTypeRef);
    }

    let c_path = CString::new(bundle_root).ok()?;

    unsafe {
        let cf_path = CFStringCreateWithCString(
            kCFAllocatorDefault,
            c_path.as_ptr(),
            K_CFSTRING_ENCODING_UTF8,
        );
        if cf_path.is_null() {
            return None;
        }

        let cf_url = CFURLCreateWithFileSystemPath(
            kCFAllocatorDefault,
            cf_path,
            K_CFURL_POSIX_PATH_STYLE,
            1,
        );
        CFRelease(cf_path as CFTypeRef);
        if cf_url.is_null() {
            return None;
        }

        let cf_bundle = CFBundleCreate(kCFAllocatorDefault, cf_url);
        CFRelease(cf_url as CFTypeRef);
        if cf_bundle.is_null() {
            return None;
        }

        let cf_identifier = CFBundleGetIdentifier(cf_bundle);
        let result = if cf_identifier.is_null() {
            None
        } else {
            let mut buffer = vec![0i8; 512];
            if CFStringGetCString(
                cf_identifier,
                buffer.as_mut_ptr(),
                buffer.len() as CFIndex,
                K_CFSTRING_ENCODING_UTF8,
            ) == 0
            {
                None
            } else {
                CStr::from_ptr(buffer.as_ptr())
                    .to_str()
                    .ok()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
            }
        };

        CFRelease(cf_bundle as CFTypeRef);
        result
    }
}

fn looks_like_bundle_id(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.matches('.').count() < 2 {
        return false;
    }

    let parts = trimmed.split('.').collect::<Vec<_>>();
    if !matches!(
        parts.first().copied(),
        Some("com" | "org" | "net" | "io" | "app" | "me" | "co" | "dev")
    ) {
        return false;
    }

    parts.iter().all(|segment| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    })
}

#[cfg(target_os = "macos")]
fn lookup_executable_macos(pid: u32) -> Option<String> {
    use libc::{c_int, c_void};

    const PROC_PIDPATHINFO_MAXSIZE: usize = 4 * 1024;

    unsafe extern "C" {
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    }

    let mut buf = [0u8; PROC_PIDPATHINFO_MAXSIZE];
    let written = unsafe {
        proc_pidpath(
            pid as c_int,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
        )
    };
    if written <= 0 {
        return None;
    }

    let len = buf
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(written as usize);
    let value = String::from_utf8_lossy(&buf[..len]).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(target_os = "macos")]
fn macos_process_name_for_pid(pid: u32, _timeout: Duration) -> Option<String> {
    let info = macos_bsd_info(pid)?;
    decode_macos_proc_name(&info.pbi_name)
        .or_else(|| decode_macos_proc_name(&info.pbi_comm))
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
fn resolve_with_macos_libproc(
    client_addr: SocketAddr,
    timeout: Duration,
) -> Option<(u32, String, bool)> {
    let deadline = Instant::now() + timeout;
    let self_pid = std::process::id();

    let pids = macos_list_all_pids(deadline)?;
    let mut generic_match: Option<(u32, String, bool)> = None;

    for pid in pids {
        if Instant::now() >= deadline {
            break;
        }
        if pid == 0 || pid == self_pid {
            continue;
        }

        let fds = match macos_list_process_fds(pid, deadline) {
            Some(fds) => fds,
            None => continue,
        };

        for fd in fds {
            if fd.proc_fdtype != macos_native::PROX_FDTYPE_SOCKET {
                continue;
            }

            let socket_info = match macos_socket_fdinfo(pid, fd.proc_fd) {
                Some(info) => info,
                None => continue,
            };

            let (local_ip, local_port) = match macos_extract_local_socket_endpoint(&socket_info) {
                Some(endpoint) => endpoint,
                None => continue,
            };

            if local_port != client_addr.port() {
                continue;
            }

            let raw_name = macos_process_name_for_pid(pid, timeout)
                .or_else(|| process_name_from_executable(lookup_executable_macos(pid).as_deref()))
                .unwrap_or_else(|| "unknown".to_string());

            if ip_matches(local_ip, client_addr.ip()) {
                return Some((pid, raw_name, true));
            }

            if generic_match.is_none() {
                generic_match = Some((pid, raw_name, false));
            }
        }
    }

    generic_match
}

#[cfg(target_os = "macos")]
fn load_macos_process_table(timeout: Duration) -> Option<HashMap<u32, ProcessTableRow>> {
    let deadline = Instant::now() + timeout;
    let mut out = HashMap::new();
    for pid in macos_list_all_pids(deadline)? {
        if Instant::now() >= deadline {
            break;
        }
        if pid == 0 {
            continue;
        }

        let Some(info) = macos_bsd_info(pid) else {
            continue;
        };

        let name = decode_macos_proc_name(&info.pbi_name)
            .or_else(|| decode_macos_proc_name(&info.pbi_comm))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        out.insert(
            pid,
            ProcessTableRow {
                ppid: info.pbi_ppid,
                name,
            },
        );
    }

    Some(out)
}

#[cfg(target_os = "macos")]
fn decode_macos_proc_name(raw: &[i8]) -> Option<String> {
    let len = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
    if len == 0 {
        return None;
    }

    let bytes = raw[..len]
        .iter()
        .map(|&byte| byte as u8)
        .collect::<Vec<_>>();
    let value = String::from_utf8_lossy(bytes.as_slice()).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(target_os = "macos")]
fn macos_bsd_info(pid: u32) -> Option<macos_native::ProcBsdInfo> {
    use libc::c_int;
    use std::mem::size_of;

    let mut info = macos_native::ProcBsdInfo::default();
    let written = unsafe {
        macos_native::proc_pidinfo(
            pid as c_int,
            macos_native::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut macos_native::ProcBsdInfo).cast(),
            size_of::<macos_native::ProcBsdInfo>() as c_int,
        )
    };
    if written < size_of::<macos_native::ProcBsdInfo>() as c_int {
        None
    } else {
        Some(info)
    }
}

#[cfg(target_os = "macos")]
fn macos_list_all_pids(deadline: Instant) -> Option<Vec<u32>> {
    use libc::{c_int, c_void};

    let mut capacity = 4096usize;
    loop {
        if Instant::now() >= deadline {
            return None;
        }

        let mut pids = vec![0i32; capacity];
        let count = unsafe {
            macos_native::proc_listallpids(
                pids.as_mut_ptr() as *mut c_void,
                (pids.len() * std::mem::size_of::<c_int>()) as c_int,
            )
        };
        if count <= 0 {
            return None;
        }

        if count as usize >= capacity {
            capacity = capacity.saturating_mul(2);
            continue;
        }

        pids.truncate(count as usize);
        return Some(
            pids.into_iter()
                .filter(|pid| *pid > 0)
                .map(|pid| pid as u32)
                .collect::<Vec<_>>(),
        );
    }
}

#[cfg(target_os = "macos")]
fn macos_list_process_fds(pid: u32, deadline: Instant) -> Option<Vec<macos_native::ProcFdInfo>> {
    use libc::c_int;

    let mut capacity = 128usize;
    loop {
        if Instant::now() >= deadline {
            return None;
        }

        let mut entries = vec![macos_native::ProcFdInfo::default(); capacity];
        let written = unsafe {
            macos_native::proc_pidinfo(
                pid as c_int,
                macos_native::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                (entries.len() * std::mem::size_of::<macos_native::ProcFdInfo>()) as c_int,
            )
        };

        if written <= 0 {
            return None;
        }

        let count = written as usize / std::mem::size_of::<macos_native::ProcFdInfo>();
        if count >= capacity {
            capacity = capacity.saturating_mul(2);
            continue;
        }

        entries.truncate(count);
        return Some(entries);
    }
}

#[cfg(target_os = "macos")]
fn macos_socket_fdinfo(pid: u32, fd: i32) -> Option<macos_native::SocketFdInfoPrefix> {
    use libc::c_int;

    let mut raw = [0u8; 2048];
    let written = unsafe {
        macos_native::proc_pidfdinfo(
            pid as c_int,
            fd,
            macos_native::PROC_PIDFDSOCKETINFO,
            raw.as_mut_ptr().cast(),
            raw.len() as c_int,
        )
    };

    if written < std::mem::size_of::<macos_native::SocketFdInfoPrefix>() as c_int {
        return None;
    }

    Some(unsafe { (raw.as_ptr() as *const macos_native::SocketFdInfoPrefix).read_unaligned() })
}

#[cfg(target_os = "macos")]
fn macos_extract_local_socket_endpoint(
    info: &macos_native::SocketFdInfoPrefix,
) -> Option<(IpAddr, u16)> {
    let sock = unsafe {
        match info.psi.soi_kind {
            macos_native::SOCKINFO_IN => info.psi.soi_proto.pri_in,
            macos_native::SOCKINFO_TCP => info.psi.soi_proto.pri_tcp.tcpsi_ini,
            _ => return None,
        }
    };

    let local_port = u16::from_be(sock.insi_lport as u16);
    if local_port == 0 {
        return None;
    }

    if sock.insi_vflag & macos_native::INI_IPV4 != 0 {
        let addr = unsafe { sock.insi_laddr.ina_46.i46a_addr4.s_addr };
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr));
        return Some((IpAddr::V4(ip), local_port));
    }

    if sock.insi_vflag & macos_native::INI_IPV6 != 0 {
        let addr = unsafe { sock.insi_laddr.ina_6.s6_addr };
        let ip = std::net::Ipv6Addr::from(addr);
        return Some((IpAddr::V6(ip), local_port));
    }

    None
}

#[cfg(target_os = "macos")]
mod macos_native {
    use libc::{c_int, c_void, gid_t, in6_addr, in_addr, off_t, uid_t, MAXCOMLEN};

    pub const PROC_PIDLISTFDS: c_int = 1;
    pub const PROC_PIDTBSDINFO: c_int = 3;
    pub const PROC_PIDFDSOCKETINFO: c_int = 3;

    pub const PROX_FDTYPE_SOCKET: u32 = 2;

    pub const SOCKINFO_IN: i32 = 1;
    pub const SOCKINFO_TCP: i32 = 2;

    pub const INI_IPV4: u8 = 0x1;
    pub const INI_IPV6: u8 = 0x2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProcBsdInfo {
        pub pbi_flags: u32,
        pub pbi_status: u32,
        pub pbi_xstatus: u32,
        pub pbi_pid: u32,
        pub pbi_ppid: u32,
        pub pbi_uid: uid_t,
        pub pbi_gid: gid_t,
        pub pbi_ruid: uid_t,
        pub pbi_rgid: gid_t,
        pub pbi_svuid: uid_t,
        pub pbi_svgid: gid_t,
        pub rfu_1: u32,
        pub pbi_comm: [i8; MAXCOMLEN as usize],
        pub pbi_name: [i8; (2 * MAXCOMLEN) as usize],
        pub pbi_nfiles: u32,
        pub pbi_pgid: u32,
        pub pbi_pjobc: u32,
        pub e_tdev: u32,
        pub e_tpgid: u32,
        pub pbi_nice: i32,
        pub pbi_start_tvsec: u64,
        pub pbi_start_tvusec: u64,
    }

    impl Default for ProcBsdInfo {
        fn default() -> Self {
            Self {
                pbi_flags: 0,
                pbi_status: 0,
                pbi_xstatus: 0,
                pbi_pid: 0,
                pbi_ppid: 0,
                pbi_uid: 0,
                pbi_gid: 0,
                pbi_ruid: 0,
                pbi_rgid: 0,
                pbi_svuid: 0,
                pbi_svgid: 0,
                rfu_1: 0,
                pbi_comm: [0; MAXCOMLEN as usize],
                pbi_name: [0; (2 * MAXCOMLEN) as usize],
                pbi_nfiles: 0,
                pbi_pgid: 0,
                pbi_pjobc: 0,
                e_tdev: 0,
                e_tpgid: 0,
                pbi_nice: 0,
                pbi_start_tvsec: 0,
                pbi_start_tvusec: 0,
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ProcFdInfo {
        pub proc_fd: i32,
        pub proc_fdtype: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ProcFileInfo {
        pub fi_openflags: u32,
        pub fi_status: u32,
        pub fi_offset: off_t,
        pub fi_type: i32,
        pub fi_guardflags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct VinfoStat {
        pub vst_dev: u32,
        pub vst_mode: u16,
        pub vst_nlink: u16,
        pub vst_ino: u64,
        pub vst_uid: uid_t,
        pub vst_gid: gid_t,
        pub vst_atime: i64,
        pub vst_atimensec: i64,
        pub vst_mtime: i64,
        pub vst_mtimensec: i64,
        pub vst_ctime: i64,
        pub vst_ctimensec: i64,
        pub vst_birthtime: i64,
        pub vst_birthtimensec: i64,
        pub vst_size: off_t,
        pub vst_blocks: i64,
        pub vst_blksize: i32,
        pub vst_flags: u32,
        pub vst_gen: u32,
        pub vst_rdev: u32,
        pub vst_qspare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct SockbufInfo {
        pub sbi_cc: u32,
        pub sbi_hiwat: u32,
        pub sbi_mbcnt: u32,
        pub sbi_mbmax: u32,
        pub sbi_lowat: u32,
        pub sbi_flags: i16,
        pub sbi_timeo: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct In4In6Addr {
        pub i46a_pad32: [u32; 3],
        pub i46a_addr4: in_addr,
    }

    impl Default for In4In6Addr {
        fn default() -> Self {
            Self {
                i46a_pad32: [0; 3],
                i46a_addr4: in_addr { s_addr: 0 },
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union InSockAddrUnion {
        pub ina_46: In4In6Addr,
        pub ina_6: in6_addr,
    }

    impl Default for InSockAddrUnion {
        fn default() -> Self {
            Self {
                ina_46: In4In6Addr::default(),
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InSockInfo {
        pub insi_fport: i32,
        pub insi_lport: i32,
        pub insi_gencnt: u64,
        pub insi_flags: u32,
        pub insi_flow: u32,
        pub insi_vflag: u8,
        pub insi_ip_ttl: u8,
        pub rfu_1: u32,
        pub insi_faddr: InSockAddrUnion,
        pub insi_laddr: InSockAddrUnion,
        pub insi_v4: InSockInfoV4,
        pub insi_v6: InSockInfoV6,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InSockInfoV4 {
        pub in4_tos: u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InSockInfoV6 {
        pub in6_hlim: u8,
        pub in6_cksum: i32,
        pub in6_ifindex: u16,
        pub in6_hops: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct TcpSockInfo {
        pub tcpsi_ini: InSockInfo,
        pub tcpsi_state: i32,
        pub tcpsi_timer: [i32; 4],
        pub tcpsi_mss: i32,
        pub tcpsi_flags: u32,
        pub rfu_1: u32,
        pub tcpsi_tp: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union SocketProtoPrefix {
        pub pri_in: InSockInfo,
        pub pri_tcp: TcpSockInfo,
    }

    impl Default for SocketProtoPrefix {
        fn default() -> Self {
            Self {
                pri_in: InSockInfo::default(),
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct SocketInfoPrefix {
        pub soi_stat: VinfoStat,
        pub soi_so: u64,
        pub soi_pcb: u64,
        pub soi_type: i32,
        pub soi_protocol: i32,
        pub soi_family: i32,
        pub soi_options: i16,
        pub soi_linger: i16,
        pub soi_state: i16,
        pub soi_qlen: i16,
        pub soi_incqlen: i16,
        pub soi_qlimit: i16,
        pub soi_timeo: i16,
        pub soi_error: u16,
        pub soi_oobmark: u32,
        pub soi_rcv: SockbufInfo,
        pub soi_snd: SockbufInfo,
        pub soi_kind: i32,
        pub rfu_1: u32,
        pub soi_proto: SocketProtoPrefix,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct SocketFdInfoPrefix {
        pub pfi: ProcFileInfo,
        pub psi: SocketInfoPrefix,
    }

    unsafe extern "C" {
        pub fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
        pub fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
        pub fn proc_pidfdinfo(
            pid: c_int,
            fd: c_int,
            flavor: c_int,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
    }
}

#[cfg(target_os = "linux")]
fn resolve_with_linux_inet_diag(
    client_addr: SocketAddr,
    timeout: Duration,
) -> Option<(u32, String, bool)> {
    if timeout.is_zero() {
        return None;
    }

    let deadline = Instant::now() + timeout;

    let mut matches = Vec::new();
    if let Some(found) = linux_find_inode_via_inet_diag(client_addr, libc::AF_INET as u8, deadline)
    {
        matches.push(found);
    }
    if let Some(found) = linux_find_inode_via_inet_diag(client_addr, libc::AF_INET6 as u8, deadline)
    {
        matches.push(found);
    }

    let best = matches.into_iter().find(|(_, exact)| *exact).or_else(|| {
        linux_find_inode_via_inet_diag(client_addr, libc::AF_INET as u8, deadline)
            .or_else(|| linux_find_inode_via_inet_diag(client_addr, libc::AF_INET6 as u8, deadline))
    })?;

    let pid = linux_find_pid_by_socket_inode(best.0, deadline)?;
    let raw_name = linux_process_name_for_pid(pid).unwrap_or_else(|| "unknown".to_string());
    Some((pid, raw_name, best.1))
}

#[cfg(target_os = "linux")]
fn linux_find_inode_via_inet_diag(
    client_addr: SocketAddr,
    family: u8,
    deadline: Instant,
) -> Option<(u32, bool)> {
    use libc::{
        c_void, recv, send, sockaddr, sockaddr_nl, socket, AF_NETLINK, NETLINK_SOCK_DIAG,
        SOCK_DGRAM,
    };

    let fd = unsafe { socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG) };
    if fd < 0 {
        return None;
    }

    let result = (|| {
        if !linux_configure_socket_deadline(fd, deadline) {
            return None;
        }

        let mut local = unsafe { std::mem::zeroed::<sockaddr_nl>() };
        local.nl_family = AF_NETLINK as u16;
        local.nl_pid = 0;
        local.nl_groups = 0;

        let bind_ret = unsafe {
            libc::bind(
                fd,
                (&local as *const sockaddr_nl).cast::<sockaddr>(),
                std::mem::size_of::<sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bind_ret != 0 {
            return None;
        }

        let req = linux_native::InetDiagReqV2::new(family);
        let header = linux_native::NlMsgHdr {
            nlmsg_len: (std::mem::size_of::<linux_native::NlMsgHdr>()
                + std::mem::size_of::<linux_native::InetDiagReqV2>()) as u32,
            nlmsg_type: linux_native::SOCK_DIAG_BY_FAMILY,
            nlmsg_flags: linux_native::NLM_F_REQUEST | linux_native::NLM_F_DUMP,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };

        let mut request_bytes = vec![0u8; header.nlmsg_len as usize];
        unsafe {
            (request_bytes.as_mut_ptr() as *mut linux_native::NlMsgHdr).write_unaligned(header);
            (request_bytes
                .as_mut_ptr()
                .add(std::mem::size_of::<linux_native::NlMsgHdr>())
                as *mut linux_native::InetDiagReqV2)
                .write_unaligned(req);
        }

        let sent = unsafe {
            send(
                fd,
                request_bytes.as_ptr().cast::<c_void>(),
                request_bytes.len(),
                0,
            )
        };
        if sent < 0 {
            return None;
        }

        let mut generic: Option<(u32, bool)> = None;
        let mut recv_buf = vec![0u8; 64 * 1024];

        loop {
            if Instant::now() >= deadline {
                break;
            }

            let size = unsafe {
                recv(
                    fd,
                    recv_buf.as_mut_ptr().cast::<c_void>(),
                    recv_buf.len(),
                    0,
                )
            };
            if size <= 0 {
                break;
            }

            let mut offset = 0usize;
            let size = size as usize;
            while offset + std::mem::size_of::<linux_native::NlMsgHdr>() <= size {
                let hdr = unsafe {
                    (recv_buf.as_ptr().add(offset) as *const linux_native::NlMsgHdr)
                        .read_unaligned()
                };
                if hdr.nlmsg_len < std::mem::size_of::<linux_native::NlMsgHdr>() as u32 {
                    break;
                }

                let msg_end = offset + hdr.nlmsg_len as usize;
                if msg_end > size {
                    break;
                }

                if hdr.nlmsg_type == linux_native::NLMSG_DONE {
                    return generic;
                }
                if hdr.nlmsg_type == linux_native::NLMSG_ERROR {
                    return None;
                }

                let payload_offset = offset + std::mem::size_of::<linux_native::NlMsgHdr>();
                let payload_len =
                    hdr.nlmsg_len as usize - std::mem::size_of::<linux_native::NlMsgHdr>();
                if payload_len >= std::mem::size_of::<linux_native::InetDiagMsg>() {
                    let diag = unsafe {
                        (recv_buf.as_ptr().add(payload_offset) as *const linux_native::InetDiagMsg)
                            .read_unaligned()
                    };
                    let local_port = u16::from_be(diag.id.idiag_sport);
                    if local_port == client_addr.port() {
                        let local_ip = linux_diag_local_ip(&diag)?;
                        if ip_matches(local_ip, client_addr.ip()) {
                            return Some((diag.idiag_inode, true));
                        }
                        if generic.is_none() {
                            generic = Some((diag.idiag_inode, false));
                        }
                    }
                }

                offset += linux_native::nlmsg_align(hdr.nlmsg_len as usize);
            }
        }

        generic
    })();

    unsafe {
        libc::close(fd);
    }

    result
}

#[cfg(target_os = "linux")]
fn linux_configure_socket_deadline(fd: i32, deadline: Instant) -> bool {
    use libc::{c_void, setsockopt, socklen_t, timeval, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO};

    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return false;
    }

    let mut tv = timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    if tv.tv_sec == 0 && tv.tv_usec == 0 {
        tv.tv_usec = 1_000;
    }

    let tv_len = std::mem::size_of::<timeval>() as socklen_t;
    let tv_ptr = (&tv as *const timeval).cast::<c_void>();

    let recv_ok = unsafe { setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv_ptr, tv_len) } == 0;
    let send_ok = unsafe { setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, tv_ptr, tv_len) } == 0;
    recv_ok && send_ok
}

#[cfg(target_os = "linux")]
fn linux_diag_local_ip(diag: &linux_native::InetDiagMsg) -> Option<IpAddr> {
    if diag.idiag_family == libc::AF_INET as u8 {
        let addr = u32::from_be(diag.id.idiag_src[0]);
        return Some(IpAddr::V4(std::net::Ipv4Addr::from(addr)));
    }

    if diag.idiag_family == libc::AF_INET6 as u8 {
        let mut octets = [0u8; 16];
        for (idx, part) in diag.id.idiag_src.iter().copied().enumerate() {
            octets[idx * 4..(idx + 1) * 4].copy_from_slice(&part.to_be_bytes());
        }
        return Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
    }

    None
}

#[cfg(target_os = "linux")]
fn linux_find_pid_by_socket_inode(inode: u32, deadline: Instant) -> Option<u32> {
    let proc_dir = std::path::Path::new("/proc");
    let self_pid = std::process::id();

    for entry in std::fs::read_dir(proc_dir).ok()? {
        if Instant::now() >= deadline {
            break;
        }

        let entry = entry.ok()?;
        let file_name = entry.file_name();
        let pid = file_name.to_str()?.parse::<u32>().ok()?;
        if pid == self_pid {
            continue;
        }

        let fd_dir = entry.path().join("fd");
        let Ok(fd_entries) = std::fs::read_dir(fd_dir) else {
            continue;
        };

        for fd_entry in fd_entries {
            if Instant::now() >= deadline {
                break;
            }
            let fd_entry = match fd_entry {
                Ok(value) => value,
                Err(_) => continue,
            };

            let Ok(link_target) = std::fs::read_link(fd_entry.path()) else {
                continue;
            };
            let link_text = link_target.to_string_lossy();
            if parse_linux_socket_inode(link_text.as_ref()) == Some(inode) {
                return Some(pid);
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn parse_linux_socket_inode(link_text: &str) -> Option<u32> {
    let prefix = "socket:[";
    let suffix = "]";
    if !link_text.starts_with(prefix) || !link_text.ends_with(suffix) {
        return None;
    }

    link_text[prefix.len()..link_text.len() - suffix.len()]
        .parse::<u32>()
        .ok()
}

#[cfg(target_os = "linux")]
fn linux_process_name_for_pid(pid: u32) -> Option<String> {
    let comm_path = format!("/proc/{pid}/comm");
    let text = std::fs::read_to_string(comm_path).ok()?;
    let value = text.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(target_os = "linux")]
fn load_linux_process_table(timeout: Duration) -> Option<HashMap<u32, ProcessTableRow>> {
    let deadline = Instant::now() + timeout;
    let mut out = HashMap::new();

    for entry in std::fs::read_dir("/proc").ok()? {
        if Instant::now() >= deadline {
            break;
        }

        let entry = match entry {
            Ok(value) => value,
            Err(_) => continue,
        };
        let pid = match entry.file_name().to_string_lossy().parse::<u32>() {
            Ok(value) => value,
            Err(_) => continue,
        };

        let stat_path = entry.path().join("stat");
        let stat_text = match std::fs::read_to_string(stat_path) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let Some((name, ppid)) = parse_linux_proc_stat_line(stat_text.as_str()) else {
            continue;
        };

        out.insert(pid, ProcessTableRow { ppid, name });
    }

    Some(out)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_proc_stat_line(line: &str) -> Option<(String, u32)> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close <= open {
        return None;
    }

    let name = line[open + 1..close].trim().to_string();
    if name.is_empty() {
        return None;
    }

    let rest = line.get(close + 1..)?.trim();
    let mut parts = rest.split_whitespace();
    let _state = parts.next()?;
    let ppid = parts.next()?.parse::<u32>().ok()?;

    Some((name, ppid))
}

#[cfg(target_os = "linux")]
mod linux_native {
    use libc::{AF_INET, AF_INET6, IPPROTO_TCP};

    pub const SOCK_DIAG_BY_FAMILY: u16 = 20;

    pub const NLM_F_REQUEST: u16 = 0x0001;
    pub const NLM_F_DUMP: u16 = 0x0300;

    pub const NLMSG_DONE: u16 = 0x0003;
    pub const NLMSG_ERROR: u16 = 0x0002;

    pub const INET_DIAG_NOCOOKIE: u32 = u32::MAX;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct NlMsgHdr {
        pub nlmsg_len: u32,
        pub nlmsg_type: u16,
        pub nlmsg_flags: u16,
        pub nlmsg_seq: u32,
        pub nlmsg_pid: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InetDiagSockId {
        pub idiag_sport: u16,
        pub idiag_dport: u16,
        pub idiag_src: [u32; 4],
        pub idiag_dst: [u32; 4],
        pub idiag_if: u32,
        pub idiag_cookie: [u32; 2],
    }

    impl InetDiagSockId {
        pub fn wildcard() -> Self {
            Self {
                idiag_sport: 0,
                idiag_dport: 0,
                idiag_src: [0; 4],
                idiag_dst: [0; 4],
                idiag_if: 0,
                idiag_cookie: [INET_DIAG_NOCOOKIE, INET_DIAG_NOCOOKIE],
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InetDiagReqV2 {
        pub sdiag_family: u8,
        pub sdiag_protocol: u8,
        pub idiag_ext: u8,
        pub pad: u8,
        pub idiag_states: u32,
        pub id: InetDiagSockId,
    }

    impl InetDiagReqV2 {
        pub fn new(family: u8) -> Self {
            let _ = AF_INET;
            let _ = AF_INET6;
            Self {
                sdiag_family: family,
                sdiag_protocol: IPPROTO_TCP as u8,
                idiag_ext: 0,
                pad: 0,
                idiag_states: u32::MAX,
                id: InetDiagSockId::wildcard(),
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InetDiagMsg {
        pub idiag_family: u8,
        pub idiag_state: u8,
        pub idiag_timer: u8,
        pub idiag_retrans: u8,
        pub id: InetDiagSockId,
        pub idiag_expires: u32,
        pub idiag_rqueue: u32,
        pub idiag_wqueue: u32,
        pub idiag_uid: u32,
        pub idiag_inode: u32,
    }

    pub fn nlmsg_align(value: usize) -> usize {
        const NLM_ALIGNTO: usize = 4;
        (value + NLM_ALIGNTO - 1) & !(NLM_ALIGNTO - 1)
    }
}

#[cfg(target_os = "windows")]
fn resolve_with_windows_tcp_table(
    client_addr: SocketAddr,
    _timeout: Duration,
) -> Option<(u32, String, bool)> {
    let mut generic: Option<(u32, bool)> = None;

    for row in windows_query_tcp4_rows()? {
        let local_port = u16::from_be(row.dw_local_port as u16);
        if local_port != client_addr.port() {
            continue;
        }

        let local_ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(row.dw_local_addr)));
        if ip_matches(local_ip, client_addr.ip()) {
            let raw_name = windows_process_name_for_pid(row.dw_owning_pid)
                .unwrap_or_else(|| "unknown".to_string());
            return Some((row.dw_owning_pid, raw_name, true));
        }

        if generic.is_none() && row.dw_local_addr == 0 {
            generic = Some((row.dw_owning_pid, false));
        }
    }

    for row in windows_query_tcp6_rows()? {
        let local_port = u16::from_be(row.dw_local_port as u16);
        if local_port != client_addr.port() {
            continue;
        }

        let local_ip = IpAddr::V6(std::net::Ipv6Addr::from(row.uc_local_addr));
        if ip_matches(local_ip, client_addr.ip()) {
            let raw_name = windows_process_name_for_pid(row.dw_owning_pid)
                .unwrap_or_else(|| "unknown".to_string());
            return Some((row.dw_owning_pid, raw_name, true));
        }

        if generic.is_none() && row.uc_local_addr.iter().all(|byte| *byte == 0) {
            generic = Some((row.dw_owning_pid, false));
        }
    }

    let (pid, exact) = generic?;
    let raw_name = windows_process_name_for_pid(pid).unwrap_or_else(|| "unknown".to_string());
    Some((pid, raw_name, exact))
}

#[cfg(target_os = "windows")]
fn lookup_executable_windows(pid: u32) -> Option<String> {
    windows_query_process_image_path(pid)
}

#[cfg(target_os = "windows")]
fn windows_process_name_for_pid(pid: u32) -> Option<String> {
    windows_query_process_image_path(pid)
        .as_deref()
        .and_then(|path| process_name_from_executable(Some(path)))
}

#[cfg(target_os = "windows")]
fn windows_query_process_image_path(pid: u32) -> Option<String> {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    type Bool = i32;

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(desired_access: u32, inherit_handle: Bool, process_id: u32) -> Handle;
        fn QueryFullProcessImageNameW(
            process: Handle,
            flags: u32,
            exe_name: *mut u16,
            size: *mut u32,
        ) -> Bool;
        fn CloseHandle(object: Handle) -> Bool;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buffer = vec![0u16; 4096];
    let mut size = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };
    unsafe {
        let _ = CloseHandle(handle);
    }

    if ok == 0 || size == 0 {
        return None;
    }

    let value = String::from_utf16_lossy(&buffer[..size as usize])
        .trim()
        .to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(target_os = "windows")]
fn windows_query_tcp4_rows() -> Option<Vec<windows_native::MibTcpRowOwnerPid>> {
    windows_query_tcp_table::<windows_native::MibTcpRowOwnerPid>(windows_native::AF_INET)
}

#[cfg(target_os = "windows")]
fn windows_query_tcp6_rows() -> Option<Vec<windows_native::MibTcp6RowOwnerPid>> {
    windows_query_tcp_table::<windows_native::MibTcp6RowOwnerPid>(windows_native::AF_INET6)
}

#[cfg(target_os = "windows")]
fn windows_query_tcp_table<Row: Copy>(address_family: u32) -> Option<Vec<Row>> {
    let mut size: u32 = 0;
    let mut result = unsafe {
        windows_native::GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            address_family,
            windows_native::TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != windows_native::ERROR_INSUFFICIENT_BUFFER && result != windows_native::NO_ERROR {
        return None;
    }

    if size == 0 {
        return Some(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    result = unsafe {
        windows_native::GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
            address_family,
            windows_native::TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if result != windows_native::NO_ERROR {
        return None;
    }

    if buffer.len() < std::mem::size_of::<u32>() {
        return None;
    }

    let entry_count = unsafe { (buffer.as_ptr() as *const u32).read_unaligned() } as usize;
    let row_offset = std::mem::size_of::<u32>();
    let row_size = std::mem::size_of::<Row>();
    let required = row_offset.checked_add(entry_count.checked_mul(row_size)?)?;
    if required > buffer.len() {
        return None;
    }

    let mut rows = Vec::with_capacity(entry_count);
    for idx in 0..entry_count {
        let start = row_offset + idx * row_size;
        let row = unsafe { (buffer.as_ptr().add(start) as *const Row).read_unaligned() };
        rows.push(row);
    }

    Some(rows)
}

#[cfg(target_os = "windows")]
fn load_windows_process_table() -> Option<HashMap<u32, ProcessTableRow>> {
    use std::ffi::c_void;

    type Handle = *mut c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
        fn Process32FirstW(snapshot: Handle, entry: *mut windows_native::ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: Handle, entry: *mut windows_native::ProcessEntry32W) -> i32;
        fn CloseHandle(object: Handle) -> i32;
    }

    let snapshot = unsafe { CreateToolhelp32Snapshot(windows_native::TH32CS_SNAPPROCESS, 0) };
    if snapshot == windows_native::INVALID_HANDLE_VALUE {
        return None;
    }

    let mut out = HashMap::new();
    let mut entry = windows_native::ProcessEntry32W::default();
    entry.dw_size = std::mem::size_of::<windows_native::ProcessEntry32W>() as u32;

    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while has_entry {
        let name = windows_native::wide_c_array_to_string(&entry.sz_exe_file)
            .unwrap_or_else(|| "unknown".to_string());
        out.insert(
            entry.th32_process_id,
            ProcessTableRow {
                ppid: entry.th32_parent_process_id,
                name,
            },
        );

        has_entry = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    Some(out)
}

#[cfg(target_os = "windows")]
mod windows_native {
    use std::ffi::c_void;

    pub const AF_INET: u32 = 2;
    pub const AF_INET6: u32 = 23;

    pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;

    pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    pub const NO_ERROR: u32 = 0;

    pub const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    pub const INVALID_HANDLE_VALUE: *mut c_void = (-1isize) as *mut c_void;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct MibTcpRowOwnerPid {
        pub dw_state: u32,
        pub dw_local_addr: u32,
        pub dw_local_port: u32,
        pub dw_remote_addr: u32,
        pub dw_remote_port: u32,
        pub dw_owning_pid: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct MibTcp6RowOwnerPid {
        pub uc_local_addr: [u8; 16],
        pub dw_local_scope_id: u32,
        pub dw_local_port: u32,
        pub uc_remote_addr: [u8; 16],
        pub dw_remote_scope_id: u32,
        pub dw_remote_port: u32,
        pub dw_state: u32,
        pub dw_owning_pid: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProcessEntry32W {
        pub dw_size: u32,
        pub cnt_usage: u32,
        pub th32_process_id: u32,
        pub th32_default_heap_id: usize,
        pub th32_module_id: u32,
        pub cnt_threads: u32,
        pub th32_parent_process_id: u32,
        pub pc_pri_class_base: i32,
        pub dw_flags: u32,
        pub sz_exe_file: [u16; 260],
    }

    impl Default for ProcessEntry32W {
        fn default() -> Self {
            Self {
                dw_size: 0,
                cnt_usage: 0,
                th32_process_id: 0,
                th32_default_heap_id: 0,
                th32_module_id: 0,
                cnt_threads: 0,
                th32_parent_process_id: 0,
                pc_pri_class_base: 0,
                dw_flags: 0,
                sz_exe_file: [0; 260],
            }
        }
    }

    pub fn wide_c_array_to_string(value: &[u16]) -> Option<String> {
        let len = value
            .iter()
            .position(|code| *code == 0)
            .unwrap_or(value.len());
        if len == 0 {
            return None;
        }

        let text = String::from_utf16_lossy(&value[..len]).trim().to_string();
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        pub fn GetExtendedTcpTable(
            tcp_table: *mut c_void,
            tcp_table_size: *mut u32,
            order: i32,
            address_family: u32,
            table_class: u32,
            reserved: u32,
        ) -> u32;
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn lookup_executable_macos(_pid: u32) -> Option<String> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn lookup_executable_windows(_pid: u32) -> Option<String> {
    None
}

fn ip_matches(candidate: IpAddr, target: IpAddr) -> bool {
    if candidate == target {
        return true;
    }

    match (candidate, target) {
        (IpAddr::V6(v6), IpAddr::V4(v4)) | (IpAddr::V4(v4), IpAddr::V6(v6)) => {
            v6.to_ipv4().map(|mapped| mapped == v4).unwrap_or(false)
        }
        _ => false,
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::EdgeRegistry;

    fn home_bundle_json() -> String {
        let path = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .expect("HOME env should be set for process attribution tests")
            .join(".soth")
            .join("registry_bundle_cache.json");
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "expected ~/.soth registry bundle cache at {}: {}",
                path.display(),
                error
            )
        })
    }

    fn registry() -> EdgeRegistry {
        let bundle_json = home_bundle_json();
        EdgeRegistry::from_json_str(&bundle_json).expect("~/.soth registry bundle should parse")
    }

    #[test]
    fn classify_app_type_detects_browser_and_editor_and_cli() {
        assert_eq!(classify_app_type("Google Chrome", None), "browser");
        assert_eq!(classify_app_type("Cursor", None), "editor");
        assert_eq!(classify_app_type("Terminal", None), "cli");
        assert_eq!(classify_app_type("2.1.47", Some("python -m app")), "cli");
        assert_eq!(
            classify_app_type(
                "Unknown",
                Some("/Applications/Figma.app/Contents/MacOS/Figma")
            ),
            "desktop_app"
        );
    }

    #[test]
    fn normalize_process_name_replaces_version_only_name_with_executable_name() {
        let normalized = normalize_process_name("2.1.45".to_string(), Some("terminal"));
        assert_eq!(normalized, "terminal");
    }

    #[test]
    fn normalize_process_name_uses_unknown_when_only_version_is_available() {
        let normalized = normalize_process_name("2.1.45".to_string(), None);
        assert_eq!(normalized, "unknown");
    }

    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn parse_linux_proc_stat_extracts_name_and_parent() {
        let line = "1234 (Code Helper) S 567 1 1 0 -1 4194560 1587 0 0 0 13 10 0 0 20 0 8 0 123456";
        let parsed = parse_linux_proc_stat_line(line).expect("stat line should parse");
        assert_eq!(parsed.0, "Code Helper");
        assert_eq!(parsed.1, 567);
    }

    #[test]
    fn process_bundle_id_extracts_scoped_node_package() {
        let path = "/Users/example/@vendor/tool/node_modules/@vendor/tool-darwin-arm64/vendor/aarch64-apple-darwin/tool/tool";
        assert_eq!(
            process_bundle_id_from_executable(Some(path)),
            Some("@vendor/tool".to_string())
        );
    }

    #[test]
    fn process_bundle_id_extracts_scoped_node_package_from_pnpm_layout() {
        let path = "/Users/example/project/node_modules/.pnpm/@vendor+tool@0.25.0/node_modules/@vendor/tool/bin/tool";
        assert_eq!(
            process_bundle_id_from_executable(Some(path)),
            Some("@vendor/tool".to_string())
        );
    }

    #[test]
    fn process_bundle_id_accepts_reverse_domain_executable_name() {
        let path = "/System/Library/Frameworks/WebKit.framework/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking";
        assert_eq!(
            process_bundle_id_from_executable(Some(path)),
            Some("com.apple.WebKit.Networking".to_string())
        );
    }

    #[test]
    fn system_helper_detection_matches_known_macos_service_names() {
        assert!(is_system_helper_process_name("com.apple.nsurlsessiond"));
        assert!(is_system_helper_process_name("com.apple.WebKit.Networking"));
        assert!(!is_system_helper_process_name("Cursor"));
    }

    #[test]
    fn responsible_parent_candidate_rejects_shells_and_accepts_apps() {
        assert!(!is_responsible_parent_candidate("zsh", Some("/bin/zsh")));
        assert!(is_responsible_parent_candidate(
            "Terminal",
            Some("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")
        ));
        assert!(is_responsible_parent_candidate("Cursor", None));
    }

    #[test]
    fn parent_walk_triggers_for_low_signal_processes() {
        assert!(should_attempt_parent_walk("node", "cli"));
        assert!(should_attempt_parent_walk("unknown", "unknown"));
        assert!(should_attempt_parent_walk("2.1.45", "unknown"));
        assert!(!should_attempt_parent_walk("Codex", "cli"));
        assert!(!should_attempt_parent_walk("Cursor", "editor"));
    }

    #[test]
    fn app_policy_resolution_prefers_bundle_id() {
        let registry = registry();
        let Some((app_id, _)) = registry.bundle().interception.app_policies.iter().next() else {
            eprintln!("Skipping app policy resolution assertion: ~/.soth bundle has no app policies");
            return;
        };
        let identity = ProcessIdentity::new(
            Some(app_id.clone()),
            Some("claude.exe".to_string()),
        );

        let resolved = resolve_process(&identity, &registry);
        assert_eq!(resolved.match_kind, ProcessMatchKind::AppPolicy);
        assert!(resolved.known_app);
    }

    #[test]
    fn browser_processes_resolve_to_host_type() {
        let registry = registry();
        let Some(browser_id) = registry
            .bundle()
            .interception
            .browser_policies
            .allowed_browsers
            .first()
            .cloned()
        else {
            eprintln!(
                "Skipping browser process assertion: ~/.soth bundle has no allowed browser ids"
            );
            return;
        };
        let identity = ProcessIdentity::new(Some(browser_id), None);

        let resolved = resolve_process(&identity, &registry);
        assert_eq!(resolved.app_type, AppType::Host);
        assert_eq!(resolved.match_kind, ProcessMatchKind::BrowserPolicy);
        assert!(resolved.browser);
    }

    #[test]
    fn unknown_process_uses_default_unknown_action() {
        let registry = registry();
        let identity = ProcessIdentity::new(Some("com.unknown.app".to_string()), None);

        let resolved = resolve_process(&identity, &registry);
        assert_eq!(resolved.match_kind, ProcessMatchKind::Unknown);
        assert_eq!(resolved.action, registry.unknown_app_action());
        assert_eq!(resolved.app_type, AppType::Unknown);
    }

    #[test]
    fn default_cache_ttl_is_long_lived() {
        let attribution = ProcessAttribution::default();
        assert!(attribution.cache_ttl >= Duration::from_secs(60 * 60));
    }

    #[test]
    fn process_attribution_clamps_timeout_and_cache_ttl() {
        let lower = ProcessAttribution::new(true, Duration::from_millis(1), Duration::ZERO);
        assert_eq!(lower.lookup_timeout, MIN_LOOKUP_TIMEOUT);
        assert_eq!(lower.cache_ttl, MIN_CACHE_TTL);

        let upper = ProcessAttribution::new(true, Duration::from_secs(30), Duration::from_secs(2));
        assert_eq!(upper.lookup_timeout, MAX_LOOKUP_TIMEOUT);
        assert_eq!(upper.cache_ttl, Duration::from_secs(2));
    }

    #[test]
    fn cache_hit_extends_expiry_for_active_connection() {
        let attribution =
            ProcessAttribution::new(true, Duration::from_millis(50), Duration::from_secs(60));
        let addr: SocketAddr = "127.0.0.1:8123".parse().unwrap();

        attribution.put_cached(
            addr,
            Some(ResolvedProcessIdentity {
                name: "cursor".to_string(),
                bundle_id: Some("com.cursor.app".to_string()),
            }),
        );

        let first_expiry = {
            let cache = lock_recover(&attribution.cache);
            cache.get(&addr).unwrap().expires_at
        };

        std::thread::sleep(Duration::from_millis(2));
        let cached = attribution.get_cached(addr);
        assert!(cached.is_some());

        let second_expiry = {
            let cache = lock_recover(&attribution.cache);
            cache.get(&addr).unwrap().expires_at
        };
        assert!(second_expiry > first_expiry);
    }
}
