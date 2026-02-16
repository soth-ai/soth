use super::*;

pub(super) struct SetupTransaction {
    dir: PathBuf,
    backups_dir: PathBuf,
    manifest_path: PathBuf,
    manifest: SetupManifest,
    backup_index: HashSet<String>,
}

impl SetupTransaction {
    pub(super) fn start(
        preflight: &PreflightContext,
        fail_mode: &FailMode,
        proxy_url: &str,
    ) -> Result<Self> {
        let setup_id = Uuid::new_v4().to_string();
        let dir = preflight.setups_dir.join(&setup_id);
        let backups_dir = dir.join("backups");
        fs::create_dir_all(&backups_dir).with_context(|| {
            format!("failed to create transaction dir {}", backups_dir.display())
        })?;

        let manifest = SetupManifest {
            setup_id,
            created_at: Utc::now().to_rfc3339(),
            completed_at: None,
            rolled_back_at: None,
            status: SetupStatus::InProgress,
            error: None,
            fail_mode: fail_mode.to_string(),
            proxy_url: proxy_url.to_string(),
            shell: preflight.shell.clone(),
            shell_file: preflight
                .shell_file
                .as_ref()
                .map(|path| path.display().to_string()),
            backups: Vec::new(),
            steps: StepState::default(),
        };

        let manifest_path = dir.join("manifest.json");
        let tx = Self {
            dir,
            backups_dir,
            manifest_path,
            manifest,
            backup_index: HashSet::new(),
        };
        tx.persist_manifest()?;
        Ok(tx)
    }

    pub(super) fn setup_id(&self) -> &str {
        &self.manifest.setup_id
    }

    pub(super) fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(super) fn set_step_ca_generated(&mut self) -> Result<()> {
        self.manifest.steps.ca_generated = true;
        self.persist_manifest()
    }

    pub(super) fn set_step_proxy_enabled(&mut self) -> Result<()> {
        self.manifest.steps.proxy_enabled = true;
        self.persist_manifest()
    }

    pub(super) fn set_step_wrap_applied(&mut self) -> Result<()> {
        self.manifest.steps.wrap_applied = true;
        self.persist_manifest()
    }

    pub(super) fn set_step_shell_env_written(&mut self) -> Result<()> {
        self.manifest.steps.shell_env_written = true;
        self.persist_manifest()
    }

    pub(super) fn set_step_state_written(&mut self) -> Result<()> {
        self.manifest.steps.state_written = true;
        self.persist_manifest()
    }

    pub(super) fn ensure_backup(&mut self, path: &Path) -> Result<()> {
        let original = normalize_path(path);
        let key = original.display().to_string();
        if self.backup_index.contains(&key) {
            return Ok(());
        }

        let existed_before = original.exists();
        let backup_path = if existed_before {
            let idx = self.manifest.backups.len();
            let file_name = original
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file");
            let target =
                self.backups_dir
                    .join(format!("{:04}_{}", idx, sanitize_file_name(file_name)));
            fs::copy(&original, &target).with_context(|| {
                format!(
                    "failed to backup {} to {}",
                    original.display(),
                    target.display()
                )
            })?;
            Some(target.display().to_string())
        } else {
            None
        };

        self.manifest.backups.push(BackupEntry {
            original_path: key.clone(),
            backup_path,
            existed_before,
        });
        self.backup_index.insert(key);
        self.persist_manifest()
    }

    pub(super) fn complete(&mut self) -> Result<()> {
        self.manifest.status = SetupStatus::Completed;
        self.manifest.completed_at = Some(Utc::now().to_rfc3339());
        self.manifest.error = None;
        self.persist_manifest()
    }

    pub(super) fn fail(&mut self, error: &str) -> Result<()> {
        self.manifest.status = SetupStatus::Failed;
        self.manifest.error = Some(error.to_string());
        self.persist_manifest()
    }

    pub(super) fn persist_manifest(&self) -> Result<()> {
        if let Some(parent) = self.manifest_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(&self.manifest)?;
        fs::write(&self.manifest_path, body)
            .with_context(|| format!("failed to write {}", self.manifest_path.display()))
    }
}

pub(super) async fn run_doctor(
    config: &SothConfig,
    global_config_path: Option<PathBuf>,
) -> Result<()> {
    let preflight = run_preflight(None, config)?;

    style::header("SOTH Setup Doctor");

    let mut healthy = true;

    let ca_ok = preflight.ca_cert_path.exists() && preflight.ca_key_path.exists();
    style::kv_colored("CA files", if ca_ok { "present" } else { "missing" }, ca_ok);
    healthy &= ca_ok;

    let state_ok = preflight.state_path.exists();
    style::kv_colored(
        "Setup state",
        if state_ok { "present" } else { "missing" },
        state_ok,
    );
    healthy &= state_ok;

    if let Some(ref shell_file) = preflight.shell_file {
        let shell_ok = has_managed_shell_block(shell_file).unwrap_or(false);
        style::kv_colored(
            "Shell managed block",
            if shell_ok { "present" } else { "missing" },
            shell_ok,
        );
        healthy &= shell_ok;
    } else {
        style::warning("Shell RC path unsupported for persistent block checks.");
    }

    if let Some(latest_id) = resolve_setup_id(None, &preflight.state_path).ok() {
        let manifest_path = manifest_path_for_setup(&preflight, &latest_id);
        let manifest_ok = manifest_path.exists();
        style::kv_colored(
            "Latest manifest",
            if manifest_ok { "present" } else { "missing" },
            manifest_ok,
        );
        if manifest_ok {
            if let Ok(manifest) = read_manifest(&manifest_path) {
                style::kv("Latest setup_id", &manifest.setup_id);
                style::kv(
                    "Latest status",
                    &format!("{:?}", manifest.status).to_lowercase(),
                );
            }
        }
    }

    println!();
    style::subtitle("Proxy Status");
    if let Err(error) = commands::proxy::run_status(global_config_path).await {
        style::warning(&format!("Proxy status command failed: {error}"));
        healthy = false;
    }

    println!();
    style::subtitle("MCP Wrap Status");
    if let Err(error) = commands::install::run_status().await {
        style::warning(&format!("Install status command failed: {error}"));
        healthy = false;
    }

    println!();
    if healthy {
        style::success("Doctor checks passed.");
        style::footer();
        return Ok(());
    }

    style::warning("Doctor detected setup issues. Re-run: soth setup wizard");
    style::footer();
    bail!("setup doctor reported unhealthy state")
}

pub(super) async fn run_rollback(
    setup_id: Option<String>,
    yes: bool,
    config: &SothConfig,
    _global_config_path: Option<PathBuf>,
) -> Result<()> {
    let preflight = run_preflight(None, config)?;
    let resolved_setup_id = resolve_setup_id(setup_id, &preflight.state_path)?;
    let manifest_path = manifest_path_for_setup(&preflight, &resolved_setup_id);
    let mut manifest = read_manifest(&manifest_path).with_context(|| {
        format!(
            "failed to read setup manifest for rollback: {}",
            manifest_path.display()
        )
    })?;

    style::header("SOTH Setup Rollback");
    style::kv("Setup ID", &resolved_setup_id);
    style::kv("Manifest", &manifest_path.display().to_string());

    if !yes && !prompt_yes_no("Rollback setup-managed changes?", false)? {
        style::warning("Rollback cancelled.");
        style::footer();
        return Ok(());
    }

    restore_backup_entries(&manifest.backups)?;

    if manifest.steps.proxy_enabled {
        if let Err(error) = commands::proxy::run_off().await {
            style::warning(&format!("Failed to disable proxy during rollback: {error}"));
        }
    }

    manifest.status = SetupStatus::RolledBack;
    manifest.rolled_back_at = Some(Utc::now().to_rfc3339());
    manifest.error = None;
    write_manifest(&manifest_path, &manifest)?;

    style::success("Rollback completed.");
    style::footer();
    Ok(())
}

pub(super) async fn run_uninstall(
    yes: bool,
    config: &SothConfig,
    _global_config_path: Option<PathBuf>,
) -> Result<()> {
    let preflight = run_preflight(None, config)?;

    style::header("SOTH Setup Uninstall");
    if !yes && !prompt_yes_no("Remove setup-managed configuration?", false)? {
        style::warning("Uninstall cancelled.");
        style::footer();
        return Ok(());
    }

    run_uninstall_internal(&preflight, true).await?;
    style::success("Uninstall completed.");
    style::footer();
    Ok(())
}

pub(super) async fn run_uninstall_internal(
    preflight: &PreflightContext,
    remove_state: bool,
) -> Result<()> {
    if let Err(error) = commands::proxy::run_off().await {
        style::warning(&format!("Failed to disable proxy: {error}"));
    }

    if let Err(error) = commands::install::run_uninstall(None).await {
        style::warning(&format!("Failed to unwrap MCP configs: {error}"));
    }

    if let Some(ref shell_file) = preflight.shell_file {
        if let Err(error) = remove_managed_shell_block(shell_file) {
            style::warning(&format!("Failed to remove shell managed block: {error}"));
        }
    }

    if remove_state && preflight.state_path.exists() {
        fs::remove_file(&preflight.state_path).with_context(|| {
            format!(
                "failed to remove setup state file {}",
                preflight.state_path.display()
            )
        })?;
    }

    Ok(())
}

pub(super) fn run_preflight(
    shell_override: Option<String>,
    config: &SothConfig,
) -> Result<PreflightContext> {
    let home = dirs::home_dir().context("home directory not found")?;

    let shell = detect_shell(shell_override);
    let shell_file = shell_rc_path(&home, &shell);
    let state_path = home.join(".soth").join("setup-state.json");
    let ca_cert_path = cli_config::expand_tilde(&config.forward_proxy.ca.cert_path);
    let ca_key_path = cli_config::expand_tilde(&config.forward_proxy.ca.key_path);
    let setups_dir = home.join(".soth").join("setups");

    Ok(PreflightContext {
        shell,
        shell_file,
        ca_cert_path,
        ca_key_path,
        state_path,
        setups_dir,
    })
}
