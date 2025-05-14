// Copyright (c) 2025 Nubificus Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::VaccelAgentInner;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use kata_types::config::Vaccel as VaccelConfig;
use std::{process::Stdio, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    sync::{Mutex, Notify},
    time::{timeout, Duration},
};

#[derive(Debug, Clone)]
pub struct VaccelAgentExternalInner {
    address: String,
    config: VaccelConfig,
    process: Arc<Mutex<Option<Child>>>,
    notify: Arc<Notify>,
}

impl VaccelAgentExternalInner {
    pub fn new(config: VaccelConfig) -> Self {
        Self {
            config,
            address: "".to_string(),
            process: Arc::new(Mutex::new(None)),
            notify: Arc::new(Notify::new()),
        }
    }
}

#[async_trait]
impl VaccelAgentInner for VaccelAgentExternalInner {
    async fn start(&mut self) -> Result<()> {
        let mut process = self.process.lock().await;
        if process.is_some() {
            return Err(anyhow!("Vaccel agent already running"));
        }

        // Initialize tokio process
        let mut cmd = Command::new(&self.config.agent_path);
        cmd.args(["-a", &self.address])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set vaccel environment variables
        let mut plugins: Vec<String> = Vec::new();
        for b in self.config.plugins.split(',') {
            plugins.push(format!("libvaccel-{}.so", b));
        }

        let profiling_enabled = self.config.profiling_enabled as u8;
        let version_ignore = self.config.version_ignore as u8;

        cmd.env("LD_LIBRARY_PATH", &self.config.library_path)
            .env("VACCEL_PLUGINS", plugins.join(":"))
            .env("VACCEL_PROFILING_ENABLED", profiling_enabled.to_string())
            .env("VACCEL_VERSION_IGNORE", version_ignore.to_string())
            .env("VACCEL_LOG_LEVEL", self.config.log_level.to_string());

        if let Some(log_file) = self.config.log_file.as_ref() {
            cmd.env("VACCEL_LOG_FILE", log_file);
        }

        // Spawn process
        let mut child = cmd.spawn().context("spawn vaccel agent")?;
        let pid = match child.id() {
            Some(id) => id,
            None => {
                let e = child.wait().await.map_err(anyhow::Error::from)?;
                return Err(anyhow!("Vaccel agent exited early with status: {:?}", e));
            }
        };
        info!(sl!(), "Vaccel agent spawned with PID={}", pid);

        tokio::spawn(process_logger(self.process.clone()));
        tokio::spawn(process_monitor(self.process.clone(), self.notify.clone()));

        *process = Some(child);

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        let mut process = self.process.lock().await;

        if let Some(proc) = process.as_mut() {
            if let Some(pid) = proc.id() {
                info!(sl!(), "Stopping vaccel agent with PID={}", pid);
                proc.kill().await.map_err(anyhow::Error::from)?;
                self.notify.notify_waiters();
                return Ok(());
            }
        }

        Err(anyhow!("Tried to stop a not running vaccel agent"))
    }

    async fn config<'a>(&'a self) -> &'a VaccelConfig {
        &self.config
    }

    async fn set_address(&mut self, address: &str) {
        self.address = address.to_string();
    }
}

async fn process_logger(process: Arc<Mutex<Option<Child>>>) -> Result<()> {
    let mut proc = process.lock().await;
    let child = match proc.as_mut() {
        Some(c) => c,
        None => return Err(anyhow!("No running vaccel agent found")),
    };

    let mut stdout_reader = BufReader::new(child.stdout.take().unwrap());
    let mut stderr_reader = BufReader::new(child.stderr.take().unwrap());
    drop(proc);
    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();

    loop {
        tokio::select! {
            result = stdout_reader.read_line(&mut stdout_buf) => {
                if result.map_err(anyhow::Error::from)? == 0 {
                    break;
                }
                debug!(sl!(), "Vaccel agent stdout: {}", stdout_buf.trim());
                stdout_buf.clear();
            }
            result = stderr_reader.read_line(&mut stderr_buf) => {
                if result.map_err(anyhow::Error::from)? == 0 {
                    break;
                }
                info!(sl!(), "Vaccel agent stderr: {}", stderr_buf.trim());
                stderr_buf.clear();
            }
        }
    }

    Ok(())
}

async fn process_monitor(process: Arc<Mutex<Option<Child>>>, notify: Arc<Notify>) -> Result<()> {
    loop {
        let timeout_duration = Duration::from_secs(5);
        let notified = notify.notified();
        let _ = timeout(timeout_duration, notified).await;

        let mut proc = process.lock().await;
        let child = match proc.as_mut() {
            Some(c) => c,
            None => return Err(anyhow!("No running vaccel agent found")),
        };

        let pid = child.id().context("pid vaccel agent")?;
        if let Some(exit_status) = child.try_wait().map_err(anyhow::Error::from)? {
            info!(
                sl!(),
                "Vaccel agent with PID={} exited with status: {:?}", pid, exit_status
            );
            proc.take();
            return Ok(());
        }
    }
}
