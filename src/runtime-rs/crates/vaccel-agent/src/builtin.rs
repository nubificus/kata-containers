// Copyright (c) 2025 Nubificus Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::VaccelAgentInner;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use kata_types::config::Vaccel as VaccelKataConfig;
use vaccel::Config as VaccelConfig;
use vaccel_rpc_agent::Agent as RpcAgent;

pub struct VaccelAgentBuiltinInner {
    address: String,
    config: VaccelKataConfig,
    rpc_agent: Option<RpcAgent>,
}

impl VaccelAgentBuiltinInner {
    pub fn new(config: VaccelKataConfig) -> Self {
        Self {
            address: "".to_string(),
            config,
            rpc_agent: None,
        }
    }

    async fn parse_vaccel_config(config: &VaccelKataConfig) -> Result<VaccelConfig> {
        let mut plugins: Vec<String> = Vec::new();
        for b in config.plugins.split(',') {
            plugins.push(format!("{}/libvaccel-{}.so", config.library_path, b));
        }
        let plugins_string = plugins.join(":");

        VaccelConfig::new(
            Some(&plugins_string),
            config.log_level,
            config.log_file.as_deref(),
            config.profiling_enabled,
            config.version_ignore,
        )
        .context("parse vaccel config")
    }
}

#[async_trait]
impl VaccelAgentInner for VaccelAgentBuiltinInner {
    async fn start(&mut self) -> Result<()> {
        let mut rpc_agent = RpcAgent::new(&self.address);
        let vaccel_config = Self::parse_vaccel_config(&self.config).await?;
        rpc_agent
            .set_vaccel_config(vaccel_config)
            .context("set vaccel config")?;

        rpc_agent.start().context("start vaccel rpc agent")?;
        info!(sl!(), "Vaccel agent started");

        self.rpc_agent = Some(rpc_agent);

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(mut rpc_agent) = self.rpc_agent.take() {
            info!(sl!(), "Stopping vaccel agent");
            return rpc_agent.shutdown().context("stop vaccel agent");
        }

        Err(anyhow!("Cannot stop uninitialized vaccel agent"))
    }

    async fn config<'a>(&'a self) -> &'a VaccelKataConfig {
        &self.config
    }

    async fn set_address(&mut self, address: &str) {
        self.address = address.to_string();
    }
}
