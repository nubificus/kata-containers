// Copyright (c) 2025 Nubificus Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::VaccelAgentInner;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use kata_types::config::Vaccel as VaccelConfig;
use std::ffi::CString;
use ttrpc::sync::Server;
use vaccel::ffi;

pub struct VaccelAgentBuiltinInner {
    address: String,
    config: VaccelConfig,
    server: Option<Server>,
}

impl VaccelAgentBuiltinInner {
    pub fn new(config: VaccelConfig) -> Self {
        Self {
            address: "".to_string(),
            config,
            server: None,
        }
    }
}

#[async_trait]
impl VaccelAgentInner for VaccelAgentBuiltinInner {
    async fn start(&mut self) -> Result<()> {
        let mut server = vaccel_rpc_agent::server_init(&self.address)?;

        let mut backends: Vec<String> = Vec::new();
        for b in self.config.backends.split(',') {
            backends.push(format!("{}/libvaccel-{}.so", self.config.library_path, b));
        }

        let backends_string = backends.join(":");
        let backends_cstring =
            CString::new(backends_string.clone()).map_err(anyhow::Error::from)?;
        match unsafe { ffi::vaccel_plugin_load(backends_cstring.as_c_str().as_ptr()) as u32 } {
            ffi::VACCEL_OK => info!(sl!(), "Loaded new vaccel backends: {}", backends_string),
            e => return Err(anyhow!("Could not load vaccel backends: Error {:?}", e)),
        };

        server.start().unwrap();
        info!(sl!(), "Vaccel agent started");

        self.server = Some(server);

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(server) = self.server.take() {
            info!(sl!(), "Stopping vaccel agent");
            server.shutdown();
            return Ok(());
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
