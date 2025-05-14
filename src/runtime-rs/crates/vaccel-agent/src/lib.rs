// Copyright (c) 2025 Nubificus Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate slog;

logging::logger_with_subsystem!(sl, "vaccel-agent");

#[cfg(feature = "builtin")]
use crate::builtin::VaccelAgentBuiltinInner;
use crate::external::VaccelAgentExternalInner;
use agent::sock::{HYBRID_VSOCK_SCHEME, REMOTE_SCHEME, VSOCK_SCHEME};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use kata_types::config::Vaccel as VaccelConfig;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

#[cfg(feature = "builtin")]
mod builtin;
mod external;

#[derive(Clone)]
pub struct VaccelAgent {
    inner: Arc<Mutex<dyn VaccelAgentInner>>,
}

impl Default for VaccelAgent {
    fn default() -> Self {
        Self::new(VaccelConfig::default()).unwrap()
    }
}

impl VaccelAgent {
    pub fn new(config: VaccelConfig) -> Result<Self> {
        info!(
            sl!(),
            "Creating new vaccel agent with config: {:?}", &config
        );
        match config.built_in {
            false => Ok(Self {
                inner: Arc::new(Mutex::new(VaccelAgentExternalInner::new(config.clone()))),
            }),
            #[cfg(feature = "builtin")]
            true => Ok(Self {
                inner: Arc::new(Mutex::new(VaccelAgentBuiltinInner::new(config.clone()))),
            }),
            #[cfg(not(feature = "builtin"))]
            true => Err(anyhow!("Built-in vaccel agent not supported")),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.start().await
    }

    pub async fn stop(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.stop().await
    }

    pub async fn set_address(&self, address: &str) {
        let mut inner = self.inner.lock().await;
        inner.set_address(address).await
    }

    pub async fn set_address_from_kata(&self, kata_socket: &str) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let config = inner.config().await;

        debug!(
            sl!(),
            "Generating vaccel agent address from kata socket='{}'", &kata_socket
        );
        let kata_address = Url::parse(kata_socket).context("parse kata socket")?;
        if let Some(kata_port) = kata_address.port() {
            if kata_port == config.agent_port {
                return Err(anyhow!(
                    "vaccel agent port={} conflicts with kata agent",
                    kata_port
                ));
            }
        };

        let mut address = kata_address.clone();
        match kata_address.scheme() {
            VSOCK_SCHEME => {
                address
                    .set_scheme("vsock")
                    .map_err(|_| anyhow!("Could not set vaccel agent address scheme"))?;
                address
                    .set_port(Some(config.agent_port))
                    .map_err(|_| anyhow!("Could not set vaccel agent address port"))?;
            }
            HYBRID_VSOCK_SCHEME | REMOTE_SCHEME => {
                address
                    .set_scheme("unix")
                    .map_err(|_| anyhow!("Could not set vaccel agent address scheme"))?;
                address
                    .set_path(&[kata_address.path(), "_", &config.agent_port.to_string()].concat());
            }
            _ => return Err(anyhow!("Unsupported address scheme")),
        };

        let address_str = String::from(address);
        info!(sl!(), "Generated vaccel agent address: {}", &address_str);
        inner.set_address(&address_str).await;

        Ok(())
    }
}

#[async_trait]
pub(crate) trait VaccelAgentInner: Send + Sync {
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    async fn config<'a>(&'a self) -> &'a VaccelConfig;
    async fn set_address(&mut self, address: &str);
}
