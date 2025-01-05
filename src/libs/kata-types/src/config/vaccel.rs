// Copyright (c) 2025 Nubificus Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::Result;

use crate::config::{ConfigOps, TomlConfig};

/// Vaccel configuration information.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Vaccel {
    /// Path to the vaccel agent binary.
    #[serde(default)]
    pub agent_path: String,

    /// Agent server's port.
    #[serde(default)]
    pub agent_port: u16,

    /// Library path for libvaccel/plugins.
    #[serde(default)]
    pub library_path: String,

    /// Backend plugins  to load from agent's libvaccel.
    #[serde(default)]
    pub backends: String,

    /// Log level for agent's libvaccel [1-4].
    #[serde(default)]
    pub log_level: u8,

    /// Use built-in agent.
    #[serde(default)]
    pub built_in: bool,
}

impl ConfigOps for Vaccel {
    fn adjust_config(_conf: &mut TomlConfig) -> Result<()> {
        // TODO: Properly implement this

        Ok(())
    }

    fn validate(_conf: &TomlConfig) -> Result<()> {
        // TODO: Properly implement this

        Ok(())
    }
}
