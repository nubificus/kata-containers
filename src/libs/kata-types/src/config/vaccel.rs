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
    #[serde(default = "default_agent_path")]
    pub agent_path: String,

    /// Agent server's port.
    #[serde(default = "default_agent_port")]
    pub agent_port: u16,

    /// Use built-in agent.
    #[serde(default)]
    pub built_in: bool,

    /// Library path for plugins.
    #[serde(default)]
    pub library_path: String,

    /// Plugins to load from agent's libvaccel.
    #[serde(default = "default_plugins")]
    pub plugins: String,

    /// Log level for agent's libvaccel [1-4].
    #[serde(default = "default_log_level")]
    pub log_level: u8,

    /// Log file path for libvaccel/plugins.
    #[serde(default)]
    pub log_file: Option<String>,

    /// Enable profiling.
    #[serde(default)]
    pub profiling_enabled: bool,

    /// Ignore plugins' libvaccel version check.
    #[serde(default)]
    pub version_ignore: bool,
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

fn default_agent_path() -> String {
    String::from("/usr/local/bin/vaccel-rpc-agent")
}

fn default_agent_port() -> u16 {
    2048
}

fn default_plugins() -> String {
    String::from("noop")
}

fn default_log_level() -> u8 {
    1
}
