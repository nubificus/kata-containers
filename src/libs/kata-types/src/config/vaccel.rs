// Copyright (c) 2025 Nubificus Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::Result;

use crate::config::{ConfigOps, TomlConfig};

/// Vaccel configuration information.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Vaccel {
    /// Path to the vaccel agent
    #[serde(default)]
    pub agent_path: String,
    /// Level of debug from agent with range  [1-4]
    #[serde(default)]
    pub debug: String,
    /// Plugins to include
    #[serde(default)]
    pub backends: String,
    /// Plugins directory
    #[serde(default)]
    pub backends_library: String,
    /// Agent's endpoint port
    #[serde(default)]
    pub endpoint_port: String,
    /// execution type of vagent exec or integrated
    #[serde(default)]
    pub execution_type: String,
}

impl ConfigOps for Vaccel {
    fn adjust_config(conf: &mut TomlConfig) -> Result<()> {
        // TODO: Properly implement this

        Ok(())
    }

    fn validate(conf: &TomlConfig) -> Result<()> {
        // TODO: Properly implement this

        Ok(())
    }
}
