//Copyright (c) 2019-2022 Alibaba Cloud
//Copyright (c) 2019-2022 Ant Group
//Copyright (c) 2023 Nubificus Ltd
//
//SPDX-License-Identifier: Apache-2.0

use super::FcInner;
use crate::{DeviceType, VmmState};
use anyhow::{anyhow, Context, Result};

impl FcInner {
    pub(crate) async fn add_device(&mut self, device: DeviceType) -> Result<()> {
        if self.state == VmmState::NotReady {
            info!(sl!(), "VMM not ready, queueing device {}", device);

            self.pending_devices.insert(0, device);

            return Ok(());
        }

        info!(sl!(), "FcInner: Add Device {} ", device);

        let _ = match device {
            DeviceType::Block(block) => self
                .hotplug_block_device(block.config.path_on_host.as_str(), block.config.index)
                .await
                .context("add block device"),
            DeviceType::Network(network) => self
                .add_net_device(&network.config, network.device_id)
                .await
                .context("add net device"),
            _ => Err(anyhow!("unhandled device: {:?}", device)),
        };

        Ok(())
    }
    
    // Since Firecracker doesn't support sharefs, we patch block devices on pre-start inserted
    // dummy drives
    pub(crate) async fn hotplug_block_device(&mut self, path: &str, id: u64) -> Result<()> {
        if id > 0{
            self.patch_container_rootfs(&id.to_string(), path).await?;
        }
        Ok(())
    }

    pub(crate) async fn remove_device(&mut self, device: DeviceType) -> Result<()> {
        info!(sl!(), "FcInner: Remove Device {} ", device);
        Ok(())
    }
}
