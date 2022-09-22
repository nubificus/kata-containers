// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{
    generic::{GenericConfig, GenericDevice},
    DeviceConfig,
};
use crate::device_type::hypervisor;
use crate::device_type::{Device, DeviceArgument};
use anyhow::Result;
use async_trait::async_trait;

/// VIRTIO_BLOCK_MMIO indicates block driver is virtio-mmio based
pub const VIRTIO_BLOCK_MMIO: &str = "virtio-blk-mmio";
/// VIRTIO_BLOCK_PCI indicates block driver is virtio-pci based
pub const VIRTIO_BLOCK_PCI: &str = "virtio-blk-pci";
pub const KATA_MMIO_BLK_DEV_TYPE: &str = "mmioblk";
pub const KATA_BLK_DEV_TYPE: &str = "blk";

/// VirtioBlkConfig: virtio-blk device config
#[derive(Debug, Default, Clone)]
pub struct VirtioBlkConfig {
    /// Unique identifier of the drive.
    pub id: String,

    /// Path of the drive.
    pub path_on_host: String,

    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_readonly: bool,

    /// Don't close `path_on_host` file when dropping the device.
    pub no_drop: bool,

    /// device index
    pub index: u64,
}

/// VirtioBlkDevice refers to a block storage device implementation
pub struct VirtioBlkDevice {
    virtio_blk_config: VirtioBlkConfig,
    virtio_blk_driver: String,
    base: GenericDevice,
}

impl VirtioBlkDevice {
    // new creates a new VirtioBlkDevice
    pub fn new(dev_info: &GenericConfig, block_driver: String) -> Self {
        // convert the block driver to kata type
        let blk_driver = match block_driver.as_str() {
            VIRTIO_BLOCK_MMIO => KATA_MMIO_BLK_DEV_TYPE.to_string(),
            VIRTIO_BLOCK_PCI => KATA_BLK_DEV_TYPE.to_string(),
            _ => "".to_string(),
        };

        VirtioBlkDevice {
            virtio_blk_config: VirtioBlkConfig {
                id: dev_info.id.clone(),
                path_on_host: dev_info.host_path.clone(),
                ..Default::default()
            },
            virtio_blk_driver: blk_driver,
            base: GenericDevice::new(dev_info),
        }
    }
}

#[async_trait]
impl Device for VirtioBlkDevice {
    async fn attach(&mut self, h: &dyn hypervisor, da: DeviceArgument) -> Result<()> {
        if let Some(index) = da.index {
            self.virtio_blk_config.index = index;
        }
        let device_info = &mut self.base.get_device_info().await?;
        if self.virtio_blk_driver != *"nvdimm" {
            if let Some(drive_name) = da.drive_name {
                device_info.virt_path = Some(format!("/dev/{}", drive_name));
            }
        }
        self.set_device_info(device_info.clone()).await?;
        h.add_device(DeviceConfig::VirtioBlk(self.virtio_blk_config.clone()))
            .await
    }

    async fn detach(&mut self, h: &dyn hypervisor) -> Result<Option<u64>> {
        h.remove_device(DeviceConfig::VirtioBlk(self.virtio_blk_config.clone()))
            .await?;
        Ok(Some(self.virtio_blk_config.index))
    }

    async fn device_id(&self) -> &str {
        self.base.device_id().await
    }

    async fn set_device_info(&mut self, device_info: GenericConfig) -> Result<()> {
        self.base.set_device_info(device_info).await
    }

    async fn get_device_info(&self) -> Result<GenericConfig> {
        self.base.get_device_info().await
    }

    async fn get_major_minor(&self) -> (i64, i64) {
        self.base.get_major_minor().await
    }

    async fn get_host_path(&self) -> &str {
        self.base.get_host_path().await
    }

    async fn get_bdf(&self) -> Option<String> {
        self.base.get_bdf().await
    }

    async fn get_attach_count(&self) -> u64 {
        self.base.get_attach_count().await
    }

    async fn increase_attach_count(&mut self) -> Result<bool> {
        self.base.increase_attach_count().await
    }

    async fn decrease_attach_count(&mut self) -> Result<bool> {
        self.base.decrease_attach_count().await
    }

    async fn device_driver(&self) -> Option<String> {
        Some(self.virtio_blk_driver.clone())
    }
}
