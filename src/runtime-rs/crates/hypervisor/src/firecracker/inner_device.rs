use super::FcInner;
use crate::device_type::DeviceConfig;
use crate::VmmState;
use anyhow::{anyhow, Context, Result};

impl FcInner {
    pub(crate) async fn add_device(&mut self, device: DeviceConfig) -> Result<()> {
        if self.state != VmmState::VmRunning {
            info!(sl!(), "VMM not ready, queueing device {}", device);

            self.pending_devices.insert(0, device);

            return Ok(());
        }

        info!(sl!(), "FcInner: Add Device {} ", device);

        let _ = match device {
            DeviceConfig::VirtioBlk(config) => {
                self.hotplug_block_device(
                    config.path_on_host.as_str(),
                    config.id.as_str(),
                    config.is_readonly,
                    config.no_drop,
                )
                .await
            }
            DeviceConfig::Network(config) => {
                self.add_net_device(&config).await.context("add net device")
            }
            DeviceConfig::ShareFsDevice(_config) => {
                info!(sl!(), "ShareFs devices are not supported in Firecracker");
                Ok(())
            }
            DeviceConfig::ShareFsMount(_config) => {
                info!(sl!(), "ShareFs mount is not supported in Firecracker");
                Ok(())
            }

            _ => Err(anyhow!("unhandled device: {:?}", device)),
        };

        Ok(())
    }

    pub(crate) async fn hotplug_block_device(
        &mut self,
        path: &str,
        _id: &str,
        _read_only: bool,
        _no_drop: bool,
    ) -> Result<()> {
        self.patch_container_rootfs("drive1", path).await?;
        Ok(())
    }

    pub(crate) async fn remove_device(&mut self, device: DeviceConfig) -> Result<()> {
        info!(sl!(), "FcInner: Remove Device {} ", device);
        todo!()
    }
}
