use super::FcInner;
use crate::DeviceType;
use crate::VmmState;
use anyhow::{anyhow, Context, Result};

impl FcInner {
    pub(crate) async fn add_device(&mut self, device: DeviceType) -> Result<()> {
        if (self.state != VmmState::VmRunning) && (self.state != VmmState::VmmServerReady) {
            info!(sl!(), "VMM not ready, queueing device {}", device);

            self.pending_devices.insert(0, device);

            return Ok(());
        }

        info!(sl!(), "FcInner: Add Device {} ", device);

        let _ = match device {
            DeviceType::Block(block) => self
                .hotplug_block_device(
                    block.config.path_on_host.as_str(),
                    block.config.index,
                    block.config.is_readonly,
                    block.config.no_drop,
                )
                .await
                .context("add block device"),
            DeviceType::Network(network) => self
                .add_net_device(&network.config, network.id)
                .await
                .context("add net device"),
            _ => Err(anyhow!("unhandled device: {:?}", device)),
        };

        Ok(())
    }

    pub(crate) async fn hotplug_block_device(
        &mut self,
        path: &str,
        id: u64,
        _read_only: bool,
        _no_drop: bool,
    ) -> Result<()> {
        self.patch_container_rootfs(&id.to_string(), path).await?;
        Ok(())
    }

    pub(crate) async fn remove_device(&mut self, device: DeviceType) -> Result<()> {
        info!(sl!(), "FcInner: Remove Device {} ", device);
        //todo!()
        Ok(())
    }
}
