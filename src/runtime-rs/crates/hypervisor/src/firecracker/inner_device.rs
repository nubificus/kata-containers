use super::FcInner;
use crate::device_type::DeviceConfig;
use crate::VmmState;
use anyhow::Result;

impl FcInner {
    pub(crate) async fn add_device(&mut self, device: DeviceConfig) -> Result<()> {
        if self.state != VmmState::VmRunning {
            info!(sl!(), "VMM not ready, queueing device {}", device);

            self.pending_devices.insert(0, device);

            return Ok(());
        }

        self.handle_device(device).await?;

        Ok(())
    }

    async fn handle_device(&mut self, device: DeviceConfig) -> Result<()> {
        info!(sl!(), "FcInner: Handle Device {} ", device);
        todo!()
    }

    pub(crate) async fn remove_device(&mut self, device: DeviceConfig) -> Result<()> {
        info!(sl!(), "FcInner: Remove Device {} ", device);
        todo!()
    }
}
