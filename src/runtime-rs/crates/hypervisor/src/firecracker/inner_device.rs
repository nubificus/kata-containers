use super::FcInner;
use crate::HybridVsockConfig;
use crate::{device::Device, VmmState};
use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use serde_json::json;

impl FcInner {
    pub(crate) async fn add_device(&mut self, device: Device) -> Result<()> {
        match device{
            Device::HybridVsock(cfg) =>{
                info!(sl!(), "ADDING HVSOCK DEVICE");
                Ok(())
            }
            _ => return Err(anyhow!("unhandled device: {:?}", device)),
        }
    }
    //Fc doesnt support hotplug so we use put dummy devices and then we patch them
    pub(crate) async fn add_dummy_devices(&mut self) -> Result<()> {
      let mut dummy_drives: Vec<String> = vec![];
      for i in 1..6 {
          dummy_drives.push(json!({
            "drive_id": format!("drive{}",i),
            "path_on_host": format!("drive{}.ext4",i),
            "is_root_device": false,
            "is_read_only": false
          }).to_string());
          self.put("/boot-source", dummy_drives[i].to_owned()).await?;
      }
      info!(sl!(), "ADDING DUMMY DEVICES");
      Ok(())
    }
  //  pub(crate) async fn handle_hvsock_device(&mut self, _cfg: &HybridVsockConfig) -> Result<()> {
  //      Ok(())
  //  }
    pub(crate) async fn patch_devices(&mut self) -> Result<()> {
        for drive in &self.pending_devices {
        }
        Ok(())
    }
    pub(crate) async fn remove_device(&mut self, device: Device) -> Result<()> {
        info!(sl!(), "FcInner: Remove Device {} ", device);
        todo!()
    }
}
