use super::FcInner;
use crate::{device::Device, VmmState};
use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;

impl FcInner {
    //Fc doesnt support hotplug so we use put dummy devices and then we patch them
    pub(crate) async fn add_dummy_devices(&mut self) -> Result<()> {
        let body_rootfs: String = format!(
            "
         {{
          \"drive_id\": \"rootfs\",
          \"path_on_host\": \"rootfs.img\",
          \"is_root_device\": true,
          \"is_read_only\": false
         }}"
        );
        info!(sl!(), "ADDING DUMMY ROOTFS");
        self.put("/boot-source", body_rootfs).await?;
        let mut dummy_drives: Vec<String> = vec![];
        for i in 0..7 {
            dummy_drives.push(format!(
                "
             {{
              \"drive_id\": \"drive{}\",
              \"path_on_host\": \"drive{}.img\",
              \"is_root_device\": false,
              \"is_read_only\": false
             }}",
                i.to_string(),
                i.to_string()
            ));
            self.put("/boot-source", dummy_drives[i].to_owned()).await?;
        }
        info!(sl!(), "ADDING DUMMY DEVICES");
        Ok(())
    }

    pub(crate) async fn patch_devices(&mut self) -> Result<()> {
        //We assume the rootfs will be first so we will pop and patch and then patch the rest of
        //the drives very similarly to the above function
        //Need to study devices further to be sure which elements we will need
        for drive in &self.pending_devices {}
        Ok(())
    }
}
