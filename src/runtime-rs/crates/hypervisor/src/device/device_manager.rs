// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    device_type::{Device, DeviceArgument, GenericConfig, GenericDevice, VirtioBlkDevice},
    DeviceType, Hypervisor,
};
use anyhow::{anyhow, Context, Result};
use ini::Ini;
use kata_sys_util::rand;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
pub type ArcBoxDevice = Arc<Mutex<Box<dyn Device>>>;
const SYS_DEV_PREFIX: &str = "/sys/dev";

/// block_index and released_block_index are used to search an available block index
/// in Sandbox.
///
/// @block_index generally default is 1 for <vdb>;
/// @released_block_index for blk devices removed and indexes will released at the same time.
#[derive(Clone, Debug, Default)]
struct SharedInfo {
    block_index: u64,
    released_block_index: Vec<u64>,
}

impl SharedInfo {
    fn new(index: u64) -> Self {
        SharedInfo {
            block_index: index,
            released_block_index: vec![],
        }
    }

    // declare the available block index
    fn declare_device_index(&mut self) -> Result<u64> {
        let current_index = if let Some(index) = self.released_block_index.pop() {
            index
        } else {
            self.block_index
        };
        self.block_index += 1;

        Ok(current_index)
    }

    fn release_device_index(&mut self, index: u64) {
        self.released_block_index.push(index);
        self.released_block_index.sort_by(|a, b| b.cmp(a));
    }
}

// Device manager will manage the lifecycle of sandbox device
#[derive(Clone)]
pub struct DeviceManager {
    devices: HashMap<String, Arc<Mutex<Box<dyn Device>>>>,
    hypervisor: Arc<dyn Hypervisor>,
    shared_info: SharedInfo,
}

impl DeviceManager {
    pub async fn new(hypervisor: Arc<dyn Hypervisor>) -> Result<Self> {
        let devices = HashMap::<String, Arc<Mutex<Box<dyn Device>>>>::new();
        Ok(DeviceManager {
            devices,
            hypervisor,
            shared_info: SharedInfo::new(1),
        })
    }

    pub async fn try_add_device(&mut self, dev_info: &mut GenericConfig) -> Result<String> {
        // if the device is already created, just return the device id. Otherwise, create a new device
        let device = if let Some(dev) = self
            .find_device(
                dev_info.major,
                dev_info.minor,
                dev_info.host_path.as_str(),
                dev_info.bdf.clone(),
            )
            .await
        {
            dev
        } else {
            self.new_device(dev_info)
                .await
                .context("failed to create device")?
        };

        let device_id = device.lock().await.device_id().await.to_string();

        // increase attach count, skip attach the device if the device is already attached
        let need_skip = device
            .lock()
            .await
            .increase_attach_count()
            .await
            .context("failed to increase attach count")?;
        if need_skip {
            return Ok(device_id);
        }

        // register device to devices
        self.devices.insert(device_id.clone(), device.clone());

        // prepare arugments to attach device
        let da = self
            .make_device_argument(dev_info.dev_type.as_str())
            .context("failed to make device arguments")?;

        if let Err(e) = device
            .lock()
            .await
            .attach(self.hypervisor.as_ref(), da.clone())
            .await
        {
            device.lock().await.decrease_attach_count().await?;
            if let Some(index) = da.index {
                self.shared_info.release_device_index(index);
            }
            self.devices.remove(&device_id);
            return Err(e);
        }
        Ok(device_id)
    }

    pub async fn try_remove_device(&mut self, device_id: &str) -> Result<()> {
        if let Some(dev) = self.devices.get(device_id) {
            // get the count of device detached, skip detach once it reaches the 0.
            let skip = dev.lock().await.decrease_attach_count().await?;
            if skip {
                return Ok(());
            }
            let result = match dev.lock().await.detach(self.hypervisor.as_ref()).await {
                Ok(index) => {
                    if let Some(i) = index {
                        // release the declared block device index
                        self.shared_info.release_device_index(i);
                    }
                    Ok(())
                }
                Err(e) => {
                    dev.lock().await.increase_attach_count().await?;
                    Err(e)
                }
            };
            if result.is_ok() {
                // if detach success, remove it from device manager
                self.devices.remove(device_id);
            }
            return result;
        }
        Err(anyhow!(
            "device with specified ID hasn't been created. {}",
            device_id
        ))
    }

    async fn find_device(
        &self,
        major: i64,
        minor: i64,
        host_path: &str,
        bdf: Option<String>,
    ) -> Option<ArcBoxDevice> {
        for dev in self.devices.values() {
            if dev.lock().await.get_host_path().await == host_path {
                return Some(dev.clone());
            }

            if dev.lock().await.get_bdf().await == bdf {
                return Some(dev.clone());
            }

            let mm = dev.lock().await.get_major_minor().await;
            if mm.0 == major && mm.1 == minor {
                return Some(dev.clone());
            }
        }

        None
    }

    async fn new_device(&self, dev_info: &mut GenericConfig) -> Result<ArcBoxDevice> {
        // device ID must be generated by manager instead of device itself
        // in case of ID collision
        dev_info.id = self.new_device_id()?;
        // check the valid device number
        if dev_info.major >= 0 && dev_info.minor >= 0 {
            // find /dev/xxxx
            let path = get_host_path(dev_info)?;
            dev_info.host_path = path;
        }

        let dev: ArcBoxDevice = match get_device_type(dev_info) {
            DeviceType::VirtioBlk => {
                let block_driver = self
                    .hypervisor
                    .hypervisor_config()
                    .await
                    .blockdev_info
                    .block_device_driver;

                Arc::new(Mutex::new(Box::new(VirtioBlkDevice::new(
                    dev_info,
                    block_driver,
                ))))
            }
            DeviceType::Vfio => {
                // TODO https://github.com/kata-containers/kata-containers/issues/6525
                todo!()
            }

            _ => Arc::new(Mutex::new(Box::new(GenericDevice::new(dev_info)))),
        };
        Ok(dev)
    }

    // get_virt_drive_name returns the disk name format for virtio-blk
    // Reference: https://github.com/torvalds/linux/blob/master/drivers/block/virtio_blk.c @c0aa3e0916d7e531e69b02e426f7162dfb1c6c0
    fn get_virt_drive_name(&self, mut index: i32) -> Result<String> {
        if index < 0 {
            return Err(anyhow!("Index cannot be negative"));
        }

        // Prefix used for virtio-block devices
        const PREFIX: &str = "vd";

        // Refer to DISK_NAME_LEN: https://github.com/torvalds/linux/blob/08c521a2011ff492490aa9ed6cc574be4235ce2b/include/linux/genhd.h#L61
        let disk_name_len = 32usize;
        let base = 26i32;

        let suff_len = disk_name_len - PREFIX.len();
        let mut disk_letters = vec![0u8; suff_len];

        let mut i = 0usize;
        while i < suff_len && index >= 0 {
            let letter: u8 = b'a' + (index % base) as u8;
            disk_letters[i] = letter;
            index = (index / base) - 1;
            i += 1;
        }
        if index >= 0 {
            return Err(anyhow!("Index not supported"));
        }
        disk_letters.truncate(i);
        disk_letters.reverse();
        Ok(String::from(PREFIX) + std::str::from_utf8(&disk_letters)?)
    }

    // device ID must be generated by device manager instead of device itself
    // in case of ID collision
    fn new_device_id(&self) -> Result<String> {
        for _ in 0..5 {
            let rand_bytes = rand::RandomBytes::new(8);
            let id = format!("{:x}", rand_bytes);

            // check collision in devices
            if self.devices.get(&id).is_none() {
                return Ok(id);
            }
        }

        Err(anyhow!("ID are exhausted"))
    }

    fn make_device_argument(&mut self, dev_type: &str) -> Result<DeviceArgument> {
        // prepare arguments to attach device
        // if it's a block device, we need to increase index number
        // Otherwise do nothing
        if dev_type == "b" {
            let current_index = self.shared_info.declare_device_index()?;
            let drive_name = self.get_virt_drive_name(current_index as i32)?;

            Ok(DeviceArgument {
                index: Some(current_index),
                drive_name: Some(drive_name),
            })
        } else {
            Ok(DeviceArgument {
                index: None,
                drive_name: None,
            })
        }
    }
}

// get_host_path is used to fetch the host path for the device.
// The path passed in the spec refers to the path that should appear inside the container.
// We need to find the actual device path on the host based on the major-minor numbers of the device.
fn get_host_path(dev_info: &GenericConfig) -> Result<String> {
    if dev_info.container_path.is_empty() {
        return Err(anyhow!("Empty path provided for device"));
    }
    let path_comp = match dev_info.dev_type.as_str() {
        "c" | "u" => "char",
        "b" => "block",
        // for device type p will return an empty string
        _ => return Ok(String::new()),
    };
    let format = format!("{}:{}", dev_info.major, dev_info.minor);
    let sys_dev_path = std::path::Path::new(SYS_DEV_PREFIX)
        .join(path_comp)
        .join(format)
        .join("uevent");
    if let Err(e) = std::fs::metadata(&sys_dev_path) {
        // Some devices(eg. /dev/fuse, /dev/cuse) do not always implement sysfs interface under /sys/dev
        // These devices are passed by default by docker.
        // Simply return the path passed in the device configuration, this does mean that no device renames are
        // supported for these devices.
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(dev_info.container_path.clone());
        }
        return Err(e.into());
    }
    let conf = Ini::load_from_file(&sys_dev_path)?;
    let dev_name = conf
        .section::<String>(None)
        .ok_or_else(|| anyhow!("has no section"))?
        .get("DEVNAME")
        .ok_or_else(|| anyhow!("has no DEVNAME"))?;
    Ok(format!("/dev/{}", dev_name))
}

fn get_device_type(dev_info: &GenericConfig) -> &DeviceType {
    if dev_info.dev_type == "b" && dev_info.minor >= 0 && dev_info.major >= 0 {
        return &DeviceType::VirtioBlk;
    }
    // TODO get other devices type
    &DeviceType::Undefined
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dragonball::Dragonball;
    use crate::HypervisorConfig;

    #[actix_rt::test]
    async fn test_get_virt_drive_name() {
        let mut hypervisor = Dragonball::new();
        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = "virtio-blk-mmio".to_string();
        hypervisor.set_hypervisor_config(config).await;
        let manager = DeviceManager::new(Arc::new(hypervisor)).await.unwrap();
        for &(input, output) in [
            (0i32, "vda"),
            (25, "vdz"),
            (27, "vdab"),
            (704, "vdaac"),
            (18277, "vdzzz"),
        ]
        .iter()
        {
            let out = manager.get_virt_drive_name(input).unwrap();
            assert_eq!(&out, output);
        }
    }

    #[test]
    fn test_get_device_type() {
        let device_config = GenericConfig {
            dev_type: "b".to_string(),
            major: 1,
            minor: 1,
            ..Default::default()
        };
        let device_type = get_device_type(&device_config);
        assert_eq!(device_type, &DeviceType::VirtioBlk);
    }
}
