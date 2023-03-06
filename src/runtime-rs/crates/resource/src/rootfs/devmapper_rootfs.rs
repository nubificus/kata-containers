use agent::Storage;
use anyhow::{Context, Result};
use async_trait::async_trait;
use kata_sys_util::mount::{umount_timeout, Mounter};
use kata_types::mount::Mount;
use std::sync::Arc;

use super::{Rootfs, ROOTFS};
use crate::share_fs::{ShareFs, ShareFsRootfsConfig};

pub(crate) struct DevmapperRootfs {
        guest_path: String,
}

impl DevmapperRootfs {
    pub async fn new(rootfs: &Mount) -> Result<Self>{
        let placeholder = rootfs.destination.as_path().display().to_string();
        Ok(DevmapperRootfs {
            //placeholder for now
            guest_path: placeholder
        })
    }
}

#[async_trait]
impl Rootfs for DevmapperRootfs {
    async fn get_guest_rootfs_path(&self) -> Result<String> {
        Ok(self.guest_path.clone())
    }

    async fn get_rootfs_mount(&self) -> Result<Vec<oci::Mount>> {
        Ok(vec![])
    }

    async fn get_storage(&self) -> Option<Storage> {
        None
    }

//    async fn cleanup(&self) -> Result<()> {
//        Ok(())
//    }
}
