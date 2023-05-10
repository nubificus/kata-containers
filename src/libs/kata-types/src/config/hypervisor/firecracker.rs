use std::io::Result;
use std::path::Path;
use std::sync::Arc;

use super::{default, register_hypervisor_plugin};

use crate::config::default::MAX_FIRECRACKER_VCPUS;
use crate::config::default::MIN_FIRECRACKER_MEMORY_SIZE_MB;

use crate::config::{ConfigPlugin, TomlConfig};
use crate::{eother, resolve_path, validate_path};

use crate::config::hypervisor::{VIRTIO_FS, VIRTIO_FS_INLINE};

/// Hypervisor name for firecracker, used to index `TomlConfig::hypervisor`.
pub const HYPERVISOR_NAME_FIRECRACKER: &str = "firecracker";

/// Configuration information for firecracker.
#[derive(Default, Debug)]
pub struct FirecrackerConfig {}

impl FirecrackerConfig {
    /// Create a new instance of `FirecrackerConfig`.
    pub fn new() -> Self {
        FirecrackerConfig {}
    }

    /// Register the firecracker plugin.
    pub fn register(self) {
        let plugin = Arc::new(self);
        register_hypervisor_plugin(HYPERVISOR_NAME_FIRECRACKER, plugin);
    }
}

impl ConfigPlugin for FirecrackerConfig {
    fn get_max_cpus(&self) -> u32 {
        MAX_FIRECRACKER_VCPUS
    }

    fn get_min_memory(&self) -> u32 {
        MIN_FIRECRACKER_MEMORY_SIZE_MB
    }
    fn name(&self) -> &str {
        HYPERVISOR_NAME_FIRECRACKER
    }

    /// Adjust the configuration information after loading from configuration file.
    fn adjust_config(&self, conf: &mut TomlConfig) -> Result<()> {
        if let Some(firecracker) = conf.hypervisor.get_mut(HYPERVISOR_NAME_FIRECRACKER) {
            if firecracker.path.is_empty() {
                firecracker.path = default::DEFAULT_FIRECRACKER_BINARY_PATH.to_string();
            }
            resolve_path!(firecracker.path, "Firecracker binary path `{}` is invalid: {}")?;
            if firecracker.boot_info.kernel.is_empty() {
                firecracker.boot_info.kernel = default::DEFAULT_FIRECRACKER_GUEST_KERNEL_IMAGE.to_string();
            }
            if firecracker.boot_info.kernel_params.is_empty() {
                firecracker.boot_info.kernel_params =
                    default::DEFAULT_FIRECRACKER_GUEST_KERNEL_PARAMS.to_string();
            }
            if firecracker.machine_info.entropy_source.is_empty() {
                firecracker.machine_info.entropy_source = default::DEFAULT_FIRECRACKER_ENTROPY_SOURCE.to_string();
            }

            if firecracker.memory_info.default_memory == 0 {
                firecracker.memory_info.default_memory = default::DEFAULT_FIRECRACKER_MEMORY_SIZE_MB;
            }
        }

        Ok(())
    }

    /// Validate the configuration information.
    fn validate(&self, conf: &TomlConfig) -> Result<()> {
        if let Some(firecracker) = conf.hypervisor.get(HYPERVISOR_NAME_FIRECRACKER) {
            validate_path!(firecracker.path, "FIRECRACKER binary path `{}` is invalid: {}")?;
//            if !firecracker.valid_jailer_paths.is_empty() {
//                return Err(eother!("Valid Firecracker jailer path list should be empty"));
//            }

//We may not need this
//            if !firecracker.blockdev_info.disable_block_device_use
//                && firecracker.blockdev_info.block_device_driver == VIRTIO_BLK_MMIO
//                {
//                    return Err(eother!("Firecracker doesn't support virtio-blk-mmio"));
//                }

            if firecracker.boot_info.kernel.is_empty() {
                return Err(eother!("Guest kernel image for firecracker is empty"));
            }
//            if firecracker.boot_info.image.is_empty() && firecracker.boot_info.initrd.is_empty() {
//                return Err(eother!(
//                     "Both guest boot image and initrd for firecracker are empty"
//                  ));
//            }

            if (firecracker.cpu_info.default_vcpus > 0
                && firecracker.cpu_info.default_vcpus as u32 > default::MAX_FIRECRACKER_VCPUS)
                || firecracker.cpu_info.default_maxvcpus > default::MAX_FIRECRACKER_VCPUS
                {
                    return Err(eother!(
                            "Firecracker hypervisor can not support {} vCPUs",
                            firecracker.cpu_info.default_maxvcpus
                            ));
                }

//            if firecracker.device_info.default_bridges > default::MAX_FIRECRACKER_PCI_BRIDGES {
//              return Err(eother!(
//                    "Firecracker hypervisor can not support {} PCI bridges",
//                  firecracker.device_info.default_bridges
//                ));
//            }

            if let Some(v) = firecracker.shared_fs.shared_fs.as_ref() {
                if v != VIRTIO_FS && v != VIRTIO_FS_INLINE {
                    return Err(eother!("Firecracker hypervisor doesn't support {}", v));
                }
            }

            if firecracker.memory_info.default_memory < MIN_FIRECRACKER_MEMORY_SIZE_MB {
                return Err(eother!(
                        "Firecracker hypervisor has minimal memory limitation {}",
                        MIN_FIRECRACKER_MEMORY_SIZE_MB
                        ));
            }
        }

        Ok(())
    }
}
