use anyhow::{anyhow, Context, Result};

use std::{io::ErrorKind, path::Path};

use crate::HypervisorState;

use crate::{
    device_type::{DeviceConfig, NetworkConfig},
    VmmState,
};
use kata_types::{
    capabilities::{Capabilities, CapabilityBits},
    config::hypervisor::Hypervisor as HypervisorConfig,
};

use hyper::{Body, Client, Method, Request};
use hyperlocal::{UnixClientExt, UnixConnector, Uri};

use crate::HYPERVISOR_FIRECRACKER;
use async_trait::async_trait;
use persist::sandbox_persist::Persist;
use serde_json::json;
use tokio::{fs, fs::File, process::Command};

use crate::firecracker::utils::*;

use dbs_utils::net::MacAddr;
use kata_sys_util::mount;

const DISK_POOL_SIZE: u32 = 9;
const FC_KERNEL: &str = "vmlinux";
const FC_ROOT_FS: &str = "rootfs";
const C_ROOTFS: &str = "container_rootfs";

unsafe impl Send for FcInner {}
unsafe impl Sync for FcInner {}

pub struct FcInner {
    pub(crate) id: String,
    pub(crate) asock_path: String,
    pub(crate) state: VmmState,
    pub(crate) config: HypervisorConfig,
    pub(crate) pid: Option<u32>,
    pub(crate) client: Client<UnixConnector>,
    pub(crate) jailer_root: String,
    pub(crate) jailed: bool,
    pub(crate) pending_devices: Vec<DeviceConfig>,
    pub(crate) capabilities: Capabilities,
}

impl FcInner {
    pub fn new() -> FcInner {
        let mut capabilities = Capabilities::new();
        capabilities.set(CapabilityBits::BlockDeviceSupport);
        FcInner {
            id: String::default(),
            asock_path: String::default(),
            state: VmmState::NotReady,
            config: Default::default(),
            pid: None,
            client: Client::unix(),
            jailer_root: String::default(),
            jailed: false,
            pending_devices: vec![],
            capabilities,
        }
    }

    pub(crate) async fn prepare_vmm(&mut self) -> Result<()> {
        let mut cmd: Command;
        match !self.jailed {
            true => {
                cmd = Command::new(&self.config.path);
                cmd.args(["--api-sock", &self.asock_path]);
            }
            false => {
                info!(sl!(), "Firecracker JAILED");
                cmd = Command::new(&self.config.jailer_path);
                cmd.args([
                    "--id",
                    &self.id,
                    "--gid",
                    "0",
                    "--uid",
                    "0",
                    "--exec-file",
                    &self.config.path,
                    "--chroot-base-dir",
                    &self.jailer_root,
                    "--daemonize",
                ]);
            }
        }

        info!(sl!(), "Firecracker PATH: {:?}", &self.config.path);
        info!(sl!(), "Firecracker JAILER: {:?}", &self.config.jailer_path);
        info!(sl!(), "Firecracker JAILER ROOT: {:?}", &self.jailer_root);
        let mut child = cmd.spawn()?;
        match child.id() {
            Some(id) => {
                info!(sl!(), "Firecracker started successfully with id: {:?}", id);
                self.pid = Some(id);
            }
            None => {
                let exit_status = child.wait().await?;
                error!(
                    sl!(),
                    "ERROR FC process exited Immediatelly {:?}", exit_status
                );
            }
        };
        Ok(())
    }

    pub(crate) fn get_resource(&self, src: &str, dst: &str) -> Result<String> {
        if self.jailed {
            self.jail_resource(src, dst)
        } else {
            Ok(src.to_string())
        }
    }

    fn jail_resource(&self, src: &str, dst: &str) -> Result<String> {
        info!(sl!(), "jail resource: src {} dst {}", src, dst);
        if src.is_empty() || dst.is_empty() {
            return Err(anyhow!("invalid param src {} dst {}", src, dst));
        }

        let jailed_location = [
            self.jailer_root.as_str(),
            "firecracker",
            &self.id,
            "root",
            dst,
        ]
        .join("/");
        mount::bind_mount_unchecked(src, jailed_location.as_str(), false)
            .context("bind_mount ERROR")?;

        let mut abs_path = String::from("/");
        abs_path.push_str(dst);
        Ok(abs_path)
    }

    pub(crate) fn remount_jailer_with_exec(&self) -> Result<()> {
        info!(
            sl!(),
            "FCInner: bind mount jailer_root: {:?}",
            self.jailer_root.as_str()
        );
        mount::bind_mount_unchecked(self.jailer_root.as_str(), self.jailer_root.as_str(), false)
            .context("bind mount jailer root")?;

        info!(
            sl!(),
            "FCInner: REbind mount jailer_root: {:?}",
            self.jailer_root.as_str()
        );
        mount::bind_remount(self.jailer_root.as_str(), false)
            .context("rebind mount jailer root")?;
        Ok(())
    }

    pub(crate) async fn prepare_api_socket(&mut self, id: &str) -> Result<()> {
        self.asock_path = get_api_socket_path(id, self.jailed, false)?;

        match fs::remove_file(&self.asock_path).await {
            Ok(_) => info!(
                sl!(),
                "Deleted Firecracker API socket {:?}", self.asock_path
            ),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                info!(
                    sl!(),
                    "Firecracker API socket not found {:?}", self.asock_path
                );
            }
            Err(e) => error!(
                sl!(),
                "ERROR: {:?} deleting API socket {:?}", e, self.asock_path
            ),
        }
        Ok(())
    }

    pub(crate) async fn prepare_hvsock(&mut self, id: &str) -> Result<()> {
        info!(sl!(), "PREPARING VSOCK");
        let uds_path = get_vsock_path(id, self.jailed, false)?;
        let rel_uds_path = get_vsock_path(id, self.jailed, true)?;

        info!(sl!(), "UDS: {}", &uds_path);
        info!(sl!(), "UDS REL: {}", &rel_uds_path);
        match fs::remove_file(&uds_path).await {
            Ok(_) => info!(sl!(), "Deleted HybridV socket {:?}", &uds_path),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                info!(sl!(), "HybridV socket not found {:?}", &uds_path);
            }
            Err(e) => error!(
                sl!(),
                "ERROR: {:?} deleting HybridV socket {:?}", e, &uds_path
            ),
        }
        let body_vsock: String = json!({
            "guest_cid": 3,
            "uds_path": rel_uds_path,
            "vsock_id": "root"
        })
        .to_string();

        self.put("/vsock", body_vsock).await?;
        while !Path::new(&uds_path).exists() {}
        Ok(())
    }

    pub(crate) async fn prepare_vmm_resources(&mut self, id: &str) -> Result<()> {
        let kernel = self
            .get_resource(&self.config.boot_info.kernel, FC_KERNEL)
            .context("get resource KERNEL")?;
        let rootfs = self
            .get_resource(&self.config.boot_info.image, FC_ROOT_FS)
            .context("get resource ROOTFS")?;

        let body_kernel: String = json!({
            "kernel_image_path": kernel,
            "boot_args": &self.config.boot_info.kernel_params
        })
        .to_string();

        let body_rootfs: String = json!({
              "drive_id": "rootfs",
              "path_on_host": rootfs,
              "is_root_device": false,
              "is_read_only": true
        })
        .to_string();

        info!(sl!(), "ASOCK_PATH: {}", &self.asock_path);

        //FIXME busywait
        //let _ = wait_api_socket(&self.asock_path);
        while !Path::new(&self.asock_path).exists() {}

        self.put("/boot-source", body_kernel).await?;
        self.put("/drives/rootfs", body_rootfs).await?;

        let sb_path = get_sandbox_path(id)?;
        let abs_dummy_path = match self.jailed {
            false => [&sb_path, "root", "dummies"].join("/"),
            true => [&sb_path, "firecracker", id, "root", "dummies"].join("/"),
        };

        let rel_dummy_path = match self.jailed {
            false => abs_dummy_path.clone(),
            true => "dummies".to_string(),
            //["root", "dummies"].join("/"),
        };
        let _ = fs::create_dir_all(&abs_dummy_path)
            .await
            .context(format!("failed to create directory {:?}", &abs_dummy_path));

        for i in 1..DISK_POOL_SIZE {
            let full_path_name = format!("{}/drive{}.ext4", abs_dummy_path, i);

            let _ = File::create(&full_path_name)
                .await
                .context(format!("failed to create file {:?}", &full_path_name));

            let body_dummy: String = json!({
                "drive_id": format!("drive{}",i),
                "path_on_host": format!("{}/drive{}.ext4", rel_dummy_path, i),
                "is_root_device": false,
                "is_read_only": false
            })
            .to_string();

            self.put(&format!("/drives/drive{}", i), body_dummy).await?;
        }

        Ok(())
    }
    pub(crate) async fn patch_container_rootfs(
        &mut self,
        drive_name: &str,
        c_rootfs: &str,
    ) -> Result<()> {
        let new_c_rootfs = self
            .get_resource(&c_rootfs, C_ROOTFS)
            .context("get resource CONTAINER ROOTFS")?;

        let body: String = json!({
            "drive_id": drive_name,
            "path_on_host": new_c_rootfs

        })
        .to_string();
        info!(sl!(), "PATCH BODY {:?}", &body);
        while !Path::new(&self.asock_path).exists() {}
        self.patch(&["/drives/", drive_name].concat(), body).await?;
        Ok(())
    }

    pub(crate) async fn add_net_device(&mut self, config: &NetworkConfig) -> Result<()> {
        let g_mac = match &config.guest_mac {
            Some(mac) => MacAddr::from_bytes(&mac.0).ok(),
            None => None,
        };
        let body: String = json!({
            "iface_id": &config.id,
            "guest_mac": g_mac,
            "host_dev_name": &config.host_dev_name

        })
        .to_string();
        while !Path::new(&self.asock_path).exists() {}
        self.put(&["/network-interfaces/", &config.id].concat(), body)
            .await?;
        Ok(())
    }

    pub(crate) async fn put(&self, uri: &str, data: String) -> Result<()> {
        let url: hyper::Uri = Uri::new(&self.asock_path, uri).into();
        let req = Request::builder()
            .method(Method::PUT)
            .uri(url.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Body::from(data))?;
        self.send_request(req).await
    }

    pub(crate) async fn patch(&self, uri: &str, data: String) -> Result<()> {
        let url: hyper::Uri = Uri::new(&self.asock_path, uri).into();
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(url.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Body::from(data))?;
        info!(sl!(), "PATCH URL {:?}", &url);
        info!(sl!(), "PATCH REQ {:?}", &req);
        self.send_request(req).await
    }

    pub(crate) async fn instance_start(&self) -> Result<()> {
        let url: hyper::Uri = Uri::new(&self.asock_path, "/actions").into();
        let req = Request::builder()
            .method(Method::PUT)
            .uri(url.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Body::from(
                "{
                    \"action_type\": \"InstanceStart\"
                   }",
            ))?;
        let _ = self.send_request(req).await;
        Ok(())
    }

    pub(crate) async fn send_request(&self, req: Request<Body>) -> Result<()> {
        info!(sl!(), "SEND ({:?}) Request ", req.method());
        let resp = self.client.request(req).await?;

        let status = resp.status();
        info!(sl!(), "Request RESPONSE {:?}", &status);
        if status.is_success() {
        } else {
            let body = hyper::body::to_bytes(resp.into_body()).await?;
            if body.is_empty() {
                info!(sl!(), "Request FAILED WITH STATUS: {:?}", status);
                None
            } else {
                let body = String::from_utf8_lossy(&body).into_owned();
                info!(
                    sl!(),
                    "Request FAILED WITH STATUS: {:?} and BODY: {:?}", status, body
                );
                Some(body)
            };
        }

        Ok(())
    }

    pub(crate) fn cleanup_resource(&self, sb_path: &String) {
        if self.jailed {
            self.umount_jail_resource(FC_KERNEL).ok();
            self.umount_jail_resource(FC_ROOT_FS).ok();
//            for id in &self.cached_block_devices {
//                self.umount_jail_resource(id.as_str()).ok();
//            }
        }
//        std::fs::remove_dir_all(sb_path)
//            .map_err(|err| {
//                error!(sl!(), "failed to remove dir all for {}", &sb_path);
//                err
//            })
//            .ok();
    }

    pub(crate) fn umount_jail_resource(&self, jailed_path: &str) -> Result<()> {
        let path = [self.jailer_root.as_str(), jailed_path].join("/");
        info!(sl!(), "FcInner: UNMOUNT JAIL RESOURCE");
        nix::mount::umount2(path.as_str(), nix::mount::MntFlags::MNT_DETACH)
            .with_context(|| format!("umount path {}", &path))
    }

    pub(crate) fn hypervisor_config(&self) -> HypervisorConfig {
        info!(sl!(), "FcInner: Hypervisor config");
        self.config.clone()
    }

    pub(crate) fn set_hypervisor_config(&mut self, config: HypervisorConfig) {
        self.config = config;
    }
}

#[async_trait]
impl Persist for FcInner {
    type State = HypervisorState;
    type ConstructorArgs = ();

    async fn save(&self) -> Result<Self::State> {
        Ok(HypervisorState {
            hypervisor_type: HYPERVISOR_FIRECRACKER.to_string(),
            id: self.id.clone(),
            vm_path: self.config.path.clone(),
            config: self.hypervisor_config(),
            jailed: self.jailed,
            jailer_root: self.jailer_root.clone(),
            netns: None,
            ..Default::default()
        })
    }
    async fn restore(
        _hypervisor_args: Self::ConstructorArgs,
        hypervisor_state: Self::State,
    ) -> Result<Self> {
        Ok(FcInner {
            id: hypervisor_state.id,
            asock_path: String::default(),
            state: VmmState::NotReady,
            config: hypervisor_state.config,
            pid: None,
            jailed: hypervisor_state.jailed,
            jailer_root: hypervisor_state.jailer_root,
            client: Client::unix(),
            pending_devices: vec![],
            capabilities: Capabilities::new(),
        })
    }
}
