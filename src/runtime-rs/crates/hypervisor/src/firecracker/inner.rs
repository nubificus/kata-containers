use anyhow::{Context, Result};

use std::{io::ErrorKind, path::Path};

use crate::HypervisorState;

use crate::{
    device::DeviceType,NetworkConfig,
    VmmState,
    kernel_param::KernelParams,
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
//use std::os::unix::{io::AsRawFd, process::CommandExt};
use std::{os::unix::io::AsRawFd};

use crate::firecracker::utils::{get_api_socket_path, get_sandbox_path, get_vsock_path};

use dbs_utils::net::MacAddr;

use nix::sched::{setns, CloneFlags};

const DISK_POOL_SIZE: u32 = 9;

unsafe impl Send for FcInner {}
unsafe impl Sync for FcInner {}

pub struct FcInner {
    pub(crate) id: String,
    //pub(crate) fc_path: String,
    pub(crate) asock_path: String,
    pub(crate) state: VmmState,
    pub(crate) config: HypervisorConfig,
    pub(crate) pid: Option<u32>,
    //pub(crate) config_json: ,
    pub(crate) netns: Option<String>,
    pub(crate) client: Client<UnixConnector>,
    //pub(crate) has_conf: bool,
    pub(crate) pending_devices: Vec<DeviceType>,
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
            netns: None,
            //config_json: Path::new("").into(),
            client: Client::unix(),
            //has_conf: false,
            pending_devices: vec![],
            capabilities,
        }
    }

    pub(crate) async fn prepare_vmm(&mut self, netns: Option<String>) -> Result<()> {
        let mut cmd = Command::new(&self.config.path);
        info!(sl!(), "Firecracker PATH: {:?}", &self.config.path);
        cmd.args(["--api-sock", &self.asock_path]);
        
        unsafe {
            let _pre = cmd.pre_exec(move || {
                if let Some(netns_path) = &netns {
                    info!(sl!(), "set netns for vmm master {:?}", &netns_path);
                    let netns_fd = std::fs::File::open(netns_path);
                    let _ = setns(netns_fd?.as_raw_fd(), CloneFlags::CLONE_NEWNET)
                        .context("set netns failed");
                }
                Ok(())
            });
        }

        let mut child = cmd.spawn()?;

        match child.id() {
       
            Some(id) => {
                let cur_tid = nix::unistd::gettid().as_raw() as u32;
                info!(sl!(), "Firecracker started successfully with id: {:?}, {:?}", id, cur_tid);
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

    pub(crate) async fn prepare_api_socket(&mut self, id: &str) -> Result<()> {
        let sb_path = get_sandbox_path(id)?;
        let r_path = [&sb_path, "root"].join("/");

        let _ = fs::create_dir_all(&r_path)
            .await
            .context(format!("failed to create directory {:?}", &sb_path));

        self.asock_path = get_api_socket_path(id)?;

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
        let uds_path = get_vsock_path(id)?;

        info!(sl!(), "UDS: {}", &uds_path);
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
            "uds_path": uds_path,
            "vsock_id": "root"
        })
        .to_string();

        self.put("/vsock", body_vsock).await?;
        info!(sl!(), "start busy wait on prepare hvsock");
        while !Path::new(&uds_path).exists() {}
        Ok(())
    }

    pub(crate) async fn prepare_vmm_resources(&mut self, id: &str) -> Result<()> {
        //
        // get kernel params
        let mut kernel_params = KernelParams::new(self.config.debug_info.enable_debug);
        // get rootfs driver
        let rootfs_driver = self.config.blockdev_info.block_device_driver.clone();

        kernel_params.append(&mut KernelParams::new_rootfs_kernel_params(
            &rootfs_driver,
            &self.config.boot_info.rootfs_type,
        )?);
        kernel_params.append(&mut KernelParams::from_string(
            &self.config.boot_info.kernel_params,
        ));
        info!(sl!(), "prepared kernel_params={:?}", kernel_params);
        let mut parameters: String = String::new().to_owned();

        for param in &kernel_params.to_string() {
            parameters.push_str(&param.to_string());
        }

        info!(sl!(), "string={:?}", parameters);
        let body_kernel: String = json!({
            "kernel_image_path": &self.config.boot_info.kernel,
            "boot_args": parameters,
        })
        .to_string();

        let body_rootfs: String = json!({
              "drive_id": "rootfs",
              "path_on_host": &self.config.boot_info.image,
              "is_root_device": false,
              "is_read_only": true
        })
        .to_string();

        //FIXME busywait
        // similar to
        // https://github.com/kata-containers/kata-containers/blob/109071855df8d73af9bb089c2a4a1d9006c08bb3/src/runtime-rs/crates/hypervisor/src/ch/inner_hypervisor.rs#L163
        info!(sl!(), "start busy wait on prepare resources");
        while !Path::new(&self.asock_path).exists() {}

        self.put("/boot-source", body_kernel).await?;
        self.put("/drives/rootfs", body_rootfs).await?;

        let sb_path = get_sandbox_path(id)?;
        let r_path = [&sb_path, "rootfs"].join("/");

        let _ = fs::create_dir_all(&r_path)
            .await
            .context(format!("failed to create directory {:?}", &r_path));

        for i in 1..DISK_POOL_SIZE {
            let full_path_name = format!("{}/drive{}.ext4", r_path, i);

            let _ = File::create(&full_path_name)
                .await
                .context(format!("failed to create file {:?}", &full_path_name));

            let body_dummy: String = json!({
                "drive_id": format!("drive{}",i),
                "path_on_host": full_path_name,
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
        let body: String = json!({
              "drive_id": format!("drive{drive_name}"),
              "path_on_host": c_rootfs

        })
        .to_string();
        info!(sl!(), "start busy wait on patch rootfs");
        while !Path::new(&self.asock_path).exists() {}
        self.patch(&["/drives/", &format!("drive{drive_name}")].concat(), body).await?;
        Ok(())
    }

    pub(crate) async fn add_net_device(&mut self, config: &NetworkConfig, device_id: String) -> Result<()> {
        let g_mac = match &config.guest_mac {
            Some(mac) => MacAddr::from_bytes(&mac.0).ok(),
            None => None,
        };
        let body: String = json!({
            "iface_id": &device_id,
            "guest_mac": g_mac,
            "host_dev_name": &config.host_dev_name

        })
        .to_string();
        info!(sl!(), "start busy wait on addnet");
        while !Path::new(&self.asock_path).exists() {}
        self.put(&["/network-interfaces/", &device_id].concat(), body)
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
        info!(sl!(), "SEND ({:?}) Request {:?}", req.method(), req);
        let resp = self.client.request(req).await?;

        let status = resp.status();
        info!(sl!(), "Request RESPONSE {:?} {:?}", &status, resp);
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
            //make sure this is correct
            vm_path: self.config.path.clone(),
            config: self.hypervisor_config(),
            //will change when jail is implemented
            jailed: false,
            jailer_root: String::default(),
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
            //netns: self.netns,
            netns: None,
            pid: None,
            //config_json: Path::new("").into(),
            client: Client::unix(),
            //has_conf: false,
            pending_devices: vec![],
            //make sure this is correct down the line
            capabilities: Capabilities::new(),
        })
    }
}
