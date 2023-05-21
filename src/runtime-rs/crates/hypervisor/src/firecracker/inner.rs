use anyhow::{anyhow, Context, Result};

use std::io::ErrorKind;

use crate::HypervisorState;

use crate::{device::DeviceType, kernel_param::KernelParams, NetworkConfig, VmmState};
use kata_types::{
    capabilities::{Capabilities, CapabilityBits},
    config::hypervisor::Hypervisor as HypervisorConfig,
};

use hyper::{Body, Client, Method, Request, Response};
use hyperlocal::{UnixClientExt, UnixConnector, Uri};

use crate::HYPERVISOR_FIRECRACKER;
use async_trait::async_trait;
use persist::sandbox_persist::Persist;
use serde_json::json;

use tokio::{fs, fs::File, process::Command};
//use std::os::unix::{io::AsRawFd, process::CommandExt};
use std::os::unix::io::AsRawFd;

use crate::firecracker::utils::{get_api_socket_path, get_sandbox_path, get_vsock_path};

use dbs_utils::net::MacAddr;

use kata_sys_util::mount;
use nix::mount::MsFlags;
use nix::sched::{setns, CloneFlags};

const REQUEST_RETRY: u32 = 500;

const FC_KERNEL: &str = "vmlinux";

const FC_ROOT_FS: &str = "rootfs";
const C_ROOTFS: &str = "container_rootfs";

const DISK_POOL_SIZE: u32 = 9;

unsafe impl Send for FcInner {}
unsafe impl Sync for FcInner {}

pub struct FcInner {
    pub(crate) id: String,
    pub(crate) asock_path: String,
    pub(crate) state: VmmState,
    pub(crate) config: HypervisorConfig,
    pub(crate) pid: Option<u32>,
    pub(crate) vm_path: String,
    pub(crate) netns: Option<String>,
    pub(crate) client: Client<UnixConnector>,
    pub(crate) jailer_root: String,
    pub(crate) jailed: bool,
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
            vm_path: String::default(),
            client: Client::unix(),
            jailer_root: String::default(),
            jailed: false,
            pending_devices: vec![],
            capabilities,
        }
    }

    pub(crate) async fn prepare_vmm(&mut self, netns: Option<String>) -> Result<()> {
        let mut cmd: Command;
        self.netns = netns.clone();
        match !self.jailed {
            true => {
                cmd = Command::new(&self.config.path);
                cmd.args(["--api-sock", &self.asock_path]);
            }
            false => {
                info!(sl!(), "Firecracker JAILED");
                cmd = Command::new(&self.config.jailer_path);
                let args = [
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
                    "--",
                    "--api-sock",
                    "run/fc.sock",
                ];
                cmd.args(&args);
                debug!(sl!(), "exec: {:?}", &args);
            }
        }

        debug!(sl!(), "Firecracker PATH: {:?}", &self.config.path);
        debug!(sl!(), "Firecracker JAILER: {:?}", &self.config.jailer_path);
        debug!(sl!(), "Firecracker JAILER ROOT: {:?}", &self.jailer_root);
        debug!(sl!(), "Firecracker asock_path: {:?}", &self.asock_path);

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
                info!(
                    sl!(),
                    "Firecracker started successfully with id: {:?}, {:?}", id, cur_tid
                );
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
        debug!(sl!(), "jail resource: src {} dst {}", src, dst);
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
        mount::bind_mount_unchecked(src, jailed_location.as_str(), false, MsFlags::MS_SLAVE)
            .context("bind_mount ERROR")?;

        let mut abs_path = String::from("/");
        abs_path.push_str(dst);
        debug!(sl!(), "abs_path: {:?}", abs_path);
        Ok(abs_path)
    }

    pub(crate) fn remount_jailer_with_exec(&self) -> Result<()> {
        debug!(
            sl!(),
            "FCInner: bind mount jailer_root: {:?}",
            self.jailer_root.as_str()
        );
        mount::bind_mount_unchecked(
            self.jailer_root.as_str(),
            self.jailer_root.as_str(),
            false,
            MsFlags::MS_SHARED,
        )
        .context("bind mount jailer root")?;

        debug!(
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
            Ok(_) => debug!(
                sl!(),
                "Deleted Firecracker API socket {:?}", self.asock_path
            ),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                debug!(
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
        debug!(sl!(), "PREPARING VSOCK");
        let uds_path = get_vsock_path(id, self.jailed, false)?;
        let rel_uds_path = get_vsock_path(id, self.jailed, true)?;

        debug!(sl!(), "UDS: {}", &uds_path);
        debug!(sl!(), "UDS REL: {}", &rel_uds_path);
        match fs::remove_file(&uds_path).await {
            Ok(_) => debug!(sl!(), "Deleted HybridV socket {:?}", &uds_path),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                debug!(sl!(), "HybridV socket not found {:?}", &uds_path);
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

        self.put_with_retry("/vsock", body_vsock).await?;
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
        debug!(sl!(), "prepared kernel_params={:?}", kernel_params);
        let mut parameters: String = String::new().to_owned();

        for param in &kernel_params.to_string() {
            parameters.push_str(&param.to_string());
        }

        let kernel = self
            .get_resource(&self.config.boot_info.kernel, FC_KERNEL)
            .context("get resource KERNEL")?;
        let rootfs = self
            .get_resource(&self.config.boot_info.image, FC_ROOT_FS)
            .context("get resource ROOTFS")?;

        debug!(sl!(), "string={:?}", parameters);
        let body_kernel: String = json!({
            "kernel_image_path": kernel,
            "boot_args": parameters,
        })
        .to_string();

        let body_rootfs: String = json!({
              "drive_id": "rootfs",
              "path_on_host": rootfs,
              "is_root_device": false,
              "is_read_only": true
        })
        .to_string();

        //self.put("/boot-source", body_kernel).await?;
        self.put_with_retry("/boot-source", body_kernel).await?;
        self.put_with_retry("/drives/rootfs", body_rootfs).await?;

        let sb_path = get_sandbox_path(id)?;
        //let r_path = [&sb_path, "rootfs"].join("/");
        let abs_dummy_path = match self.jailed {
            false => [&sb_path, "root"].join("/"),
            true => [&self.jailer_root, "firecracker", &self.id, "root"].join("/"),
        };

        //let _ = fs::create_dir_all(&r_path)
        let rel_dummy_path = "/".to_string();
        let _ = fs::create_dir_all(&abs_dummy_path)
            .await
            .context(format!("failed to create directory {:?}", &abs_dummy_path));

        debug!(
            sl!(),
            "CREATE DIR {:?} REL PATH {:?}", &abs_dummy_path, &rel_dummy_path
        );

        for i in 1..DISK_POOL_SIZE {
            //let full_path_name = format!("{}/drive{}.ext4", r_path, i);
            let full_path_name = format!("{}/drive{}.ext4", abs_dummy_path, i);

            let _ = File::create(&full_path_name)
                .await
                .context(format!("failed to create file {:?}", &full_path_name));

            let path_on_host = match self.jailed {
                false => abs_dummy_path.clone(),
                true => rel_dummy_path.clone(),
            };
            let body_dummy: String = json!({
                "drive_id": format!("drive{}",i),
                "path_on_host": format!("{}/drive{}.ext4", path_on_host, i),
                "is_root_device": false,
                "is_read_only": false
            })
            .to_string();

            self.put_with_retry(&format!("/drives/drive{}", i), body_dummy)
                .await?;
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
              "drive_id": format!("drive{drive_name}"),
              "path_on_host": new_c_rootfs

        })
        .to_string();
        self.patch(&["/drives/", &format!("drive{drive_name}")].concat(), body)
            .await?;
        Ok(())
    }

    pub(crate) async fn add_net_device(
        &mut self,
        config: &NetworkConfig,
        device_id: String,
    ) -> Result<()> {
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
        self.put_with_retry(&["/network-interfaces/", &device_id].concat(), body)
            .await?;
        Ok(())
    }

    pub(crate) async fn _put(&self, uri: &str, data: String) -> Result<Response<Body>> {
        let url: hyper::Uri = Uri::new(&self.asock_path, uri).into();
        let req = Request::builder()
            .method(Method::PUT)
            .uri(url.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Body::from(data))?;
        self.send_request(req).await
    }

    pub(crate) async fn put_with_retry(&self, uri: &str, data: String) -> Result<()> {
        let url: hyper::Uri = Uri::new(&self.asock_path, uri).into();
        let method = Method::PUT;
        self.send_request_with_retry(method, url, data).await
    }

    pub(crate) async fn patch(&self, uri: &str, data: String) -> Result<Response<Body>> {
        let url: hyper::Uri = Uri::new(&self.asock_path, uri).into();
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(url.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Body::from(data))?;
        debug!(sl!(), "PATCH URL {:?}", &url);
        debug!(sl!(), "PATCH REQ {:?}", &req);
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

    pub(crate) async fn send_request_with_retry(
        &self,
        method: Method,
        uri: hyper::Uri,
        data: String,
    ) -> Result<()> {
        for _count in 0..REQUEST_RETRY {
            let req = Request::builder()
                .method(method.clone())
                .uri(uri.clone())
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .body(Body::from(data.clone()))?;

            match self.send_request(req).await {
                Ok(resp) => {
                    debug!(sl!(), "Request sent, resp: {:?}", resp);
                    return Ok(());
                }
                Err(resp) => {
                    debug!(sl!(), "Request sent with error, resp: {:?}", resp);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
            }
        }
        Err(anyhow::anyhow!(
            "After {} attempts, it still doesn't work.",
            REQUEST_RETRY
        ))
    }

    pub(crate) async fn send_request(&self, req: Request<Body>) -> Result<Response<Body>> {
        //for count in 0..REQUEST_RETRY {
        //info!(sl!(), "SEND ({:?}) Request {:?}", req.method(), req);
        let resp = self.client.request(req).await?;

        let status = resp.status();
        debug!(sl!(), "Request RESPONSE {:?} {:?}", &status, resp);
        if status.is_success() {
            return Ok(resp);
        } else {
            let body = hyper::body::to_bytes(resp.into_body()).await?;
            if body.is_empty() {
                debug!(sl!(), "Request FAILED WITH STATUS: {:?}", status);
                None
            } else {
                let body = String::from_utf8_lossy(&body).into_owned();
                debug!(
                    sl!(),
                    "Request FAILED WITH STATUS: {:?} and BODY: {:?}", status, body
                );
                Some(body)
            };
        }

        //}
        Err(anyhow::anyhow!(
            "After {} attempts, it still doesn't work.",
            REQUEST_RETRY
        ))
    }

    pub(crate) fn cleanup_resource(&self, sb_path: &String) {
        if self.jailed {
            let jailed_path = ["firecracker", &self.id, "root"].join("/");
            self.umount_jail_resource(&[jailed_path.clone(), FC_KERNEL.to_string()].join("/"))
                .ok();
            self.umount_jail_resource(&[jailed_path.clone(), FC_ROOT_FS.to_string()].join("/"))
                .ok();
            self.umount_jail_resource(&[jailed_path.clone(), C_ROOTFS.to_string()].join("/"))
                .ok();
            self.umount_jail_resource("").ok();

            std::fs::remove_dir_all(
                &[
                    self.jailer_root.clone(),
                    "firecracker".to_string(),
                    self.id.clone(),
                ]
                .join("/"),
            )
            .map_err(|err| {
                error!(sl!(), "failed to remove dir all for {}", &jailed_path);
                err
            })
            .ok();
        }
        std::fs::remove_dir_all(sb_path)
            .map_err(|err| {
                error!(sl!(), "failed to remove dir all for {}", &sb_path);
                err
            })
            .ok();
    }

    pub(crate) fn umount_jail_resource(&self, jailed_path: &str) -> Result<()> {
        let path = [self.jailer_root.as_str(), jailed_path].join("/");
        debug!(sl!(), "umount: {:?}", path);
        mount::umount_all(path.as_str(), false).with_context(|| format!("umount path {}", &path))
        //nix::mount::umount2(path.as_str(), nix::mount::MntFlags::MNT_DETACH)
        //    .with_context(|| format!("umount path {}", &path))
    }

    pub(crate) fn hypervisor_config(&self) -> HypervisorConfig {
        debug!(sl!(), "FcInner: Hypervisor config");
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
            vm_path: self.vm_path.clone(),
            config: self.hypervisor_config(),
            jailed: self.jailed,
            jailer_root: self.jailer_root.clone(),
            netns: self.netns.clone(),
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
            vm_path: hypervisor_state.vm_path,
            config: hypervisor_state.config,
            netns: hypervisor_state.netns,
            //netns: None,
            pid: None,
            jailed: hypervisor_state.jailed,
            jailer_root: hypervisor_state.jailer_root,
            client: Client::unix(),
            pending_devices: vec![],
            capabilities: Capabilities::new(),
        })
    }
}
