use anyhow::{anyhow, Context, Result};

use std::{io::ErrorKind, path::Path, path::PathBuf};

use crate::HypervisorState;
use crate::VsockConfig;
use crate::VcpuThreadIds;
use crate::{device::Device, VmmState};
use kata_types::{
    capabilities::{Capabilities, CapabilityBits},
    config::hypervisor::Hypervisor as HypervisorConfig,
};
use shim_interface::KATA_PATH;
use crate::HybridVsockConfig;

use hyper::{Body, Client, Method, Request, Response};
use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use sysinfo::{Pid, ProcessExt, ProcessRefreshKind, System, SystemExt};

use tokio::{
    fs,
    process::Command,
    time::{sleep, Duration},
};
use persist::sandbox_persist::Persist;
use async_trait::async_trait;
use serde_json::json;
use crate::HYPERVISOR_FIRECRACKER;

const FC_API_SOCKET_NAME: &str = "fc.sock";
const FC_AGENT_SOCKET_NAME: &str = "kata.hvsock";


unsafe impl Send for FcInner {}
unsafe impl Sync for FcInner {}

pub struct FcInner {
    pub(crate) id: String,
    //pub(crate) fc_path: String,
    pub(crate) asock_path: String,
    pub(crate) state: VmmState,
    pub(crate) config: HypervisorConfig,
    //pub(crate) config_json: ,
    pub(crate) client: Client<UnixConnector>,
    //pub(crate) has_conf: bool,
    pub(crate) pending_devices: Vec<Device>,
    pub(crate) capabilities: Capabilities,
}

impl FcInner {
    pub fn new() -> FcInner {
        let mut capabilities = Capabilities::new();
        capabilities.set(
            CapabilityBits::BlockDeviceSupport
            );
        FcInner {
            id: String::default(),
            asock_path: String::default(),
            state: VmmState::NotReady,
            config: Default::default(),
            //config_json: Path::new("").into(),
            client: Client::unix(),
            //has_conf: false,
            pending_devices: vec![],
            capabilities
        }
    }
    pub(crate) async fn prepare_vm(&mut self, id: &str, _netns: Option<String>) -> Result<()> {
        info!(sl!(), "Preparing Firecracker");

        self.id=id.to_string();
        self.prepare_api_socket(&id).await?;
        self.prepare_vmm().await?;
        self.state = VmmState::VmmServerReady;
        self.prepare_vmm_resources().await?;
        self.prepare_hvsock(&id).await?;
        Ok(())
    }

    pub(crate) async fn start_vm(&mut self, _timeout: i32) -> Result<()> {
        info!(sl!(), "Starting Firecracker");
        self.instance_start().await?;
        self.patch_container_rootfs().await?;
//        self.patch("/drives/drive1");
//        let body_container_rootfs: String = json!({
//              "drive_id": "drive1",
//              "path_on_host": "container_rootfs",
//        })
//        .to_string();
        self.state = VmmState::VmRunning;
        Ok(())
    }
    //alot of error handling here
    pub(crate) async fn stop_vm(&mut self) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn prepare_vmm(&mut self) -> Result<()> {
        let mut cmd = Command::new(&self.config.path);
        info!(sl!(), "Firecracker PATH: {:?}", &self.config.path);
        cmd.args(&["--api-sock", &self.asock_path]);
        let mut child = cmd.spawn()?;
        match child.id() {
            Some(id) => {
                info!(sl!(), "Firecracker started successfully with id: {:?}", id);
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
        let r_path=[&sb_path, "root"].join("/");

        fs::create_dir_all(&r_path)
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
            Err(e) => error!(sl!(), "ERROR deletingr API socket {:?}", self.asock_path),
        }
        Ok(())
    }


    pub(crate) async fn prepare_hvsock(&mut self, id: &str) -> Result<()>{
        info!(sl!(), "PREPARING VSOCK");
        let uds_path=get_vsock_path(&id)?;

        info!(sl!(), "UDS: {}",&uds_path);
        match fs::remove_file(&uds_path).await {
            Ok(_) => info!(
                sl!(),
                "Deleted HybridV socket {:?}", &uds_path
            ),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                info!(
                    sl!(),
                    "HybridV socket not found {:?}", &uds_path
                );
            }
            Err(e) => error!(sl!(), "ERROR deleting HybridV socket {:?}", &uds_path),
        }
        let body_vsock: String = json!({
            "guest_cid": 3,
            "uds_path": uds_path,
            "vsock_id": "root"
        })
        .to_string();

        self.put("/vsock",body_vsock).await?;
        while !Path::new(&uds_path).exists() {}
        Ok(())
    }


    pub(crate) async fn prepare_vmm_resources(&mut self) -> Result<()> {
        let body_kernel: String = json!({
            "kernel_image_path": &self.config.boot_info.kernel,
            "boot_args": "systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service systemd.mask=systemd-networkd.socket root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 pci=off reboot=k panic=1 iommu=off net.ifnames=0 random.trust_cpu=on acpi=off agent.log_vport=1025 console=ttyS0"
        })
        .to_string();

        let body_rootfs: String = json!({
              "drive_id": "rootfs",
              "path_on_host": &self.config.boot_info.image,
              "is_root_device": false,
              "is_read_only": true
        })
        .to_string();

        let body_dummy: String = json!({
              "drive_id": "drive1",
              "path_on_host": "/opt/kata/share/kata-containers2/rootfs3.ext4",
              "is_root_device": false,
              "is_read_only": true
        })
        .to_string();
        

        //FIXME busywait
        // similar to
        // https://github.com/kata-containers/kata-containers/blob/109071855df8d73af9bb089c2a4a1d9006c08bb3/src/runtime-rs/crates/hypervisor/src/ch/inner_hypervisor.rs#L163
        while !Path::new(&self.asock_path).exists() {}
        self.put("/boot-source", body_kernel).await?;
        self.put("/drives/rootfs", body_rootfs).await?;
        self.put("/drives/drive1", body_dummy).await?;
        //info!(sl!(), "PUT Request DUMMY");
        Ok(())
    }
    pub(crate) async fn patch_container_rootfs(&mut self)-> Result<()>{
        let body_dummy: String = json!({
              "drive_id": "drive1",
              "path_on_host": "/opt/kata/share/kata-containers2/rootfs3.ext4",
        })
        .to_string();
        while !Path::new(&self.asock_path).exists() {}
        self.patch("/drives/drive1", body_dummy).await?;
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
        return self.send_request(req).await;
    }

    pub(crate) async fn patch(&self, uri: &str, data: String) -> Result<()> {
        let url: hyper::Uri = Uri::new(&self.asock_path, uri).into();
        //info!(sl!(), "PATCH Request to uri{:?}", uri);
        //info!(sl!(), "PATCH Request SOCK: {:?}", &self.asock_path);
        //info!(sl!(), "PATCH Request URL: {:?}", &url);
        //info!(sl!(), "PATCH Request URI: {:?}", &uri);
        //info!(sl!(), "PATCH Request BODY: {:?}", &data);
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(url.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Body::from(data))?;
        info!(sl!(), "PATCH Request WHOLE{:?}", &req);
        return self.send_request(req).await;
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
        self.send_request(req).await;
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
            let body = if body.is_empty() {
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
        //    match self.timeout {
        //        Some(timeout) => match tokio::time::timeout(timeout, resp).await {
        //            Ok(result) => result.map_err(|e| anyhow!(e)),
        //            Err(_) => Err(anyhow!("{:?} timeout after {:?}", msg, self.timeout)),
        //        },
        //        None => resp.await.context(format!("{:?} failed", msg)),
        //    }
    }

    pub(crate) fn pause_vm(&self) -> Result<()> {
        info!(sl!(), "Pausing Firecracker");
        todo!()
    }

    pub(crate) async fn save_vm(&self) -> Result<()> {
        info!(sl!(), "Saving Firecracker");
        todo!()
    }
    pub(crate) fn resume_vm(&self) -> Result<()> {
        info!(sl!(), "Resuming Firecracker");
        todo!()
    }

    pub(crate) async fn get_agent_socket(&self) -> Result<String> {
        const HYBRID_VSOCK_SCHEME: &str = "hvsock";
        info!(sl!(), "FcInner: Get agent socket");
        let vsock_path=get_vsock_path(&self.id)?;
        Ok(format!(
            "{}://{}",
            HYBRID_VSOCK_SCHEME, vsock_path
        ))
    }

    pub(crate) async fn disconnect(&mut self) {
        info!(sl!(), "FcInner: Disconnect");
        todo!()
    }

    pub(crate) fn hypervisor_config(&self) -> HypervisorConfig {
        info!(sl!(), "FcInner: Hypervisor config");
        self.config.clone()
    }

    pub(crate) fn set_hypervisor_config(&mut self, config: HypervisorConfig) {
        self.config = config;
    }

    pub(crate) async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        info!(sl!(), "FcInner: Getthread ids");
        Ok(VcpuThreadIds::default())
    }

    pub(crate) async fn get_pids(&self) -> Result<Vec<u32>> {
        info!(sl!(), "FcInner: Get pids");
        todo!()
    }

    pub(crate) async fn get_vmm_master_tid(&self) -> Result<u32> {
        info!(sl!(), "FcInner: get vmm master tid");
        todo!()
    }

    pub(crate) async fn get_ns_path(&self) -> Result<String> {
        info!(sl!(), "FcInner: get ns path");
        todo!()
    }

    pub(crate) async fn cleanup(&self) -> Result<()> {
        info!(sl!(), "FcInner: Cleanup");
        todo!()
    }

    pub(crate) async fn check(&self) -> Result<()> {
        info!(sl!(), "FcInner: Check");
        todo!()
    }

    pub(crate) async fn get_jailer_root(&self) -> Result<String> {
        info!(sl!(), "FcInner: Get jailerroot");
        todo!()
    }
    pub(crate) async fn save_state(&self) -> Result<HypervisorState> {
        info!(sl!(), "FcInner: Save state");
        todo!()
    }
    //check this later
    pub(crate) async fn capabilities(&self) -> Result<Capabilities> {
        Ok(self.capabilities.clone())
    }

}

#[async_trait]
impl Persist for FcInner{
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
            //config_json: Path::new("").into(),
            client: Client::unix(),
            //has_conf: false,
            pending_devices: vec![],
            //make sure this is correct down the line
            capabilities: Capabilities::new(),
        })
    }
}
    //Could be move to a new file at a later time
    pub(crate) fn get_sandbox_path(id: &str) -> Result<String> {
        Ok([KATA_PATH, id].join("/"))
    }

    pub(crate) fn get_api_socket_path(id: &str) -> Result<String> {
        let sb_path = get_sandbox_path(id)?;
        Ok([&sb_path, FC_API_SOCKET_NAME].join("/"))
    }

    pub(crate) fn get_vsock_path(id: &str) -> Result<String> {
        let sb_path = get_sandbox_path(id)?;
        Ok([&sb_path, "root" ,FC_AGENT_SOCKET_NAME].join("/"))
    }
