use anyhow::{anyhow, Context, Result};

use std::{path::Path, path::PathBuf, io::ErrorKind};

use crate::{device::Device, VmmState};
use crate::HypervisorState;
use crate::VcpuThreadIds;
use kata_types::{
    capabilities::{Capabilities, CapabilityBits},
    config::hypervisor::Hypervisor as HypervisorConfig
};
use shim_interface::KATA_PATH;

use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use sysinfo::{Pid, ProcessExt, ProcessRefreshKind, System, SystemExt};
use hyper::{Body, Client, Method, Request, Response};

use tokio::{fs,process::Command,time::{sleep, Duration}};

const VSOCK_SCHEME: &str = "vsock";
const VSOCK_AGENT_CID: u32 = 3;
const VSOCK_AGENT_PORT: u32 = 1024;

unsafe impl Send for FcInner {}
unsafe impl Sync for FcInner {}

pub struct FcInner {
//    pub(crate) vm_id: String,
//    pub(crate) fc_path: String,
    pub(crate) asock_path: String,
    pub(crate) state: VmmState,
    pub(crate) config: HypervisorConfig,
//    pub(crate) config_json: ,
    pub(crate) client: Client<UnixConnector>,
//    pub(crate) has_conf: bool,
    pub(crate) pending_devices: Vec<Device>,
}

impl FcInner {
    pub fn new() -> FcInner {
        FcInner {
            asock_path: "".to_string(),
            state: VmmState::NotReady,
            config: Default::default(),
//            config_json: Path::new("").into(),
            client: Client::unix(),
//            has_conf: false,
            pending_devices: vec![],
        }
    }
    pub(crate) async fn prepare_vm(&mut self, id: &str, _netns: Option<String>) -> Result<()> {
        info!(sl!(), "Preparing Firecracker");

        let sb_path= [KATA_PATH, id].join("/");

        info!(sl!(), "SANDBOX PATH: {:?}", sb_path);

        fs::create_dir_all(&sb_path).await.context(format!("failed to create directory {:?}",&sb_path));

        self.asock_path=[&sb_path, "fc.sock"].join("/");

        match fs::remove_file(&self.asock_path).await {
            Ok(_) => info!(sl!(), "Deleted Firecracker API socket {:?}", self.asock_path),
            Err(e) if e.kind() == ErrorKind::NotFound =>{
                info!(sl!(), "Firecracker API socket not found {:?}", self.asock_path);
            }
            Err(e) => error!(sl!(), "ERROR deletingr API socket {:?}", self.asock_path),
        }
        //info!(sl!(), "FC  config: {:?}", self.config);
        
        let mut cmd = Command::new(&self.config.path);
        info!(sl!(), "Firecracker PATH: {:?}", &self.config.path);
        cmd
            .args(&[
                  "--api-sock",
                  &self.asock_path,
            ]);
        let mut child=cmd.spawn()?;
        match child.id() {
            Some(id) => {
                info!(sl!(), "Firecracker started successfully with id: {:?}", id);
            }
            None => {
                let exit_status = child.wait().await?;
                error!(sl!(), "ERROR FC process exited Immediatelly {:?}", exit_status);
            }
        };
        self.state = VmmState::VmmServerReady;

        let body_kernel: String =
            format!("
         {{
          \"kernel_image_path\": \"{}\",
          \"boot_args\": \"{}\"
         }}", &self.config.boot_info.kernel, &self.config.boot_info.kernel_params);

        let body_rootfs: String = 
            format!("{{
              \"drive_id\": \"rootfs\",
              \"path_on_host\": \"{}\",
              \"is_root_device\": true,
              \"is_read_only\": false
        }}", &self.config.boot_info.image);
        info!(sl!(), "BODY KERNEL: {:?}", &body_kernel);
        while !Path::new(&self.asock_path).exists(){}
        self.put("/boot-source", body_kernel).await?;
        self.put("/drives/rootfs", body_rootfs).await?;
        self.instance_start().await?;
        Ok(())
    }

    pub(crate) async fn start_vm(&mut self, _timeout: i32) -> Result<()> {
        info!(sl!(), "Starting Firecracker");

        
        self.state = VmmState::VmRunning;
        Ok(())
    }
    //alot of error handling here
    pub(crate) async fn stop_vm(&mut self) -> Result<()> {
//        let pid = match self.state {
//            MachineState::SHUTOFF => {
//                anyhow::bail!("Firecracker is not running");
//            }
//            MachineState::RUNNING { pid } => pid,
//        };
//        let killed = task::spawn_blocking(move || {
//            let mut sys = System::new();
//            if sys.refresh_process_specifics(Pid::from(pid), ProcessRefreshKind::new()) {
//                match sys.process(Pid::from(pid)) {
//                    Some(process) => Ok(process.kill()),
//                    None => {
//                        anyhow::bail!("Process with pid {:?} is not running", pid);
//                    }
//                }
//            } else {
//                anyhow::bail!("Process with pid {:?} is not running", pid);
//            }
//        })
//        .await??;
//
//        if !killed {
//            error!(sl!(), "Process with pid {:?} was not killed", pid);
//        }
//        self.state = MachineState::SHUTOFF;
        Ok(())
    }

    pub(crate) async fn put(&self, uri: &str, data: String) -> Result<()> {
        let url: hyper::Uri = Uri::new(&self.asock_path, uri).into();
//        info!(sl!(), "PUT Request to uri{:?}", uri);
//        info!(sl!(), "PUT Request SOCK: {:?}", &self.asock_path);
//        info!(sl!(), "PUT Request URL: {:?}", &url);
//        info!(sl!(), "PUT Request URI: {:?}", &uri);
//        info!(sl!(), "PUT Request BODY: {:?}", &data);
        let req = Request::builder()
            .method(Method::PUT)
            .uri(url.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Body::from(data))?;
//        info!(sl!(), "PUT Request WHOLE{:?}", &req);
        return self.send_request(req).await;
    }

    pub(crate) async fn patch(&self, uri: &str, data: String) -> Result<()> {
        let url: hyper::Uri = Uri::new(&self.asock_path, uri).into();
        info!(sl!(), "PATCH Request to uri{:?}", uri);
        info!(sl!(), "PATCH Request SOCK: {:?}", &self.asock_path);
        info!(sl!(), "PATCH Request URL: {:?}", &url);
        info!(sl!(), "PATCH Request URI: {:?}", &uri);
        info!(sl!(), "PATCH Request BODY: {:?}", &data);
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(url.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Body::from(data))?;
        info!(sl!(), "PATCH Request WHOLE{:?}", &req);
        return self.send_request(req).await;
    }

    pub(crate) async fn instance_start(&self)->Result<()>{
        let url: hyper::Uri = Uri::new(&self.asock_path, "/actions").into();
        let req = Request::builder()
            .method(Method::PUT)
            .uri(url.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Body::from("{
                    \"action_type\": \"InstanceStart\"
                   }"))?;
        info!(sl!(), "INSTANCE START Request WHOLE: {:?}", &req);
        return self.send_request(req).await;
    }

    pub(crate) async fn send_request(&self, req: Request<Body>) -> Result<()> {
        info!(sl!(), "SEND ({:?}) Request ", req.method());
        let resp = self.client.request(req).await?;

        let status = resp.status();
        info!(sl!(), "Request RESPONSE {:?}", &status);
        if status.is_success() {
            info!(sl!(), "Request SUCCESSFUL");
        } else {
            let body = hyper::body::to_bytes(resp.into_body()).await?;
            let body = if body.is_empty() {
                info!(sl!(), "Request FAILED WITH STATUS: {:?}", status);
                None
            } else {
                let body = String::from_utf8_lossy(&body).into_owned();
                info!(sl!(), "Request FAILED WITH STATUS: {:?} and BODY: {:?}", status, body);
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

    /// TODO: using a single hardcoded CID is clearly not adequate in the
    /// long run. Use the recently added VsockConfig infrastructure to
    ///  fix this.
    pub(crate) async fn get_agent_socket(&self) -> Result<String> {
        info!(sl!(), "FcInner: Get agent socket");
        Ok(format!(
            "{}://{}:{}",
            VSOCK_SCHEME, VSOCK_AGENT_CID, VSOCK_AGENT_PORT
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
        self.config=config;
    }

    pub(crate) async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        info!(sl!(), "FcInner: Getthread ids");
        todo!()
    }

    pub(crate) async fn get_pids(&self) -> Result<Vec<u32>> {
        info!(sl!(), "FcInner: Get pids");
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
        let mut caps = Capabilities::default();
        caps.set(CapabilityBits::FsSharingSupport);
        Ok(caps)
    }

    //Could maybe make inner_device
    //have to see what to do with the requests/actions
    pub(crate) async fn add_device(&mut self, device: Device) -> Result<()> {
        info!(sl!(), "FcInner: Add device {}", device);
        todo!()
    }

    pub(crate) async fn remove_device(&mut self, device: Device) -> Result<()> {
        info!(sl!(), "FcInner: Remove Device {} ", device);
        todo!()
    }
}
