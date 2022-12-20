use anyhow::Result;

use crate::{HypervisorConfig, VcpuThreadIds};
use kata_types::capabilities::{CapabilityBits,Capabilities};

use std::{borrow::Cow, path::Path};
use uuid::Uuid;
use firec::Machine};
use hyperlocal::{UnixConnector};

const VSOCK_SCHEME: &str = "vsock";
const VSOCK_AGENT_CID: u32 = 3;
const VSOCK_AGENT_PORT: u32 = 1024;

unsafe impl Send for FcInner{}
unsafe impl Sync for FcInner{}

pub struct FcInner<'f>{
    pub(crate) vm_id: Uuid,
    pub(crate) fc_path: Cow<'f, Path>,
    pub(crate) asock_path: Cow<'f, Path>,
    pub(crate) state: MachineState,
    pub(crate) config: Cow<'f, Path>,
    pub(crate) client: Client<UnixConnector>,
    pub(crate) has_conf: bool,



use tokio::{process::Command};

impl<'f>  FcInner<'f>{
    pub fn new()->FcInner{
        FcInner{
            vm_id: Uuid::new_v4(),
            fc_path: Path::new("/usr/bin/firecracker").into(),
            asock_path: Path::new("/tmp/firecracker.socket").into(),
            state: MachineState::SHUTOFF,
            config: Path::new("").into(),
            client: Client::unix(),
            has_conf: false,
        }
    }
    pub(crate) async fn prepare_vm(&mut self, _id: &str, _netns: Option<String>) -> Result<()> {
        ///could maybe remove socket later on
        info!(sl!(), "Preparing Firecracker");
        Ok(())
    }

    pub(crate) async fn start_vm(&mut self, _timeout: i32) -> Result<()> {
        info!(sl!(), "Starting Firecracker");

        let mut command = Command::new(&self.fc_path);
        ///need to change error handling to that of kata
        command
            .arg("-kernel")
            .arg(&self.config.boot_info.kernel)
            .arg("-m")
            .arg(format!("{}M", &self.config.memory_info.default_memory))
            let cmd = match self.has_conf {
                true => cmd
                    .args(&[
                          "--config-file",
                          ///here
                          self.config.to_str(),
                          "--api-sock",
                          self.as_path.to_str(),
                    ])
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit()),
                false => cmd
                    .args(&[
                          ///here
                          "--api-sock",
                          self.as_path.to_str(),
                    ])
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit()),
            };
        let mut child = cmd.spawn()?;
        let pid: u32 = match child.id() {
            Some(id) => id,
            None => {
                ///for sure here
                let exit_status = child.wait().await?;
                error!(sl!(), "failed to call end err : {:?}", exit_status);
            }
        };
        trace!("{vm_id}: VM started successfully.");
        self.state = MachineState::RUNNING {
            pid: pid.try_into()?,
        };
        child.wait().await?;
        Ok(())
    }
    ///alot of error handling here
    pub(crate) fn stop_vm(&mut self) -> Result<()> {
        let pid = match self.state {
            MachineState::SHUTOFF => {
                return Err(Error::ProcessNotStarted);
            }
            MachineState::RUNNING { pid } => pid,
        };
        let killed = task::spawn_blocking(move || {
            let mut sys = System::new();
            if sys.refresh_process_specifics(Pid::from(pid), ProcessRefreshKind::new()) {
                match sys.process(Pid::from(pid)) {
                    Some(process) => Ok(process.kill()),
                    None => Err(Error::ProcessNotRunning(pid)),
                }
            } else {
                Err(Error::ProcessNotRunning(pid))
            }
        })
        .await??;

        if !killed {
            return Err(Error::ProcessNotKilled(pid));
        }
        self.state = MachineState::SHUTOFF;
        Ok(())
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
    pub(crate) async fn get_agent_socket(&self) ->
        Result<String> {
            info!(sl!(), "FcInner: Get agent socket");
            Ok(format!(
                    "{}://{}:{}",
                    VSOCK_SCHEME,
                    VSOCK_AGENT_CID,
                    VSOCK_AGENT_PORT
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
    pub(crate) async fn save_state(&self) -> Result<HypervisorState>{
        info!(sl!(), "FcInner: Save state");
        todo!()
    }

    ///Could maybe make inner_device
    ///have to see what to do with the requests/actions
    pub(crate) async fn add_device(&mut self, device: Device) -> Result<()> {
        info!(sl!(), "FcInner: Add device {}", device);
        todo!()
    }

    pub(crate) async fn remove_device(&mut self, device: Device) -> Result<()> {
        info!(sl!(), "FcInner: Remove Device {} ", device);
        todo!()
    }
}
