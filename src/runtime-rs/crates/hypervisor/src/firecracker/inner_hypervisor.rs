use anyhow::{anyhow, Context, Result};

use crate::VcpuThreadIds;
use crate::VmmState;

use kata_types::capabilities::Capabilities;

use crate::firecracker::utils::{get_sandbox_path, get_vsock_path};

use crate::firecracker::FcInner;
use std::collections::HashSet;
use tokio::fs;

use shim_interface::KATA_PATH;
use std::iter::FromIterator;

impl FcInner {
    pub(crate) async fn prepare_vm(&mut self, id: &str, _netns: Option<String>) -> Result<()> {
        info!(sl!(), "Preparing Firecracker, netns: {:?}", _netns);

        let sb_path = get_sandbox_path(id)?;
        //let j_path = [&sb_path, "firecracker", id, "root"].join("/");
        self.id = id.to_string();

        if !self.config.jailer_path.is_empty() {
            info!(sl!(), "JAILER ENCOUNTERED");
            self.jailed = true;
            self.jailer_root = KATA_PATH.to_string();
            let _ = self.remount_jailer_with_exec();
            let _ = fs::create_dir_all([&self.jailer_root, "firecracker", id].join("/"))
                .await
                .context(format!(
                    "failed to create directory {:?}",
                    [&self.jailer_root, "firecrakcer", id].join("/")
                ));

            self.vm_path = [KATA_PATH, "firecracker", id].join("/");
        } else {
            let _ = fs::create_dir_all(&sb_path)
                .await
                .context(format!("failed to create directory {:?}", &sb_path));
            self.vm_path = sb_path;
        }

        info!(sl!(), "vmpath: {:?}", &self.vm_path);

        self.prepare_api_socket(id).await?;
        self.netns = _netns.clone();
        self.prepare_vmm(self.netns.clone()).await?;
        self.state = VmmState::VmmServerReady;
        self.prepare_vmm_resources(id).await?;
        self.prepare_hvsock(id).await?;
        Ok(())
    }

    pub(crate) async fn start_vm(&mut self, _timeout: i32) -> Result<()> {
        info!(sl!(), "Starting Firecracker");
        self.instance_start().await?;
        self.state = VmmState::VmRunning;
        Ok(())
    }

    pub(crate) async fn stop_vm(&mut self) -> Result<()> {
        info!(sl!(), "Stopping Firecracker");
        if self.state != VmmState::VmRunning {
            info!(sl!(), "Cannot stop Firecracker as it is not running!");
        } else if let Some(pid_to_kill) = &self.pid {
            let pid = ::nix::unistd::Pid::from_raw(*pid_to_kill as i32);
            if let Err(err) = ::nix::sys::signal::kill(pid, nix::sys::signal::SIGKILL) {
                if err != ::nix::Error::ESRCH {
                    info!(
                        sl!(),
                        "failed to kill Firecracker with pid {} {:?}", pid, err
                    );
                }
            }
        }
        Ok(())
    }

    pub(crate) fn pause_vm(&self) -> Result<()> {
        info!(sl!(), "Pausing Firecracker");
        //todo!()
        Ok(())
    }

    pub(crate) async fn save_vm(&self) -> Result<()> {
        info!(sl!(), "Saving Firecracker");
        //todo!()
        Ok(())
    }
    pub(crate) fn resume_vm(&self) -> Result<()> {
        info!(sl!(), "Resuming Firecracker");
        //todo!()
        Ok(())
    }

    pub(crate) async fn get_agent_socket(&self) -> Result<String> {
        const HYBRID_VSOCK_SCHEME: &str = "hvsock";
        info!(sl!(), "FcInner: Get agent socket");
        let vsock_path = get_vsock_path(&self.id, self.jailed, false)?;
        Ok(format!("{}://{}", HYBRID_VSOCK_SCHEME, vsock_path))
    }

    pub(crate) async fn disconnect(&mut self) {
        info!(sl!(), "FcInner: Disconnect");
        //todo!()
        //Ok(());
    }
    pub(crate) async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        info!(sl!(), "FcInner: Getthread ids");
        Ok(VcpuThreadIds::default())
    }

    pub(crate) async fn get_pids(&self) -> Result<Vec<u32>> {
        info!(sl!(), "FcInner: Get pids");
        //todo!()
        let mut pids = HashSet::new();
        // get shim thread ids
        pids.insert(self.pid.unwrap());

        info!(sl!(), "get pids {:?}", pids);
        Ok(Vec::from_iter(pids.into_iter()))
    }

    pub(crate) async fn get_vmm_master_tid(&self) -> Result<u32> {
        info!(sl!(), "FcInner: get vmm master tid");
        if let Some(pid) = self.pid {
            Ok(pid)
        } else {
            Err(anyhow!("could not get vmm master tid"))
        }
    }
    pub(crate) async fn get_ns_path(&self) -> Result<String> {
        info!(sl!(), "FcInner: get ns path");
        if let Some(pid) = self.pid {
            let ns_path = format!("/proc/{}/ns", pid);
            Ok(ns_path)
        } else {
            Err(anyhow!("could not get ns path"))
        }
    }

    pub(crate) async fn cleanup(&self) -> Result<()> {
        info!(sl!(), "FcInner: Cleanup");
        let sb_path = get_sandbox_path(&self.id)?;
        self.cleanup_resource(&sb_path);
        Ok(())
    }

    pub(crate) async fn check(&self) -> Result<()> {
        info!(sl!(), "FcInner: Check");
        //todo!()
        Ok(())
    }

    pub(crate) async fn get_jailer_root(&self) -> Result<String> {
        info!(sl!(), "FcInner: Get jailerroot");
        //todo!()
        Ok(self.jailer_root.clone())
    }
    pub(crate) async fn capabilities(&self) -> Result<Capabilities> {
        Ok(self.capabilities.clone())
    }
}
