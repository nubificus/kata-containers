//Copyright (c) 2019-2022 Alibaba Cloud
//Copyright (c) 2023 Nubificus Ltd
//
//SPDX-License-Identifier: Apache-2.0

use crate::firecracker::{
    utils::{get_sandbox_path, get_vsock_path},
    FcInner,
};
use crate::{VcpuThreadIds, VmmState, HYPERVISOR_FIRECRACKER};
use anyhow::{anyhow, Context, Result};
use kata_types::capabilities::Capabilities;
use kata_types::config::KATA_PATH;
use std::collections::HashSet;
use std::iter::FromIterator;
use tokio::fs;

const HYBRID_VSOCK_SCHEME: &str = "hvsock";

impl FcInner {
    pub(crate) async fn prepare_vm(&mut self, id: &str, _netns: Option<String>) -> Result<()> {
        info!(sl!(), "Preparing Firecracker");
        info!(sl!(), "EGWWWW");

        let sb_path = get_sandbox_path(id)?;
        self.id = id.to_string();

        if !self.config.jailer_path.is_empty() {
            self.jailed = true;
            self.jailer_root = KATA_PATH.to_string();
            self.vm_path = [KATA_PATH, HYPERVISOR_FIRECRACKER, id].join("/");
            let _ = self.remount_jailer_with_exec().await;
        } else {
            let _ = fs::create_dir_all(&sb_path)
                .await
                .context(format!("failed to create directory {:?}", &sb_path));
            self.vm_path = sb_path;
        }

        self.wait_api_socket(id).await?;
        self.netns = _netns.clone();
        self.prepare_vmm(self.netns.clone()).await?;
        self.state = VmmState::VmmServerReady;
        self.prepare_vmm_resources(id).await?;
        self.prepare_hvsock(id).await?;
        Ok(())
    }

    pub(crate) async fn start_vm(&mut self, _timeout: i32) -> Result<()> {
        info!(sl!(), "Starting Firecracker sandbox");
        let body: String = serde_json::json!({
            "action_type": "InstanceStart"
        })
        .to_string();
        while let Some(dev) = self.pending_devices.pop() {
            self.add_device(dev).await.context("add_device")?;
        }
        self.request_with_retry(hyper::Method::PUT, "/actions", body).await?;
        self.state = VmmState::VmRunning;
        Ok(())
    }

    pub(crate) async fn stop_vm(&mut self) -> Result<()> {
        info!(sl!(), "Stopping Firecracker sandbox");
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
        info!(sl!(), "FcInner: Currently not implemented");
        Ok(())
    }

    pub(crate) async fn save_vm(&self) -> Result<()> {
        info!(sl!(), "Saving Firecracker");
        info!(sl!(), "FcInner: Currently not implemented");
        Ok(())
    }
    pub(crate) fn resume_vm(&self) -> Result<()> {
        info!(sl!(), "Resuming Firecracker");
        info!(sl!(), "FcInner: Currently not implemented");
        Ok(())
    }

    pub(crate) async fn get_agent_socket(&self) -> Result<String> {
        info!(sl!(), "FcInner: Get agent socket");
        let vsock_path = get_vsock_path(&self.id, self.jailed, false)?;
        Ok(format!("{}://{}", HYBRID_VSOCK_SCHEME, vsock_path))
    }

    pub(crate) async fn disconnect(&mut self) {
        info!(sl!(), "FcInner: Disconnect");
        info!(sl!(), "FcInner: Currently not implemented");
    }
    pub(crate) async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        info!(sl!(), "FcInner: Getthread ids");
        Ok(VcpuThreadIds::default())
    }

    pub(crate) async fn get_pids(&self) -> Result<Vec<u32>> {
        info!(sl!(), "FcInner: Get pids");
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

    pub(crate) async fn resize_vcpu(&self, old_vcpu: u32, new_vcpu: u32) -> Result<(u32, u32)> {
        info!(sl!(), "FcInner: Resize vCPU");
        info!(sl!(), "FcInner: Currently not implemented");
        Ok((old_vcpu, new_vcpu))
    }

    pub(crate) async fn check(&self) -> Result<()> {
        info!(sl!(), "FcInner: Check");
        info!(sl!(), "FcInner: Currently not implemented");
        Ok(())
    }

    pub(crate) async fn get_jailer_root(&self) -> Result<String> {
        info!(sl!(), "FcInner: Get jailer root");
        Ok(self.jailer_root.clone())
    }

    pub(crate) async fn capabilities(&self) -> Result<Capabilities> {
        info!(sl!(), "FcInner: Capabilities");
        Ok(self.capabilities.clone())
    }

    pub(crate) async fn get_hypervisor_metrics(&self) -> Result<String> {
        info!(sl!(), "FcInner: Get hypervisor metrics");
        info!(sl!(), "Not yet implemented!");
        todo!()
    }
}
