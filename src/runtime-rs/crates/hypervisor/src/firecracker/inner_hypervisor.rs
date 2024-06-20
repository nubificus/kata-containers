//Copyright (c) 2019-2022 Alibaba Cloud
//Copyright (c) 2023 Nubificus Ltd
//
//SPDX-License-Identifier: Apache-2.0

use crate::firecracker::FcInner;
use crate::{VcpuThreadIds, VmmState, HYPERVISOR_FIRECRACKER};
use anyhow::{anyhow, Context, Result};
use kata_types::capabilities::Capabilities;
use kata_types::config::KATA_PATH;
use std::collections::HashSet;
use std::iter::FromIterator;
use tokio::fs;

pub const FC_API_SOCKET_NAME: &str = "fc.sock";
pub const FC_AGENT_SOCKET_NAME: &str = "kata.hvsock";
pub const ROOT: &str = "root";

const HYBRID_VSOCK_SCHEME: &str = "hvsock";

impl FcInner {
    pub(crate) async fn prepare_vm(&mut self, id: &str, _netns: Option<String>) -> Result<()> {
        debug!(sl!(), "[Firecracker] Preparing Firecracker");

        self.id = id.to_string();

        if !self.config.jailer_path.is_empty() {
            debug!(sl!(), "[Firecracker] Running jailed");
            self.jailed = true;
            self.jailer_root = KATA_PATH.to_string();
            debug!(sl!(), "[Firecracker] jailer_root: {:?}", self.jailer_root);
            self.vm_path = [
                self.jailer_root.clone(),
                HYPERVISOR_FIRECRACKER.to_string(),
                id.to_string(),
            ]
            .join("/");
            debug!(sl!(), "[Firecracker] VM Path: {:?}", self.vm_path);
            self.run_dir = [self.vm_path.clone(), "root".to_string(), "run".to_string()].join("/");
            debug!(sl!(), "[Firecracker] Rundir: {:?}", self.run_dir);
            let _ = self.remount_jailer_with_exec().await;
        } else {
            self.vm_path = [KATA_PATH.to_string(), id.to_string()].join("/");
            debug!(sl!(), "[Firecracker] VM Path: {:?}", self.vm_path);
            self.run_dir = [self.vm_path.clone(), "run".to_string()].join("/");
            debug!(sl!(), "[Firecracker] Rundir: {:?}", self.run_dir);
        }
        // We construct the FC API socket path based on the run_dir variable (jailed or
        // non-jailed).
        self.asock_path = [self.run_dir.as_str(), "fc.sock"].join("/");
        debug!(sl!(), "[Firecracker] Socket Path: {:?}", self.asock_path);

        let _ = fs::create_dir_all(self.run_dir.as_str())
            .await
            .context(format!("failed to create directory {:?}", self.vm_path));

        self.netns = _netns.clone();
        self.prepare_vmm(self.netns.clone()).await?;
        self.state = VmmState::VmmServerReady;
        self.prepare_vmm_resources().await?;
        self.prepare_hvsock().await?;
        Ok(())
    }

    pub(crate) async fn start_vm(&mut self, _timeout: i32) -> Result<()> {
        debug!(sl!(), "[Firecracker] Starting sandbox");
        let body: String = serde_json::json!({
            "action_type": "InstanceStart"
        })
        .to_string();
        self.request_with_retry(hyper::Method::PUT, "/actions", body)
            .await?;
        self.state = VmmState::VmRunning;
        Ok(())
    }

    pub(crate) async fn stop_vm(&mut self) -> Result<()> {
        debug!(sl!(), "[Firecracker] Stopping sandbox");
        if self.state != VmmState::VmRunning {
            debug!(sl!(), "[Firecracker] VM not running!");
        } else if let Some(pid_to_kill) = &self.pid {
            let pid = ::nix::unistd::Pid::from_raw(*pid_to_kill as i32);
            if let Err(err) = ::nix::sys::signal::kill(pid, nix::sys::signal::SIGKILL) {
                if err != ::nix::Error::ESRCH {
                    debug!(
                        sl!(),
                        "[Firecracker] Failed to kill VMM with pid {} {:?}", pid, err
                    );
                }
            }
        }
        Ok(())
    }

    pub(crate) fn pause_vm(&self) -> Result<()> {
        warn!(sl!(), "[Firecracker] Pause VM: Not implemented");
        Ok(())
    }

    pub(crate) async fn save_vm(&self) -> Result<()> {
        warn!(sl!(), "[Firecracker] Save VM: Not implemented");
        Ok(())
    }
    pub(crate) fn resume_vm(&self) -> Result<()> {
        warn!(sl!(), "[Firecracker] Resume VM: Not implemented");
        Ok(())
    }

    pub(crate) async fn get_agent_socket(&self) -> Result<String> {
        debug!(sl!(), "[Firecracker] Get kata-agent socket");
        let vsock_path = match self.jailed {
            false => [self.vm_path.as_str(), FC_AGENT_SOCKET_NAME].join("/"),
            true => [self.vm_path.as_str(), ROOT, FC_AGENT_SOCKET_NAME].join("/"),
        };
        Ok(format!("{}://{}", HYBRID_VSOCK_SCHEME, vsock_path))
    }

    pub(crate) async fn disconnect(&mut self) {
        warn!(sl!(), "[Firecracker] Disconnect: Not implemented");
    }
    pub(crate) async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        debug!(sl!(), "[Firecracker] Get Thread IDs");
        Ok(VcpuThreadIds::default())
    }

    pub(crate) async fn get_pids(&self) -> Result<Vec<u32>> {
        debug!(sl!(), "[Firecracker] Get PIDs");
        let mut pids = HashSet::new();
        // get shim thread ids
        pids.insert(self.pid.unwrap());

        debug!(sl!(), "[Firecracker] PIDs: {:?}", pids);
        Ok(Vec::from_iter(pids.into_iter()))
    }

    pub(crate) async fn get_vmm_master_tid(&self) -> Result<u32> {
        debug!(sl!(), "[Firecracker] Get VMM master TID");
        if let Some(pid) = self.pid {
            Ok(pid)
        } else {
            Err(anyhow!("could not get vmm master tid"))
        }
    }
    pub(crate) async fn get_ns_path(&self) -> Result<String> {
        debug!(sl!(), "[Firecracker] Get NS path");
        if let Some(pid) = self.pid {
            let ns_path = format!("/proc/{}/ns", pid);
            Ok(ns_path)
        } else {
            Err(anyhow!("could not get ns path"))
        }
    }

    pub(crate) async fn cleanup(&self) -> Result<()> {
        debug!(sl!(), "[Firecracker] Cleanup");
        self.cleanup_resource();

        std::fs::remove_dir_all(self.vm_path.as_str())
            .map_err(|err| {
                error!(
                    sl!(),
                    "failed to remove dir all for {} with error: {:?}", &self.vm_path, &err
                );
                err
            })
            .ok();

        Ok(())
    }

    pub(crate) async fn resize_vcpu(&self, old_vcpu: u32, new_vcpu: u32) -> Result<(u32, u32)> {
        warn!(sl!(), "[Firecracker] Resize vCPU: Not implemented");
        Ok((old_vcpu, new_vcpu))
    }

    pub(crate) async fn check(&self) -> Result<()> {
        warn!(sl!(), "[Firecracker] Check: Not implemented");
        Ok(())
    }

    pub(crate) async fn get_jailer_root(&self) -> Result<String> {
        debug!(sl!(), "[Firecracker] Get Jailer Root");
        Ok(self.jailer_root.clone())
    }

    //pub(crate) async fn get_run_dir(&self) -> Result<String> {
    //    info!(sl!(), "FcInner: Get run dir");
    //    Ok(self.run_dir.clone())
    //}

    pub(crate) async fn capabilities(&self) -> Result<Capabilities> {
        debug!(sl!(), "[Firecracker] Capabilities");
        Ok(self.capabilities.clone())
    }

    pub(crate) async fn get_hypervisor_metrics(&self) -> Result<String> {
        warn!(
            sl!(),
            "[Firecracker] Get Hypervisor Metrics: Not implemented"
        );
        todo!()
    }
}
