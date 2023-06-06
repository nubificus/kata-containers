use crate::firecracker::utils::*;
use crate::{firecracker::FcInner, kernel_param::KernelParams, NetworkConfig};
use anyhow::{anyhow, Context, Result};
use dbs_utils::net::MacAddr;
use hyper::{Body, Method, Request, Response};
use hyperlocal::Uri;
use kata_sys_util::mount;
use nix::mount::MsFlags;
use serde_json::json;
use std::io::ErrorKind;
use tokio::{fs, fs::File};

const REQUEST_RETRY: u32 = 500;
const FC_KERNEL: &str = "vmlinux";
const FC_ROOT_FS: &str = "rootfs";
const DRIVE_PREFIX: &str = "drive";
const DISK_POOL_SIZE: u32 = 5;

impl FcInner {
    pub(crate) fn get_resource(&self, src: &str, dst: &str) -> Result<String> {
        if self.jailed {
            self.jail_resource(src, dst)
        } else {
            Ok(src.to_string())
        }
    }

    fn jail_resource(&self, src: &str, dst: &str) -> Result<String> {
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
        Ok(abs_path)
    }

    pub(crate) fn remount_jailer_with_exec(&self) -> Result<()> {
        mount::bind_mount_unchecked(
            self.jailer_root.as_str(),
            self.jailer_root.as_str(),
            false,
            MsFlags::MS_SHARED,
        )
        .context("bind mount jailer root")?;

        mount::bind_remount(self.jailer_root.as_str(), false)
            .context("rebind mount jailer root")?;
        Ok(())
    }

    pub(crate) async fn prepare_api_socket(&mut self, id: &str) -> Result<()> {
        self.asock_path = get_api_socket_path(id, self.jailed, false)?;

        match fs::remove_file(&self.asock_path).await {
            Err(e) if e.kind() != ErrorKind::NotFound => error!(
                sl!(),
                "ERROR: {:?} deleting API socket {:?}", e, self.asock_path
            ),
            _ => {}
        }
        Ok(())
    }

    pub(crate) async fn prepare_hvsock(&mut self, id: &str) -> Result<()> {
        let uds_path = get_vsock_path(id, self.jailed, false)?;
        let rel_uds_path = get_vsock_path(id, self.jailed, true)?;

        match fs::remove_file(&uds_path).await {
            Err(e) if e.kind() != ErrorKind::NotFound => error!(
                sl!(),
                "ERROR: {:?} deleting HybridV socket {:?}", e, &uds_path
            ),
            _ => {}
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
        let mut kernel_params = KernelParams::new(self.config.debug_info.enable_debug);
        let rootfs_driver = self.config.blockdev_info.block_device_driver.clone();

        kernel_params.append(&mut KernelParams::new_rootfs_kernel_params(
            &rootfs_driver,
            &self.config.boot_info.rootfs_type,
        )?);
        kernel_params.append(&mut KernelParams::from_string(
            &self.config.boot_info.kernel_params,
        ));
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

        self.put_with_retry("/boot-source", body_kernel).await?;
        self.put_with_retry("/drives/rootfs", body_rootfs).await?;

        let sb_path = get_sandbox_path(id)?;

        let abs_dummy_path = match self.jailed {
            false => [&sb_path, "root"].join("/"),
            true => [&self.jailer_root, "firecracker", &self.id, "root"].join("/"),
        };

        let rel_dummy_path = "/".to_string();
        let _ = fs::create_dir_all(&abs_dummy_path)
            .await
            .context(format!("failed to create directory {:?}", &abs_dummy_path));

        for i in 1..DISK_POOL_SIZE {
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
        drive_id: &str,
        drive_path: &str,
    ) -> Result<()> {
        let new_drive_id = &[DRIVE_PREFIX, drive_id].concat();
        let new_drive_path = self
            .get_resource(drive_path, new_drive_id)
            .context("get resource CONTAINER ROOTFS")?;
        let body: String = json!({
            "drive_id": format!("drive{drive_id}"),
            "path_on_host": new_drive_path
        })
        .to_string();
        self.patch(&["/drives/", &format!("drive{drive_id}")].concat(), body)
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

        Err(anyhow::anyhow!(
            "After {} attempts, it
                            still doesn't work.",
            REQUEST_RETRY
        ))
    }
    pub(crate) fn cleanup_resource(&self, sb_path: &String) {
        if self.jailed {
            let jailed_path = ["firecracker", &self.id, "root"].join("/");
            self.umount_jail_resource(FC_KERNEL).ok();
            self.umount_jail_resource(FC_ROOT_FS).ok();

            for i in 1..DISK_POOL_SIZE {
                self.umount_jail_resource(&[DRIVE_PREFIX, &i.to_string()].concat())
                    .ok();
                self.umount_jail_resource("").ok();
            }

            std::fs::remove_dir_all(
                [
                    self.jailer_root.clone(),
                    "firecracker".to_string(),
                    self.id.clone(),
                ]
                .join("/"),
            )
            .map_err(|err| {
                error!(
                    sl!(),
                    "failed to remove dir all for {} with error: {:?}", &jailed_path, &err
                );
                err
            })
            .ok();
        }
        std::fs::remove_dir_all(sb_path)
            .map_err(|err| {
                error!(
                    sl!(),
                    "failed to remove dir all for {} with error: {:?}", &sb_path, &err
                );
                err
            })
            .ok();
    }

    pub(crate) fn umount_jail_resource(&self, jailed_path: &str) -> Result<()> {
        let path = [self.jailer_root.as_str(), jailed_path].join("/");
        nix::mount::umount2(path.as_str(), nix::mount::MntFlags::MNT_DETACH)
            .with_context(|| format!("umount path {}", &path))
    }
}
