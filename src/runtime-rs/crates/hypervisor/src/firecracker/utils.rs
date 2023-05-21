use anyhow::{anyhow, Result};
use shim_interface::KATA_PATH;

use std::{path::Path, time::Duration};

const FC_API_SOCKET_NAME: &str = "fc.sock";
const FC_AGENT_SOCKET_NAME: &str = "kata.hvsock";

pub(crate) fn get_sandbox_path(id: &str) -> Result<String> {
    Ok([KATA_PATH, id].join("/"))
}

pub(crate) fn get_api_socket_path(id: &str, jailed: bool, relative: bool) -> Result<String> {
    let sb_path = get_sandbox_path(id)?;
    let path = match jailed {
        false => [&sb_path, FC_API_SOCKET_NAME].join("/"),
        true => match relative {
            false => [
                "/run/kata",
                "firecracker",
                id,
                "root",
                "run",
                FC_API_SOCKET_NAME,
            ]
            .join("/"),
            true => ["run", FC_API_SOCKET_NAME].join("/"),
        },
    };
    Ok(path)
}

pub(crate) fn get_vsock_path(id: &str, jailed: bool, relative: bool) -> Result<String> {
    let sb_path = get_sandbox_path(id)?;
    let path = match jailed {
        false => [&sb_path, "root", FC_AGENT_SOCKET_NAME].join("/"),
        true => match relative {
            false => ["/run/kata", "firecracker", id, "root", FC_AGENT_SOCKET_NAME].join("/"),
            true => FC_AGENT_SOCKET_NAME.to_string(),
            //["firecracker", id, "root", FC_AGENT_SOCKET_NAME].join("/"),
        },
    };
    Ok(path)
}

pub(crate) async fn _wait_api_socket(path: &String) -> Result<()> {
    let retries = 1000000;
    let timeout: u64 = 5;

    for _ in 0..retries {
        info!(sl!(), "FcInner: RETRY");
        match Path::new(path).exists() {
            true => {
                info!(sl!(), "FcInner: APIi socket has been created successfully");
                return Ok(());
            }
            false => tokio::time::sleep(Duration::from_millis(timeout)).await,
        }
    }

    Err(anyhow!(
        "api_socket could not be found after {} retries",
        retries
    ))
}
