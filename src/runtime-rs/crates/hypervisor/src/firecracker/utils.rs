use anyhow::Result;
use shim_interface::KATA_PATH;

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
        },
    };
    Ok(path)
}
