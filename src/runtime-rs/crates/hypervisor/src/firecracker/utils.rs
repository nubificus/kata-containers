use anyhow::Result;
use shim_interface::KATA_PATH;

const FC_API_SOCKET_NAME: &str = "fc.sock";
const FC_AGENT_SOCKET_NAME: &str = "kata.hvsock";

pub(crate) fn get_sandbox_path(id: &str) -> Result<String> {
    Ok([KATA_PATH, id].join("/"))
}

pub(crate) fn get_api_socket_path(id: &str) -> Result<String> {
    let sb_path = get_sandbox_path(id)?;
    Ok([&sb_path, FC_API_SOCKET_NAME].join("/"))
}

pub(crate) fn get_vsock_path(id: &str) -> Result<String> {
    let sb_path = get_sandbox_path(id)?;
    Ok([&sb_path, "root", FC_AGENT_SOCKET_NAME].join("/"))
}
