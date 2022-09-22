// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod device_manager;
pub mod device_type;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DeviceType {
    VirtioBlk,
    Network,
    ShareFsDevice,
    Vfio,
    ShareFsMount,
    Vsock,
    HybridVsock,
    Undefined,
}
