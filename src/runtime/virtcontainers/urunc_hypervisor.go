// Copyright (c) 2016 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"errors"
	"os"

	hv "github.com/kata-containers/kata-containers/src/runtime/pkg/hypervisors"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
)

var UruncHybridVSockPath = "/tmp/kata-mock-hybrid-vsock.socket"

type uruncHypervisor struct {
	mockPid int
}

func (u *uruncHypervisor) Capabilities(ctx context.Context) types.Capabilities {
	caps := types.Capabilities{}
	caps.SetFsSharingSupport()
	return caps
}

func (u *uruncHypervisor) HypervisorConfig() HypervisorConfig {
	return HypervisorConfig{}
}

func (u *uruncHypervisor) setConfig(config *HypervisorConfig) error {
	if err := config.Valid(); err != nil {
		return err
	}

	return nil
}

func (u *uruncHypervisor) CreateVM(ctx context.Context, id string, network Network, hypervisorConfig *HypervisorConfig) error {
	if err := u.setConfig(hypervisorConfig); err != nil {
		return err
	}

	return nil
}

func (u *uruncHypervisor) StartVM(ctx context.Context, timeout int) error {
	return nil
}

func (u *uruncHypervisor) StopVM(ctx context.Context, waitOnly bool) error {
	return nil
}

func (u *uruncHypervisor) PauseVM(ctx context.Context) error {
	return nil
}

func (u *uruncHypervisor) ResumeVM(ctx context.Context) error {
	return nil
}

func (u *uruncHypervisor) SaveVM() error {
	return nil
}

func (u *uruncHypervisor) AddDevice(ctx context.Context, devInfo interface{}, devType DeviceType) error {
	return nil
}

func (u *uruncHypervisor) HotplugAddDevice(ctx context.Context, devInfo interface{}, devType DeviceType) (interface{}, error) {
	switch devType {
	case CpuDev:
		return devInfo.(uint32), nil
	case MemoryDev:
		memdev := devInfo.(*MemoryDevice)
		return memdev.SizeMB, nil
	}
	return nil, nil
}

func (u *uruncHypervisor) HotplugRemoveDevice(ctx context.Context, devInfo interface{}, devType DeviceType) (interface{}, error) {
	switch devType {
	case CpuDev:
		return devInfo.(uint32), nil
	case MemoryDev:
		return 0, nil
	}
	return nil, nil
}

func (u *uruncHypervisor) GetVMConsole(ctx context.Context, sandboxID string) (string, string, error) {
	return "", "", nil
}

func (u *uruncHypervisor) ResizeMemory(ctx context.Context, memMB uint32, memorySectionSizeMB uint32, probe bool) (uint32, MemoryDevice, error) {
	return 0, MemoryDevice{}, nil
}
func (u *uruncHypervisor) ResizeVCPUs(ctx context.Context, cpus uint32) (uint32, uint32, error) {
	return 0, 0, nil
}

func (u *uruncHypervisor) Disconnect(ctx context.Context) {
}

func (u *uruncHypervisor) GetThreadIDs(ctx context.Context) (VcpuThreadIDs, error) {
	vcpus := map[int]int{0: os.Getpid()}
	return VcpuThreadIDs{vcpus}, nil
}

func (u *uruncHypervisor) Cleanup(ctx context.Context) error {
	return nil
}

func (u *uruncHypervisor) GetPids() []int {
	return []int{u.mockPid}
}

func (u *uruncHypervisor) GetVirtioFsPid() *int {
	return nil
}

func (u *uruncHypervisor) fromGrpc(ctx context.Context, hypervisorConfig *HypervisorConfig, j []byte) error {
	return errors.New("uruncHypervisor is not supported by VM cache")
}

func (u *uruncHypervisor) toGrpc(ctx context.Context) ([]byte, error) {
	return nil, errors.New("uruncHypervisor is not supported by VM cache")
}

func (u *uruncHypervisor) Save() (s hv.HypervisorState) {
	return
}

func (u *uruncHypervisor) Load(s hv.HypervisorState) {}

func (u *uruncHypervisor) Check() error {
	return nil
}

func (u *uruncHypervisor) GenerateSocket(id string) (interface{}, error) {
	return types.MockHybridVSock{
		UdsPath: UruncHybridVSockPath,
	}, nil
}

func (u *uruncHypervisor) IsRateLimiterBuiltin() bool {
	return false
}
