// Copyright (c) 2016 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	osexec "os/exec"

	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	pbTypes "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	vcTypes "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// This is intented to pass the required data back to containerd-shim
type ExecData struct {
	BinaryType string
	BinaryPath string
	IPAddress  string
	Mask       string
	Container  *Container
}

// uruncAgent is an empty Agent implementation, for deploying unikernels
// We can add some fields here if we need to persist data between agent calls.
type uruncAgent struct {
	ExecData ExecData
}

func (u *uruncAgent) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "urunc_agent")
}

func newExecData() ExecData {
	return ExecData{
		BinaryType: "",
		BinaryPath: "",
		IPAddress:  "",
		Mask:       "",
	}
}

// nolint:golint
func NewUruncAgent() agent {
	data := newExecData()
	return &uruncAgent{ExecData: data}
}

func (u *uruncAgent) GetExecData() ExecData {
	return u.ExecData
}

// init initializes the Noop agent, i.e. it does nothing.
func (u *uruncAgent) init(ctx context.Context, sandbox *Sandbox, config KataAgentConfig) (bool, error) {
	logF := logrus.Fields{"src": "uruncio", "file": "vs/urunc_agent.go", "func": "init"}
	u.Logger().WithFields(logF).Error("urunc agent init")
	for _, mnt := range sandbox.config.SandboxBindMounts {
		msg := "mount is " + mnt
		u.Logger().WithFields(logF).Error(msg)
	}
	return false, nil
}

func (u *uruncAgent) longLiveConn() bool {
	return false
}

// createSandbox is the Noop agent sandbox creation implementatiou. It does nothing.
func (u *uruncAgent) createSandbox(ctx context.Context, sandbox *Sandbox) error {
	return nil
}

// capabilities returns empty capabilities, i.e no capabilties are supported.
func (u *uruncAgent) capabilities() types.Capabilities {
	return types.Capabilities{}
}

// disconnect is the Noop agent connection closer. It does nothing.
func (u *uruncAgent) disconnect(ctx context.Context) error {
	return nil
}

// exec is the Noop agent command execution implementatiou. It does nothing.
func (u *uruncAgent) exec(ctx context.Context, sandbox *Sandbox, c Container, cmd types.Cmd) (*Process, error) {
	return nil, nil
}

// startSandbox is the Noop agent Sandbox starting implementatiou. It does nothing.
func (u *uruncAgent) startSandbox(ctx context.Context, sandbox *Sandbox) error {
	logF := logrus.Fields{"src": "uruncio", "file": "vc/urunc_agent.go", "func": "startSandbox"}

	interfaces, _, _, err := generateVCNetworkStructures(ctx, sandbox.network)
	// interfaces, routes, neighs, err := generateVCNetworkStructures(ctx, sandbox.network)
	if err != nil {
		return err
	}
	// u.Logger().WithFields(logF).WithField("interfaces", interfaces).Error("createContainer 4")
	//msg="createContainer 4" interfaces="[&Interface{Device:eth0,Name:eth0,IPAddresses:[]*IPAddress{&IPAddress{Family:v4,Address:10.4.0.20,Mask:24,XXX_unrecognized:[],},&IPAddress{Family:v6,Address:fe80::9c89:5ff:feb5:86d5,Mask:64,XXX_unrecognized:[],},},Mtu:1500,HwAddr:9e:89:05:b5:86:d5,PciPath:,Type:,RawFlags:0,XXX_unrecognized:[],}]" name=containerd-shim-v2 pid=1371845 sandbox=c06d6ba018f0036de74eb529263801b5ea7c611384478d9ecf5385992e4c9edd source=virtcontainers subsystem=mock_agent
	IPAddress := interfaces[0].IPAddresses[0].Address
	mask := interfaces[0].IPAddresses[0].Mask
	u.Logger().WithFields(logF).WithField("IPAddress", IPAddress).Error("createContainer 4.5")
	u.Logger().WithFields(logF).WithField("mask", mask).Error("createContainer 4.5")
	// u.Logger().WithFields(logF).WithField("routes", routes).Error("createContainer 4.5")
	// u.Logger().WithFields(logF).WithField("neighs", neighs).Error("createContainer 4.5")
	u.ExecData.IPAddress = IPAddress
	u.ExecData.Mask = mask
	return nil
}

// stopSandbox is the Noop agent Sandbox stopping implementatiou. It does nothing.
func (u *uruncAgent) stopSandbox(ctx context.Context, sandbox *Sandbox) error {
	return nil
}

// createContainer is the Noop agent Container creation implementatiou. It does nothing.
func (u *uruncAgent) createContainer(ctx context.Context, sandbox *Sandbox, c *Container) (*Process, error) {
	logF := logrus.Fields{"src": "uruncio", "file": "vc/urunc_agent.go", "func": "createContainer"}

	u.ExecData.Container = c

	if u.ExecData.IPAddress == "" {
		u.Logger().WithFields(logF).Error("IP empty, generating...")

		interfaces, _, _, err := generateVCNetworkStructures(ctx, sandbox.network)
		// interfaces, routes, neighs, err := generateVCNetworkStructures(ctx, sandbox.network)
		if err != nil {
			u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("IP error...")
		}
		u.Logger().WithFields(logF).Error("IP generated...")

		u.Logger().WithFields(logF).WithField("interfaces", len(interfaces)).Error("IP1")
		// interfaces is 0
		u.Logger().WithFields(logF).WithField("IPAddresses", len(interfaces[0].IPAddresses)).Error("IP2")
		IPAddress := interfaces[0].IPAddresses[0].Address

		u.Logger().WithFields(logF).Error("IP found...")
		mask := interfaces[0].IPAddresses[0].Mask
		u.Logger().WithFields(logF).Error("Mask found...")

		u.Logger().WithFields(logF).WithField("IPAddress", IPAddress).Error("createContainer 4.5")
		u.Logger().WithFields(logF).WithField("mask", mask).Error("createContainer 4.5")
		u.ExecData.IPAddress = IPAddress
		u.ExecData.Mask = mask
	}
	u.Logger().WithFields(logF).WithField("IPADDR", u.ExecData.IPAddress).Error("IPADDR")

	// first lets get some data to better understand the process.

	// First, let's find our cwd.
	cwdPath, err := os.Getwd()
	if err != nil {
		u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("cwd error")
	} else {
		u.Logger().WithFields(logF).WithField("cwd", string(cwdPath)).Error("cwd OK")
	}

	// Let's find our cwd direct subdirs/files.
	ls1Out, err := osexec.Command("ls").Output()
	if err != nil {
		u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("ls 1 error")
	} else {
		u.Logger().WithFields(logF).WithField("out", string(ls1Out)).Error("ls 1 OK")
	}

	// Our cwd had a ./rootfs subdir. Let's have a closer look:
	ls2Out, err := osexec.Command("ls", "rootfs").Output()
	if err != nil {
		u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("ls 2 error")
	} else {
		u.Logger().WithFields(logF).WithField("out", string(ls2Out)).Error("ls 2 OK")
	}

	// we need to check if is devmapper or not.
	// if c.rootFs.Source is "", then no devmapper.
	// if c.rootFs.Source is "/dev/dm-*", then we need to mount the block device

	rootFsPath := "/run/containerd/io.containerd.runtime.v2.task/default/" + c.id + "/" + c.rootfsSuffix
	u.Logger().WithFields(logF).WithField("rootFsPath", rootFsPath).Error("")

	if c.rootFs.Source != "" {
		u.Logger().WithFields(logF).Error("Devmapper")

		// We can mount the block device either in one of the two provided dirs
		// - defaultKataHostSharedDir     = "/run/kata-containers/shared/sandboxes/"
		// - defaultKataGuestSharedDir    = "/run/kata-containers/shared/containers/"

		// I used to create a "/run/kata-containers/shared/containers/"+Container ID dir and mount it there. If that's
		// the case, we will need to change dir, or change the search prefix to find the file.

		// or we can mount in our current dir's rootfs subdirectory:
		// /run/containerd/io.containerd.runtime.v2.task/default/{Container ID}/rootfs
		// and keep the same workflow as if it wasn't a devmap device.

		mntOut, err := osexec.Command("mount", c.rootFs.Source, rootFsPath).CombinedOutput()
		if err != nil {
			u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("mount error")
		} else {
			u.Logger().WithFields(logF).WithField("out", string(mntOut)).Error("mount OK")
		}
	}

	// Now the ./rootfs/ dir should contain the unikernel or the pause file.
	ls3out, err := osexec.Command("ls", "rootfs").Output()
	if err != nil {
		u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("ls 3 error")
	} else {
		u.Logger().WithFields(logF).WithField("out", string(ls3out)).Error("ls 3 OK")
	}

	// we need to parse the contents of the bundle's rootfs.
	// if it contains a single /unikernel/file, we execute that file.
	// if it contains a single /pause file, we do nothing (or execute it, we must explore that)
	// if it contains a /unikernel/*.hvt file, we must create a cmd string and execute it,.

	lsResult := string(ls3out)
	lsResult = strings.ReplaceAll(lsResult, "\n", "")
	lsResult = strings.ReplaceAll(lsResult, "/", "")
	lsResult = strings.ReplaceAll(lsResult, " ", "")
	u.Logger().WithFields(logF).WithField("lsResult", lsResult).Error("")

	if lsResult == "pause" {
		u.ExecData.BinaryType = "pause"
		u.ExecData.BinaryPath = rootFsPath + "/pause"
	} else if lsResult != "unikernel" {
		return &Process{}, errors.New("requested image not supported")
	} else {
		// if we made it to this step, we need to find if .hvt or not
		ls4out, err := osexec.Command("ls", "rootfs/unikernel").Output()
		if err != nil {
			u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("ls 4 error")
		} else {
			u.Logger().WithFields(logF).WithField("out", string(ls4out)).Error("ls 4 OK")
		}
		lsResult := string(ls4out)
		lsResult = strings.ReplaceAll(lsResult, "\n", "")
		lsResult = strings.ReplaceAll(lsResult, "/", "")
		lsResult = strings.ReplaceAll(lsResult, " ", "")
		u.Logger().WithFields(logF).WithField("unikernelBinary", string(lsResult)).Error("ls4out")

		// now let's check if ".hvt" or not
		if strings.Contains(lsResult, ".hvt") {
			u.ExecData.BinaryType = "hvt"
			u.ExecData.BinaryPath = rootFsPath + "/unikernel/" + lsResult
		} else {
			u.ExecData.BinaryType = "unikernel"
			u.ExecData.BinaryPath = rootFsPath + "/unikernel/" + lsResult
		}
	}
	u.Logger().WithFields(logF).WithField("u.ExecData", u.ExecData.BinaryType).Error("return")

	// we must also create a netns, find the IP and pass them as args to qemu

	return &Process{}, nil
}

// startContainer is the Noop agent Container starting implementatiou. It does nothing.
func (u *uruncAgent) startContainer(ctx context.Context, sandbox *Sandbox, c *Container) error {

	logF := logrus.Fields{"src": "uruncio", "file": "vc/urunc_agent.go", "func": "startContainer"}
	u.Logger().WithFields(logF).Error("START")

	if sharedRootfs, err := sandbox.fsShare.ShareRootFilesystem(ctx, c); err != nil {
		u.Logger().WithFields(logF).Error(sharedRootfs.guestPath)
		// return nil
	}

	return nil
}

// Unmounts block device and tries to remove any related directories
func (u *uruncAgent) stopContainer(ctx context.Context, sandbox *Sandbox, c Container) error {
	logF := logrus.Fields{"src": "uruncio", "file": "vc/urunc_agent.go", "func": "stopContainer"}
	rootfsSourcePath := c.rootFs.Source
	u.Logger().WithFields(logF).WithField("rootfsSourcePath", rootfsSourcePath).Error("stopContainer 1")

	rootfsGuestPath := filepath.Join(kataGuestSharedDir(), c.id, c.rootfsSuffix)
	u.Logger().WithFields(logF).WithField("rootfsGuestPath", rootfsGuestPath).Error("createContainer 2")
	rootFsPath := "/run/containerd/io.containerd.runtime.v2.task/default/" + c.id + "/" + c.rootfsSuffix

	if rootfsSourcePath != "" {

		umnt1Out, err := osexec.Command("umount", "/run/kata-containers/shared/containers/"+c.id+"/rootfs").Output()
		if err != nil {
			u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("unmount 1 error")
		} else {
			u.Logger().WithFields(logF).WithField("out", string(umnt1Out)).Error("unmount 1 OK")
		}

		//  This unmount is also handled earlier by kata, but I left it just in case.
		umnt2Out, err := osexec.Command("umount", rootFsPath).Output()
		if err != nil {
			u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("unmount 2 error")
		} else {
			u.Logger().WithFields(logF).WithField("out", string(umnt2Out)).Error("unmount 2 OK")
		}

		// remove garbage dirs
		rmOut, err := osexec.Command("rm", "-rf", "/run/kata-containers/shared/containers/"+c.id).Output()
		if err != nil {
			u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("rm container error")
		} else {
			u.Logger().WithFields(logF).WithField("out", string(rmOut)).Error("rm container OK")
		}

		rmOut, err = osexec.Command("rm", "-rf", "/run/kata-containers/shared/sandboxes/"+c.id).Output()
		if err != nil {
			u.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("rm sandbox error")
		} else {
			u.Logger().WithFields(logF).WithField("out", string(rmOut)).Error("rm sandbox OK")
		}
	}
	return nil
}

// signalProcess is the Noop agent Container signaling implementatiou. It does nothing.
func (u *uruncAgent) signalProcess(ctx context.Context, c *Container, processID string, signal syscall.Signal, all bool) error {
	return nil
}

// updateContainer is the Noop agent Container update implementatiou. It does nothing.
func (u *uruncAgent) updateContainer(ctx context.Context, sandbox *Sandbox, c Container, resources specs.LinuxResources) error {
	return nil
}

// memHotplugByProbe is the Noop agent notify meomory hotplug event via probe interface implementatiou. It does nothing.
func (u *uruncAgent) memHotplugByProbe(ctx context.Context, addr uint64, sizeMB uint32, memorySectionSizeMB uint32) error {
	return nil
}

// onlineCPUMem is the Noop agent Container online CPU and Memory implementatiou. It does nothing.
func (u *uruncAgent) onlineCPUMem(ctx context.Context, cpus uint32, cpuOnly bool) error {
	return nil
}

// updateInterface is the Noop agent Interface update implementatiou. It does nothing.
func (u *uruncAgent) updateInterface(ctx context.Context, inf *pbTypes.Interface) (*pbTypes.Interface, error) {
	return nil, nil
}

// listInterfaces is the Noop agent Interfaces list implementatiou. It does nothing.
func (u *uruncAgent) listInterfaces(ctx context.Context) ([]*pbTypes.Interface, error) {
	return nil, nil
}

// updateRoutes is the Noop agent Routes update implementatiou. It does nothing.
func (u *uruncAgent) updateRoutes(ctx context.Context, routes []*pbTypes.Route) ([]*pbTypes.Route, error) {
	return nil, nil
}

// listRoutes is the Noop agent Routes list implementatiou. It does nothing.
func (u *uruncAgent) listRoutes(ctx context.Context) ([]*pbTypes.Route, error) {
	return nil, nil
}

// check is the Noop agent health checker. It does nothing.
func (u *uruncAgent) check(ctx context.Context) error {
	return nil
}

// statsContainer is the Noop agent Container stats implementatiou. It does nothing.
func (u *uruncAgent) statsContainer(ctx context.Context, sandbox *Sandbox, c Container) (*ContainerStats, error) {
	return &ContainerStats{}, nil
}

// waitProcess is the Noop agent process waiter. It does nothing.
func (u *uruncAgent) waitProcess(ctx context.Context, c *Container, processID string) (int32, error) {
	return 0, nil
}

// winsizeProcess is the Noop agent process tty resizer. It does nothing.
func (u *uruncAgent) winsizeProcess(ctx context.Context, c *Container, processID string, height, width uint32) error {
	return nil
}

// writeProcessStdin is the Noop agent process stdin writer. It does nothing.
func (u *uruncAgent) writeProcessStdin(ctx context.Context, c *Container, ProcessID string, data []byte) (int, error) {
	return 0, nil
}

// closeProcessStdin is the Noop agent process stdin closer. It does nothing.
func (u *uruncAgent) closeProcessStdin(ctx context.Context, c *Container, ProcessID string) error {
	return nil
}

// readProcessStdout is the Noop agent process stdout reader. It does nothing.
func (u *uruncAgent) readProcessStdout(ctx context.Context, c *Container, processID string, data []byte) (int, error) {
	return 0, nil
}

// readProcessStderr is the Noop agent process stderr reader. It does nothing.
func (u *uruncAgent) readProcessStderr(ctx context.Context, c *Container, processID string, data []byte) (int, error) {
	return 0, nil
}

// pauseContainer is the Noop agent Container pause implementatiou. It does nothing.
func (u *uruncAgent) pauseContainer(ctx context.Context, sandbox *Sandbox, c Container) error {
	return nil
}

// resumeContainer is the Noop agent Container resume implementatiou. It does nothing.
func (u *uruncAgent) resumeContainer(ctx context.Context, sandbox *Sandbox, c Container) error {
	return nil
}

// configure is the Noop agent configuration implementatiou. It does nothing.
func (u *uruncAgent) configure(ctx context.Context, h Hypervisor, id, sharePath string, config KataAgentConfig) error {
	return nil
}

func (u *uruncAgent) configureFromGrpc(ctx context.Context, h Hypervisor, id string, config KataAgentConfig) error {
	return nil
}

// reseedRNG is the Noop agent RND reseeder. It does nothing.
func (u *uruncAgent) reseedRNG(ctx context.Context, data []byte) error {
	return nil
}

// reuseAgent is the Noop agent reuser. It does nothing.
func (u *uruncAgent) reuseAgent(agent agent) error {
	return nil
}

// getAgentURL is the Noop agent url getter. It returns nothing.
func (u *uruncAgent) getAgentURL() (string, error) {
	return "", nil
}

// setAgentURL is the Noop agent url setter. It does nothing.
func (u *uruncAgent) setAgentURL() error {
	return nil
}

// getGuestDetails is the Noop agent GuestDetails queryer. It does nothing.
func (u *uruncAgent) getGuestDetails(context.Context, *grpc.GuestDetailsRequest) (*grpc.GuestDetailsResponse, error) {
	return nil, nil
}

// setGuestDateTime is the Noop agent guest time setter. It does nothing.
func (u *uruncAgent) setGuestDateTime(context.Context, time.Time) error {
	return nil
}

// copyFile is the Noop agent copy file. It does nothing.
func (u *uruncAgent) copyFile(ctx context.Context, src, dst string) error {
	return nil
}

// addSwap is the Noop agent setup swap. It does nothing.
func (u *uruncAgent) addSwap(ctx context.Context, PCIPath vcTypes.PciPath) error {
	return nil
}

func (u *uruncAgent) markDead(ctx context.Context) {
}

func (u *uruncAgent) cleanup(ctx context.Context) {
}

// save is the Noop agent state saver. It does nothing.
func (u *uruncAgent) save() (s persistapi.AgentState) {
	return
}

// load is the Noop agent state loader. It does nothing.
func (u *uruncAgent) load(s persistapi.AgentState) {}

func (u *uruncAgent) getOOMEvent(ctx context.Context) (string, error) {
	return "", nil
}

func (u *uruncAgent) getAgentMetrics(ctx context.Context, req *grpc.GetMetricsRequest) (*grpc.Metrics, error) {
	return nil, nil
}

func (u *uruncAgent) getGuestVolumeStats(ctx context.Context, volumeGuestPath string) ([]byte, error) {
	return nil, nil
}

func (u *uruncAgent) resizeGuestVolume(ctx context.Context, volumeGuestPath string, size uint64) error {
	return nil
}
