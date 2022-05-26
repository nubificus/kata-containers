// Copyright (c) 2016 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"os"
	"path/filepath"
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

// mockAgent is an empty Agent implementation, for testing and
// mocking purposes.
type mockAgent struct {
	container *Container
	IPAddress string
	mask	string
}

func (n *mockAgent) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "mock_agent")
}

// nolint:golint
func NewMockAgent() agent {
	return &mockAgent{}
}

// init initializes the Noop agent, i.e. it does nothing.
func (n *mockAgent) init(ctx context.Context, sandbox *Sandbox, config KataAgentConfig) (bool, error) {
	logF := logrus.Fields{"src": "uruncio", "file": "vs/mock_agent.go", "func": "init"}
	n.Logger().WithFields(logF).Error("mock agent init")
	for _, mnt := range sandbox.config.SandboxBindMounts {
		msg := "mount is " + mnt
		n.Logger().WithFields(logF).Error(msg)
	}
	return false, nil
}

func (n *mockAgent) longLiveConn() bool {
	return false
}

// createSandbox is the Noop agent sandbox creation implementation. It does nothing.
func (n *mockAgent) createSandbox(ctx context.Context, sandbox *Sandbox) error {
	return nil
}

// capabilities returns empty capabilities, i.e no capabilties are supported.
func (n *mockAgent) capabilities() types.Capabilities {
	return types.Capabilities{}
}

// disconnect is the Noop agent connection closer. It does nothing.
func (n *mockAgent) disconnect(ctx context.Context) error {
	return nil
}

// exec is the Noop agent command execution implementation. It does nothing.
func (n *mockAgent) exec(ctx context.Context, sandbox *Sandbox, c Container, cmd types.Cmd) (*Process, error) {
	return nil, nil
}

// startSandbox is the Noop agent Sandbox starting implementation. It does nothing.
func (n *mockAgent) startSandbox(ctx context.Context, sandbox *Sandbox) error {

	// Setup network interfaces and routes
	interfaces, routes, neighs, err := generateVCNetworkStructures(ctx, sandbox.network)
	if err != nil {
		return err
	}

	n.Logger().WithField("interfaces", interfaces).Error("createContainer 4")
	//msg="createContainer 4" interfaces="[&Interface{Device:eth0,Name:eth0,IPAddresses:[]*IPAddress{&IPAddress{Family:v4,Address:10.4.0.20,Mask:24,XXX_unrecognized:[],},&IPAddress{Family:v6,Address:fe80::9c89:5ff:feb5:86d5,Mask:64,XXX_unrecognized:[],},},Mtu:1500,HwAddr:9e:89:05:b5:86:d5,PciPath:,Type:,RawFlags:0,XXX_unrecognized:[],}]" name=containerd-shim-v2 pid=1371845 sandbox=c06d6ba018f0036de74eb529263801b5ea7c611384478d9ecf5385992e4c9edd source=virtcontainers subsystem=mock_agent
	IPAddress := interfaces[0].IPAddresses[0].Address
	mask := interfaces[0].IPAddresses[0].Mask
	n.Logger().WithField("IPAddress", IPAddress).Error("createContainer 4.5")
	n.Logger().WithField("mask", mask).Error("createContainer 4.5")
	n.Logger().WithField("routes", routes).Error("createContainer 4.5")
	n.Logger().WithField("neighs", neighs).Error("createContainer 4.5")
	n.IPAddress = IPAddress
	n.mask = mask
	return nil
}

// stopSandbox is the Noop agent Sandbox stopping implementation. It does nothing.
func (n *mockAgent) stopSandbox(ctx context.Context, sandbox *Sandbox) error {
	return nil
}

// createContainer is the Noop agent Container creation implementation. It does nothing.
func (n *mockAgent) createContainer(ctx context.Context, sandbox *Sandbox, c *Container) (*Process, error) {

	logF := logrus.Fields{"src": "uruncio", "file": "vc/mock_agent.go", "func": "createContainer"}
	n.Logger().WithFields(logF).WithField("c.rootFs.Source", c.rootFs.Source).Error("createContainer 1")
	n.Logger().WithFields(logF).WithField("c.rootfsSuffix", c.rootfsSuffix).Error("createContainer 1.5")
	rootfsSourcePath := c.rootFs.Source
	n.Logger().WithFields(logF).WithField("rootfsSourcePath", rootfsSourcePath).Error("createContainer 1.7")

	// defaultKataHostSharedDir     = "/run/kata-containers/shared/sandboxes/"
	// defaultKataGuestSharedDir    = "/run/kata-containers/shared/containers/"
	n.container = c

	rootfsGuestPath := filepath.Join("/run/kata-containers/shared/containers/", c.id, c.rootfsSuffix)
	n.Logger().WithFields(logF).WithField("rootfsGuestPath", rootfsGuestPath).Error("createContainer 2")

	// then it is a devmapper device
	if rootfsSourcePath != "" {
		// getcwd
		cwdPath, err := os.Getwd()
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("pwd error")
		} else {
			n.Logger().WithFields(logF).WithField("cwd", string(cwdPath)).Error("pwd OK")
		}

		// create dir
		mkdirOut, err := osexec.Command("mkdir", "-p", rootfsGuestPath).Output()
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("mkdir error")
		} else {
			n.Logger().WithFields(logF).WithField("out", string(mkdirOut)).Error("mdkir OK")
		}

		// mount dev to dir
		mntOut, err := osexec.Command("mount", rootfsSourcePath, rootfsGuestPath).Output()
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("mount error")
		} else {
			n.Logger().WithFields(logF).WithField("out", string(mntOut)).Error("mount OK")
		}

		// change wd to dir
		//err = os.Chdir(rootfsGuestPath)
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("chdir error")
		} else {
			n.Logger().WithFields(logF).WithField("out", string(mkdirOut)).Error("chdir OK")
		}

		lsOut, err := osexec.Command("ls", rootfsGuestPath).Output()
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("ls 1 error")
		} else {
			n.Logger().WithFields(logF).WithField("out", string(lsOut)).Error("ls 1 OK")
		}

		rootFsKataHostSharedDir := "/run/kata-containers/shared/sandboxes/" + c.id

		lsOut, err = osexec.Command("ls", rootFsKataHostSharedDir).Output()
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("ls 2 error")
		} else {
			n.Logger().WithFields(logF).WithField("out", string(lsOut)).Error("ls 2 OK")
		}

	}

	return &Process{}, nil
}

// startContainer is the Noop agent Container starting implementation. It does nothing.
func (n *mockAgent) startContainer(ctx context.Context, sandbox *Sandbox, c *Container) error {
	logF := logrus.Fields{"src": "uruncio", "file": "vc/mock_agent.go", "func": "startContainer"}

	if sharedRootfs, err := sandbox.fsShare.ShareRootFilesystem(ctx, c); err != nil {
		n.Logger().WithFields(logF).Error(sharedRootfs.guestPath)
		// return nil
	}

	return nil
}

// stopContainer is the Noop agent Container stopping implementation. It does nothing.
func (n *mockAgent) stopContainer(ctx context.Context, sandbox *Sandbox, c Container) error {
	logF := logrus.Fields{"src": "uruncio", "file": "vc/mock_agent.go", "func": "stopContainer"}
	rootfsSourcePath := c.rootFs.Source
	n.Logger().WithFields(logF).WithField("rootfsSourcePath", rootfsSourcePath).Error("stopContainer 1")

	if rootfsSourcePath != "" {


		cwd, err := os.Getwd()
		n.Logger().WithFields(logF).WithField("cwd", cwd).Error("getcwd")
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("chdir error")
		}
		err = os.Chdir("/")
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("chdir error")
		}
		cwd, err = os.Getwd()
		n.Logger().WithFields(logF).WithField("cwd", cwd).Error("getcwd")
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("chdir error")
		}

		umntOut, err := osexec.Command("umount", "/run/kata-containers/shared/containers/"+c.id+"/rootfs").Output()
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("unmount error")
		} else {
			n.Logger().WithFields(logF).WithField("out", string(umntOut)).Error("unmount OK")
		}

		// remove garbage dirs
		rmOut, err := osexec.Command("rm", "-rf", "/run/kata-containers/shared/containers/"+c.id).Output()
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("rm container error")
		} else {
			n.Logger().WithFields(logF).WithField("out", string(rmOut)).Error("rm container OK")
		}

		rmOut, err = osexec.Command("rm", "-rf", "/run/kata-containers/shared/sandboxes/"+c.id).Output()
		if err != nil {
			n.Logger().WithFields(logF).WithField("errmsg", err.Error()).Error("rm sandbox error")
		} else {
			n.Logger().WithFields(logF).WithField("out", string(rmOut)).Error("rm sandbox OK")
		}
	}
	// defaultKataHostSharedDir     = "/run/kata-containers/shared/sandboxes/"
	// defaultKataGuestSharedDir    = "/run/kata-containers/shared/containers/"

	// rootfsGuestPath := filepath.Join(kataGuestSharedDir(), c.id, c.rootfsSuffix)
	// n.Logger().WithFields(logF).WithField("rootfsGuestPath", rootfsGuestPath).Error("createContainer 2")

	// n.Logger().WithFields(logF).WithField("c.rootFs.Source", c.rootFs.Source).Error("stopContainer 1")

	// mntDir := "/run/kata-containers/shared/containers/urunc-kata-test/rootfs"

	// This is the /dev/dm- path. Not sure if at all useful
	// rootfsSourcePath := c.rootFs.Source

	// defaultKataHostSharedDir     = "/run/kata-containers/shared/sandboxes/"
	// defaultKataGuestSharedDir    = "/run/kata-containers/shared/containers/"

	// rootfsGuestPath := filepath.Join(kataGuestSharedDir(), c.id, c.rootfsSuffix)
	// n.Logger().WithFields(logF).WithField("rootfsGuestPath", rootfsGuestPath).Error("createContainer 2")

	// umount dir
	// umount /run/kata-containers/shared/containers/urunc-kata-test/rootfs

	return nil
}

// signalProcess is the Noop agent Container signaling implementation. It does nothing.
func (n *mockAgent) signalProcess(ctx context.Context, c *Container, processID string, signal syscall.Signal, all bool) error {
	return nil
}

// updateContainer is the Noop agent Container update implementation. It does nothing.
func (n *mockAgent) updateContainer(ctx context.Context, sandbox *Sandbox, c Container, resources specs.LinuxResources) error {
	return nil
}

// memHotplugByProbe is the Noop agent notify meomory hotplug event via probe interface implementation. It does nothing.
func (n *mockAgent) memHotplugByProbe(ctx context.Context, addr uint64, sizeMB uint32, memorySectionSizeMB uint32) error {
	return nil
}

// onlineCPUMem is the Noop agent Container online CPU and Memory implementation. It does nothing.
func (n *mockAgent) onlineCPUMem(ctx context.Context, cpus uint32, cpuOnly bool) error {
	return nil
}

// updateInterface is the Noop agent Interface update implementation. It does nothing.
func (n *mockAgent) updateInterface(ctx context.Context, inf *pbTypes.Interface) (*pbTypes.Interface, error) {
	return nil, nil
}

// listInterfaces is the Noop agent Interfaces list implementation. It does nothing.
func (n *mockAgent) listInterfaces(ctx context.Context) ([]*pbTypes.Interface, error) {
	return nil, nil
}

// updateRoutes is the Noop agent Routes update implementation. It does nothing.
func (n *mockAgent) updateRoutes(ctx context.Context, routes []*pbTypes.Route) ([]*pbTypes.Route, error) {
	return nil, nil
}

// listRoutes is the Noop agent Routes list implementation. It does nothing.
func (n *mockAgent) listRoutes(ctx context.Context) ([]*pbTypes.Route, error) {
	return nil, nil
}

// check is the Noop agent health checker. It does nothing.
func (n *mockAgent) check(ctx context.Context) error {
	return nil
}

// statsContainer is the Noop agent Container stats implementation. It does nothing.
func (n *mockAgent) statsContainer(ctx context.Context, sandbox *Sandbox, c Container) (*ContainerStats, error) {
	return &ContainerStats{}, nil
}

// waitProcess is the Noop agent process waiter. It does nothing.
func (n *mockAgent) waitProcess(ctx context.Context, c *Container, processID string) (int32, error) {
	return 0, nil
}

// winsizeProcess is the Noop agent process tty resizer. It does nothing.
func (n *mockAgent) winsizeProcess(ctx context.Context, c *Container, processID string, height, width uint32) error {
	return nil
}

// writeProcessStdin is the Noop agent process stdin writer. It does nothing.
func (n *mockAgent) writeProcessStdin(ctx context.Context, c *Container, ProcessID string, data []byte) (int, error) {
	return 0, nil
}

// closeProcessStdin is the Noop agent process stdin closer. It does nothing.
func (n *mockAgent) closeProcessStdin(ctx context.Context, c *Container, ProcessID string) error {
	return nil
}

// readProcessStdout is the Noop agent process stdout reader. It does nothing.
func (n *mockAgent) readProcessStdout(ctx context.Context, c *Container, processID string, data []byte) (int, error) {
	return 0, nil
}

// readProcessStderr is the Noop agent process stderr reader. It does nothing.
func (n *mockAgent) readProcessStderr(ctx context.Context, c *Container, processID string, data []byte) (int, error) {
	return 0, nil
}

// pauseContainer is the Noop agent Container pause implementation. It does nothing.
func (n *mockAgent) pauseContainer(ctx context.Context, sandbox *Sandbox, c Container) error {
	return nil
}

// resumeContainer is the Noop agent Container resume implementation. It does nothing.
func (n *mockAgent) resumeContainer(ctx context.Context, sandbox *Sandbox, c Container) error {
	return nil
}

// configure is the Noop agent configuration implementation. It does nothing.
func (n *mockAgent) configure(ctx context.Context, h Hypervisor, id, sharePath string, config KataAgentConfig) error {
	return nil
}

func (n *mockAgent) configureFromGrpc(ctx context.Context, h Hypervisor, id string, config KataAgentConfig) error {
	return nil
}

// reseedRNG is the Noop agent RND reseeder. It does nothing.
func (n *mockAgent) reseedRNG(ctx context.Context, data []byte) error {
	return nil
}

// reuseAgent is the Noop agent reuser. It does nothing.
func (n *mockAgent) reuseAgent(agent agent) error {
	return nil
}

// getAgentURL is the Noop agent url getter. It returns nothing.
func (n *mockAgent) getAgentURL() (string, error) {
	return "", nil
}

// setAgentURL is the Noop agent url setter. It does nothing.
func (n *mockAgent) setAgentURL() error {
	return nil
}

// getGuestDetails is the Noop agent GuestDetails queryer. It does nothing.
func (n *mockAgent) getGuestDetails(context.Context, *grpc.GuestDetailsRequest) (*grpc.GuestDetailsResponse, error) {
	return nil, nil
}

// setGuestDateTime is the Noop agent guest time setter. It does nothing.
func (n *mockAgent) setGuestDateTime(context.Context, time.Time) error {
	return nil
}

// copyFile is the Noop agent copy file. It does nothing.
func (n *mockAgent) copyFile(ctx context.Context, src, dst string) error {
	return nil
}

// addSwap is the Noop agent setup swap. It does nothing.
func (n *mockAgent) addSwap(ctx context.Context, PCIPath vcTypes.PciPath) error {
	return nil
}

func (n *mockAgent) markDead(ctx context.Context) {
}

func (n *mockAgent) cleanup(ctx context.Context) {
}

// save is the Noop agent state saver. It does nothing.
func (n *mockAgent) save() (s persistapi.AgentState) {
	return
}

// load is the Noop agent state loader. It does nothing.
func (n *mockAgent) load(s persistapi.AgentState) {}

func (n *mockAgent) getOOMEvent(ctx context.Context) (string, error) {
	return "", nil
}

func (n *mockAgent) getAgentMetrics(ctx context.Context, req *grpc.GetMetricsRequest) (*grpc.Metrics, error) {
	return nil, nil
}

func (n *mockAgent) getGuestVolumeStats(ctx context.Context, volumeGuestPath string) ([]byte, error) {
	return nil, nil
}

func (n *mockAgent) resizeGuestVolume(ctx context.Context, volumeGuestPath string, size uint64) error {
	return nil
}
