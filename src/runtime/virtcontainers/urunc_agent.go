// Copyright (c) 2016 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
	Tap        string
	Gateway    string
	Container  *Container
	NetNs      string
	BlkDevice  string
}

// uruncAgent is an empty Agent implementation, for deploying unikernels
// We can add some fields here if we need to persist data between agent calls.
type uruncAgent struct {
	ExecData ExecData
}

// helper function to parse ls results
func cleanLsRes(res string) string {
	res = strings.ReplaceAll(res, "\n", " ")
	res = strings.ReplaceAll(res, "  ", " ")
	res = strings.TrimSpace(res)
	return res
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
		Gateway:    "",
		Tap:        "",
		NetNs:      "",
		BlkDevice:  "",
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

func (u *uruncAgent) Name() string {
	return "urunc"
}

// init initializes the Noop agent, i.e. it does nothing.
func (u *uruncAgent) init(ctx context.Context, sandbox *Sandbox, config KataAgentConfig) (bool, error) {
	logF := logrus.Fields{"src": "uruncio", "file": "vs/urunc_agent.go", "func": "init"}
	logrus.WithFields(logF).Error("urunc agent init")
	for _, mnt := range sandbox.config.SandboxBindMounts {
		msg := "mount is " + mnt
		logrus.WithFields(logF).Error(msg)
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
	u.Logger().WithFields(logF).Error("startSandbox")
	u.addNetworkData(ctx, sandbox)
	return nil
}

// stopSandbox is the Noop agent Sandbox stopping implementatiou. It does nothing.
func (u *uruncAgent) stopSandbox(ctx context.Context, sandbox *Sandbox) error {
	return nil
}

func (u *uruncAgent) addNetworkData(ctx context.Context, sandbox *Sandbox) error {
	logF := logrus.Fields{"src": "uruncio", "file": "vc/urunc_agent.go", "func": "addNetworkData"}
	logrus.WithFields(logF).Error("")

	if u.ExecData.IPAddress == "" {
		logrus.WithFields(logF).Error("IP not set, generating...")
		interfaces, routes, _, err := generateVCNetworkStructures(ctx, sandbox.network)
		if err != nil {
			logrus.WithFields(logF).WithField("errmsg", err.Error()).Error("IP generation error...")
			return err
		}
		logrus.WithFields(logF).WithField("interfaces len", len(interfaces)).WithField("routes len", len(routes)).Error("")

		// usually there are 2 routes and 1 interface, so I take the first of each one
		if len(routes) >= 1 && len(interfaces) >= 1 {
			u.ExecData.IPAddress = interfaces[0].IPAddresses[0].Address
			u.ExecData.Mask = interfaces[0].IPAddresses[0].Mask
			u.ExecData.Tap = interfaces[0].Device
			u.ExecData.Gateway = routes[0].Gateway
			u.ExecData.NetNs = sandbox.GetNetNs()

			netData := logrus.Fields{"IP": interfaces[0].IPAddresses[0].Address, "mask": interfaces[0].IPAddresses[0].Mask, "tap": interfaces[0].Device, "gw": routes[0].Gateway, "ns": sandbox.GetNetNs()}
			logrus.WithFields(logF).WithFields(netData).Error("")
		} else {
			logrus.WithFields(logF).Error("Network creation failed")
			return errors.New("Network creation failed")
		}
	} else {
		logrus.WithFields(logF).Error("Network is already created")
	}
	return nil
}

// createContainer retrieves the net data, mounts rootfs if necessary and
// populates the uruncAgent exec data fields
func (u *uruncAgent) createContainer(ctx context.Context, sandbox *Sandbox, c *Container) (*Process, error) {
	logF := logrus.Fields{"src": "uruncio", "file": "vc/urunc_agent.go", "func": "createContainer"}

	// Get the network data
	u.ExecData.Container = c
	u.addNetworkData(ctx, sandbox)
	if u.ExecData.IPAddress != "" {
		logrus.WithFields(logF).WithField("IP", u.ExecData.IPAddress).Error("Network data added")
	} else {
		logrus.WithFields(logF).Error("Network creation failed")
	}

	// Find the bundle data
	logrus.WithFields(logF).WithField("CID", c.ID()).Error("")
	logrus.WithFields(logF).WithField("SID", sandbox.ID()).Error("")

	lsPrefix := "."

	// Find cwd
	cwdPath, err := os.Getwd()
	if err != nil {
		logrus.WithFields(logF).WithField("cwdErr", err.Error()).Error("")
	} else {
		logrus.WithFields(logF).WithField("cwd", string(cwdPath)).Error("")
	}
	cwdPath = strings.ReplaceAll(cwdPath, " ", "")
	cwdPath = strings.TrimSpace(cwdPath)

	// Check if sandboxID eq containerID
	if c.ID() != sandbox.ID() {
		logrus.WithFields(logF).Error("Sandbox already exists")
		cwdPath = strings.ReplaceAll(cwdPath, sandbox.ID(), c.ID())
		lsPrefix = cwdPath
	}

	// Mount device if needed and parse rootfs for binary

	// The expected file structure is:
	// .
	// ..
	// address
	// config.json
	// rootfs
	// shim-binary-path
	// shim.pid
	// work

	// Our rootfs path
	rootFsPath := cwdPath + "/" + c.rootfsSuffix

	// Let's find out more info from c.Rootfs
	tempFields := logrus.Fields{
		"rootFs_source": c.rootFs.Source,
		"rootFs_target": c.rootFs.Target,
		"rootFs_Type":   c.rootFs.Type,
		"rootFs_Path":   rootFsPath,
	}
	logrus.WithFields(logF).WithFields(tempFields).Error("rootfs info")

	// If c.rootFs.source contains "dm-", we need to mount the devmapper device, create a new dir with the device contents, then unmount the blk dev
	if strings.Contains(c.rootFs.Source, "dm") {
		logrus.WithFields(logF).Error("is devmapper, mounting...")
		logrus.WithFields(logF).WithField("rootFsPath", rootFsPath).Error("")
		mntCmd := "mount " + "-t " + c.rootFs.Type + " " + c.rootFs.Source + " " + rootFsPath
		logrus.WithFields(logF).WithField("mntCmd", mntCmd).Error("")
		mntOut, err := osexec.Command("mount", "-t", c.rootFs.Type, c.rootFs.Source, rootFsPath).CombinedOutput()
		if err != nil {
			logrus.WithFields(logF).WithField("mountErr", err.Error()).Error("")
			logrus.WithFields(logF).WithField("mountErr", string(mntOut)).Error("")
			return &Process{}, errors.New("failed to mount")
		}

		c.rootFs.Mounted = true
		c.rootFs.Target = rootFsPath
		logrus.WithFields(logF).Error("device mounted")

		// copy everything from rootFsPath to newDir
		newDir := strings.ReplaceAll(rootFsPath, "rootfs", "") + "tmp"
		logrus.WithFields(logF).WithField("newDir", string(newDir)).Error("")
		err = CopyDir(rootFsPath, newDir)
		if err != nil {
			logrus.WithFields(logF).WithField("cpdir", err.Error()).Error("Err copying1")
			return &Process{}, errors.New("failed to copy block device content")
		}
		logrus.WithFields(logF).Error("copying1 done")

		// unmount dev
		uMntOut, err := osexec.Command("umount", c.rootFs.Source).CombinedOutput()
		if err != nil {
			logrus.WithFields(logF).WithField("unmountErr", err.Error()).Error("")
			logrus.WithFields(logF).WithField("unmountErr", string(uMntOut)).Error("")
		}
		logrus.WithFields(logF).Error("unmount done")

		// rm rootfs in order to copy
		err = os.RemoveAll(rootFsPath)
		if err != nil {
			logrus.WithFields(logF).WithField("rmdir", err.Error()).Error("Err rming")
		}
		logrus.WithFields(logF).Error("rming done")

		// copy from newDir to rootfsPath
		err = CopyDir(newDir, rootFsPath)
		// err = CopyDir()
		if err != nil {
			logrus.WithFields(logF).WithField("cpdir", err.Error()).Error("Err copying2")
		}
		logrus.WithFields(logF).Error("copying2 done")

		// rm newDir
		err = os.RemoveAll(newDir)
		if err != nil {
			logrus.WithFields(logF).WithField("rmdir", err.Error()).Error("Err rming")
		}
		logrus.WithFields(logF).Error("rming done")

		// pass dev to execData
		u.ExecData.BlkDevice = c.rootFs.Source

		// .
		// rootfs
		// 		unikernel
		// mnt
		// 		rootfs
		// 			unikernel
		//

		// TODO: remove following lines
		// newDirFs := newDir + "/rootfs"
		// logrus.WithFields(logF).WithField("newDirFs", string(newDirFs)).Error("")
		// logrus.WithFields(logF).WithField("rootFsPath", string(rootFsPath)).Error("")
		// err = os.MkdirAll(newDirFs, os.ModePerm)
		// if err != nil {
		// 	logrus.WithFields(logF).WithField("newDirErr", err.Error()).Error("Err creating new dir")
		// }

		// //
		// logrus.WithFields(logF).WithField("newDir", string(newDir)).Error("Created new dir")

		// // chdir to new dir
		// err = os.Chdir(newDir)
		// if err != nil {
		// 	logrus.WithFields(logF).WithField("chdir", err.Error()).Error("Err chdir to new dir")
		// }

	}

	// Let's find our cwd direct subdirs/files.
	ls1Out, err := osexec.Command("ls", lsPrefix).Output()
	ls1 := cleanLsRes(string(ls1Out))
	if err != nil {
		logrus.WithFields(logF).WithField("ls1err", err.Error()).Error("")
	} else {
		logrus.WithFields(logF).WithField("ls1", ls1).Error("")
	}

	// Our cwd had a ./rootfs subdir. Let's have a closer look:
	ls2Out, err := osexec.Command("ls", lsPrefix+"/rootfs").Output()
	ls2 := cleanLsRes(string(ls2Out))
	if err != nil {
		logrus.WithFields(logF).WithField("ls2err", err.Error()).Error("")
	} else {
		logrus.WithFields(logF).WithField("ls2", ls2).Error("")
	}

	// we need to parse the contents of the bundle's rootfs.
	// if it containsa  single /unikernel/binary or /pause we execute that file.
	// if it contains a /unikernel/*.hvt or /unikernel/*.qm file, we must create a cmd string and execute it
	if strings.Contains(ls2, "unikernel") {
		ls2 = "unikernel"
	} else if strings.Contains(ls2, "pause") {
		ls2 = "pause"
	}
	switch ls2 {
	case "pause":
		u.ExecData.BinaryType = "pause"
		u.ExecData.BinaryPath = rootFsPath + "/pause"
		logrus.WithFields(logF).WithField("file", u.ExecData.BinaryPath).Error("")
		logrus.WithFields(logF).WithField("type", u.ExecData.BinaryType).Error("")
	case "unikernel":
		ls3out, err := osexec.Command("ls", lsPrefix+"/rootfs/unikernel").Output()
		ls3 := cleanLsRes(string(ls3out))
		if err != nil {
			logrus.WithFields(logF).WithField("ls3err", err.Error()).Error("")
		} else {
			logrus.WithFields(logF).WithField("ls3", ls3).Error("")
		}

		// now let's check if ".hvt" or not
		if strings.Contains(ls3, ".hvt") {
			u.ExecData.BinaryType = "hvt"
			u.ExecData.BinaryPath = rootFsPath + "/unikernel/" + ls3
		} else if strings.Contains(ls3, ".qm") {
			u.ExecData.BinaryType = "qemu"
			u.ExecData.BinaryPath = rootFsPath + "/unikernel/" + ls3
		} else {
			u.ExecData.BinaryType = "binary"
			u.ExecData.BinaryPath = rootFsPath + "/unikernel/" + ls3
			logrus.WithFields(logF).WithField("bin", u.ExecData.BinaryPath).Error("file to chmod")
		}
		logrus.WithFields(logF).WithField("file", u.ExecData.BinaryPath).Error("")
		logrus.WithFields(logF).WithField("type", u.ExecData.BinaryType).Error("")
	default:
		return &Process{}, errors.New("requested image not supported")
	}
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
	logrus.WithFields(logF).WithField("cid", c.id).Error("")

	// psOut, _ := osexec.Command("ps", "-ef", "|", "grep", c.id).Output()
	// logrus.WithFields(logF).WithField("psOut", string(psOut)).Error("")

	// pcs, err := ps.Processes()
	// if err == nil {
	// 	for _, pc := range pcs {
	// 		logrus.WithFields(logF).WithField("process", "mew").Error("ps")
	// 		p := pc.Executable()
	// 		logrus.WithFields(logF).WithField("pid", p).Error("ps")
	// 	}
	// }
	// logrus.WithFields(logF).WithField("ps-go", "end").Error("")

	rootfsSourcePath := c.rootFs.Source
	u.Logger().WithFields(logF).WithField("rootfsSourcePath", rootfsSourcePath).Error("stopContainer 1")

	rootfsGuestPath := filepath.Join(kataGuestSharedDir(), c.id, c.rootfsSuffix)
	u.Logger().WithFields(logF).WithField("rootfsGuestPath", rootfsGuestPath).Error("createContainer 2")

	// rootFsPath := "/run/containerd/io.containerd.runtime.v2.task/default/" + c.id + "/" + c.rootfsSuffix
	// This needs to change to the cwd path. the default ns is not used.
	// rootFsPath := "/run/containerd/io.containerd.runtime.v2.task/default/" + c.id + "/" + c.rootfsSuffix

	cwdPath, _ := os.Getwd()
	cwdPath = strings.ReplaceAll(cwdPath, " ", "")
	cwdPath = strings.TrimSpace(cwdPath)
	rootFsPath := cwdPath + c.id + "/" + c.rootfsSuffix
	u.Logger().WithFields(logF).WithField("rootFsPath", rootFsPath).Error("")

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

// URUNC SPECIFIC LOGIC

// type Command struct {
// 	cmdString string
// 	id        string
// 	stdin     string
// 	stdout    string
// 	stderr    string
// 	bundle    string
// 	exec      *osexec.Cmd
// }

// func (u *uruncAgent) CreateCommand(execData ExecData) *Command {
// 	logF := logrus.Fields{"src": "uruncio", "file": "vc/urunc_agent.go", "func": "CreateCommand"}
// 	cmdString := CmdLine(execData)
// 	logrus.WithField("BinaryType", execData.BinaryType).WithFields(logF).Error("exec info")
// 	logrus.WithField("cmdString", cmdString).WithFields(logF).Error("exec info")

// 	args := strings.Split(cmdString, " ")
// 	var newCmd *osexec.Cmd
// 	if len(args) == 1 {
// 		logrus.WithField("cmdString", args[0]).WithFields(logF).Error("exec info")
// 		newCmd = osexec.Command(args[0])
// 	} else {
// 		name, args := args[0], args[1:]
// 		newCmd = osexec.Command(name, args...)
// 	}
// 	return &Command{cmdString: cmdString, container: container, id: container.id, stdin: container.stdin, stdout: container.stdout, stderr: container.stderr, bundle: container.bundle, exec: newCmd}
// }

// func CmdLine(execData ExecData) string {

// 	// BinaryType string
// 	// BinaryPath string
// 	// IPAddress  string
// 	// Mask       string
// 	// Tap        string
// 	// Container  *Container
// 	logF := logrus.Fields{"src": "uruncio", "file": "vc/urunc_agent.go", "func": "CmdLine"}
// 	logrus.WithField("BinaryType", execData.BinaryType).WithFields(logF).Error("ExecData")
// 	logrus.WithField("BinaryPath", execData.BinaryPath).WithFields(logF).Error("ExecData")
// 	logrus.WithField("IPAddress", execData.IPAddress).WithFields(logF).Error("ExecData")
// 	logrus.WithField("Mask", execData.Mask).WithFields(logF).Error("ExecData")
// 	logrus.WithField("Tap", execData.Tap).WithFields(logF).Error("ExecData")
// 	logrus.WithField("Container", execData.Container.ID()).WithFields(logF).Error("ExecData")

// 	switch execData.BinaryType {
// 	case "pause":
// 		return execData.BinaryPath
// 	case "hvt":
// 		return HvtCmd(execData)
// 	case "qemu":
// 		return QemuCmd(execData)
// 	case "binary":
// 		return execData.BinaryPath
// 	default:
// 		return ""
// 	}
// }

// func HvtCmd(execData ExecData) string {
// 	// ./tenders/hvt/solo5-hvt --net:service0=tap192  tests/test_net/test_net.hvt
// 	return "HvtMonitor" + "--net:service0=" + execData.Tap + " " + execData.BinaryPath
// }

// func QemuCmd(execData ExecData) string {
// 	qemuCmd := "qemu-system-x86_64 -cpu host"
// 	qemuCmd += " -enable-kvm"
// 	qemuCmd += " -m 128"
// 	qemuCmd += " -nodefaults -no-acpi "
// 	qemuCmd += " -display none -serial stdio "
// 	qemuCmd += " -device isa-debug-exit "
// 	qemuCmd += " -net nic,model=virtio "
// 	qemuCmd += " -net tap,script=no,ifname=" + execData.Tap
// 	qemuCmd += " -kernel " + execData.BinaryPath
// 	qemuCmd += " -append \"netdev.ipv4_addr=" + execData.IPAddress + "netdev.ipv4_gw_addr=" + execData.Gateway + " netdev.ipv4_subnet_mask=255.255.255.255 --"

// 	// qemu-system-x86_64 \
// 	//     -cpu host \
// 	//     -enable-kvm \
// 	//     -m 128 \
// 	//     -nodefaults -no-acpi \
// 	//     -display none -serial stdio \
// 	//     -device isa-debug-exit \
// 	//     -net nic,model=virtio \
// 	//     -net tap,script=no,ifname=tap106 \
// 	//     -kernel /app-helloworld_kvm-x86_64 \
// 	//     -append "netdev.ipv4_addr=$IP netdev.ipv4_gw_addr=169.254.1.1 netdev.ipv4_subnet_mask=255.255.255.255 --"
// 	return qemuCmd
// }

func CopyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		if e := out.Close(); e != nil {
			err = e
		}
	}()

	_, err = io.Copy(out, in)
	if err != nil {
		return
	}

	err = out.Sync()
	if err != nil {
		return
	}

	si, err := os.Stat(src)
	if err != nil {
		return
	}
	err = os.Chmod(dst, si.Mode())
	if err != nil {
		return
	}

	return
}

// CopyDir recursively copies a directory tree, attempting to preserve permissions.
// Source directory must exist, destination directory must *not* exist.
// Symlinks are ignored and skipped.
func CopyDir(src string, dst string) (err error) {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !si.IsDir() {
		return fmt.Errorf("source is not a directory")
	}

	_, err = os.Stat(dst)
	if err != nil && !os.IsNotExist(err) {
		return
	}
	if err == nil {
		return fmt.Errorf("destination already exists")
	}

	err = os.MkdirAll(dst, si.Mode())
	if err != nil {
		return
	}

	entries, err := ioutil.ReadDir(src)
	if err != nil {
		return
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			err = CopyDir(srcPath, dstPath)
			if err != nil {
				return
			}
		} else {
			// Skip symlinks.
			if entry.Mode()&os.ModeSymlink != 0 {
				continue
			}

			err = CopyFile(srcPath, dstPath)
			if err != nil {
				return
			}
		}
	}

	return
}
