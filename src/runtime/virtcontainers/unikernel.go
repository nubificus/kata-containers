//go:build linux
// +build linux

// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	//"net"
	//"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	hv "github.com/kata-containers/kata-containers/src/runtime/pkg/hypervisors"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils/katatrace"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/device/config"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/fs"
	//"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/unikernel/client"
	models "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/firecracker/client/models"
	//ops "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/unikernel/client/operations"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/utils"

	"github.com/blang/semver"
	"github.com/containerd/console"
	"github.com/containerd/fifo"
	//httptransport "github.com/go-openapi/runtime/client"
	//"github.com/go-openapi/strfmt"
	"github.com/opencontainers/selinux/go-selinux/label"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// ukTracingTags defines tags for the trace span
var ukTracingTags = map[string]string{
	"source":    "runtime",
	"package":   "virtcontainers",
	"subsystem": "hypervisor",
	"type":      "unikernel",
}

type ukvmmState uint8

const (
	uknotReady ukvmmState = iota
	ukcfReady
	ukvmReady
)

const (
	//ukTimeout is the maximum amount of time in seconds to wait for the VMM to respond
	ukTimeout = 10
	ukSocket  = "unikernel.socket"
	//Name of the files within jailer root
	//Having predefined names helps with Cleanup
	ukKernel             = "vmlinux"
	ukRootfs             = "rootfs"
	ukStopSandboxTimeout = 15
	// This indicates the number of block devices that can be attached to the
	// unikernel guest VM.
	// We attach a pool of placeholder drives before the guest has started, and then
	// patch the replace placeholder drives with drives with actual contents.
	ukDiskPoolSize           = 8
	ukdefaultHybridVSocketName = "kata.hvsock"

	// This is the first usable vsock context ID. All the vsocks can use the same
	// ID, since it's only used in the guest.
	ukdefaultGuestVSockCID = int64(0x3)

	// This is related to unikernel logging scheme
	ukLogFifo     = "logs.fifo"
	ukMetricsFifo = "metrics.fifo"

	ukdefaultFcConfig = "ukConfig.json"
)

// Specify the minimum version of unikernel supported
var ukMinSupportedVersion = semver.MustParse("0.21.1")

var ukKernelParams = append(commonVirtioblkKernelRootParams, []Param{
	// The boot source is the first partition of the first block device added
	{"pci", "off"},
	{"reboot", "k"},
	{"panic", "1"},
	{"iommu", "off"},
	{"net.ifnames", "0"},
	{"random.trust_cpu", "on"},

	// Unikernel doesn't support ACPI
	// Fix kernel error "ACPI BIOS Error (bug)"
	{"acpi", "off"},
}...)

func (s ukvmmState) String() string {
	switch s {
	case uknotReady:
		return "UK not ready"
	case ukcfReady:
		return "UK configure ready"
	case ukvmReady:
		return "UK VM ready"
	}

	return ""
}

// UnikernelInfo contains information related to the hypervisor that we
// want to store on disk
type UnikernelInfo struct {
	Version string
	PID     int
}

type unikernelState struct {
	sync.RWMutex
	state ukvmmState
}

func (s *unikernelState) set(state ukvmmState) {
	s.Lock()
	defer s.Unlock()

	s.state = state
}

// unikernel is an Hypervisor interface implementation for the unikernel VMM.
type unikernel struct {
	console console.Console
	ctx     context.Context

	pendingDevices []unikernelDevice // Devices to be added before the FC VM ready

	unikerneld *exec.Cmd           //Tracks the unikernel process itself
	ukConfig     *types.FcConfig     // Parameters configured before VM starts
	//connection   *client.Unikernel //Tracks the current active connection

	id               string //Unique ID per pod. Normally maps to the sandbox id
	vmPath           string //All jailed VM assets need to be under this
	chrootBaseDir    string //chroot base for the jailer
	jailerRoot       string
	socketPath       string
	hybridSocketPath string
	netNSPath        string
	uid              string //UID and GID to be used for the VMM
	gid              string
	ukConfigPath     string

	info   UnikernelInfo
	config HypervisorConfig
	state  unikernelState

	jailed bool //Set to true if jailer is enabled
}

type unikernelDevice struct {
	dev     interface{}
	devType DeviceType
}

// Logger returns a logrus logger appropriate for logging unikernel  messages
func (uk *unikernel) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "unikernel")
}

//At some cases, when sandbox id is too long, it will incur error of overlong
//unikernel API unix socket(uk.socketPath).
//In Linux, sun_path could maximumly contains 108 bytes in size.
//(http://man7.org/linux/man-pages/man7/unix.7.html)
func (uk *unikernel) truncateID(id string) string {
	if len(id) > 32 {
		//truncate the id to only leave the size of UUID(128bit).
		return id[:32]
	}

	return id
}

func (uk *unikernel) setConfig(config *HypervisorConfig) error {
	err := config.Valid()
	if err != nil {
		return err
	}

	uk.config = *config

	return nil
}

// CreateVM For unikernel this call only sets the internal structure up.
// The sandbox will be created and started through startSandbox().
func (uk *unikernel) CreateVM(ctx context.Context, id string, network Network, hypervisorConfig *HypervisorConfig) error {
	uk.ctx = ctx

	span, _ := katatrace.Trace(ctx, uk.Logger(), "CreateVM", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	//TODO: Check validity of the hypervisor config provided
	//https://github.com/kata-containers/runtime/issues/1065
	uk.id = uk.truncateID(id)
	uk.state.set(uknotReady)

	if err := uk.setConfig(hypervisorConfig); err != nil {
		return err
	}

	uk.setPaths(&uk.config)

	// So we need to repopulate this at StartVM where it is valid
	uk.netNSPath = network.NetworkID()

	// Till we create lower privileged kata user run as root
	// https://github.com/kata-containers/runtime/issues/1869
	uk.uid = "0"
	uk.gid = "0"

	uk.ukConfig = &types.FcConfig{}
	uk.ukConfigPath = filepath.Join(uk.vmPath, ukdefaultFcConfig)
	return nil
}

func (uk *unikernel) setPaths(hypervisorConfig *HypervisorConfig) {
	// When running with jailer all resources need to be under
	// a specific location and that location needs to have
	// exec permission (i.e. should not be mounted noexec, e.g. /run, /var/run)
	// Also unix domain socket names have a hard limit
	// #define UNIX_PATH_MAX   108
	// Keep it short and live within the jailer expected paths
	// <chroot_base>/<exec_file_name>/<id>/
	// Also jailer based on the id implicitly sets up cgroups under
	// <cgroups_base>/<exec_file_name>/<id>/
	hypervisorName := filepath.Base(hypervisorConfig.HypervisorPath)
	//fs.RunStoragePath cannot be used as we need exec perms
	uk.chrootBaseDir = filepath.Join("/run", fs.StoragePathSuffix)

	uk.vmPath = filepath.Join(uk.chrootBaseDir, hypervisorName, uk.id)
	uk.jailerRoot = filepath.Join(uk.vmPath, "root") // auto created by jailer

	// Unikernel and jailer automatically creates default API socket under /run
	// with the name of "unikernel.socket"
	uk.socketPath = filepath.Join(uk.jailerRoot, "run", ukSocket)

	uk.hybridSocketPath = filepath.Join(uk.jailerRoot, ukdefaultHybridVSocketName)
}

/*func (uk *unikernel) newFireClient(ctx context.Context) *client.Unikernel {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "newFireClient", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()
	httpClient := client.NewHTTPClient(strfmt.NewFormats())

	socketTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, path string) (net.Conn, error) {
			addr, err := net.ResolveUnixAddr("unix", uk.socketPath)
			if err != nil {
				return nil, err
			}

			return net.DialUnix("unix", nil, addr)
		},
	}

	transport := httptransport.New(client.DefaultHost, client.DefaultBasePath, client.DefaultSchemes)
	transport.SetLogger(uk.Logger())
	transport.SetDebug(uk.Logger().Logger.Level == logrus.DebugLevel)
	transport.Transport = socketTransport
	httpClient.SetTransport(transport)

	return httpClient
} 

func (uk *unikernel) vmRunning(ctx context.Context) bool {
	resp, err := uk.client(ctx).Operations.DescribeInstance(nil)
	if err != nil {
		uk.Logger().WithError(err).Error("getting vm status failed")
		return false
	}
	// The current state of the Unikernel instance (swagger:model InstanceInfo)
	return resp.Payload.Started
}*/

func (uk *unikernel) getVersionNumber() (string, error) {
	args := []string{"--version"}
	checkCMD := exec.Command(uk.config.HypervisorPath, args...)

	data, err := checkCMD.Output()
	if err != nil {
		return "", fmt.Errorf("Running checking FC version command failed: %v", err)
	}

	return uk.parseVersion(string(data))
}

func (uk *unikernel) parseVersion(data string) (string, error) {
	// Unikernel versions 0.25 and over contains multiline output on "version" command.
	// So we have to Check it and use first line of output to parse version.
	lines := strings.Split(data, "\n")

	var version string
	fields := strings.Split(lines[0], " ")
	if len(fields) > 1 {
		// The output format of `Unikernel --version` is as follows
		// Unikernel v0.23.1
		version = strings.TrimPrefix(strings.TrimSpace(fields[1]), "v")
		return version, nil
	}

	return "", errors.New("getting FC version failed, the output is malformed")
}

func (uk *unikernel) checkVersion(version string) error {
	v, err := semver.Make(version)
	if err != nil {
		return fmt.Errorf("Malformed unikernel version: %v", err)
	}

	if v.LT(ukMinSupportedVersion) {
		return fmt.Errorf("version %v is not supported. Minimum supported version of unikernel is %v", v.String(), ukMinSupportedVersion.String())
	}

	return nil
}

// waitVMMRunning will wait for timeout seconds for the VMM to be up and running.
func (uk *unikernel) waitVMMRunning(ctx context.Context, timeout int) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "wait VMM to be running", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	if timeout < 0 {
		return fmt.Errorf("Invalid timeout %ds", timeout)
	}

	timeStart := time.Now()
	for {
		//if uk.vmRunning(ctx) {
			return nil
		//}

		if int(time.Since(timeStart).Seconds()) > timeout {
			return fmt.Errorf("Failed to connect to unikernelinstance (timeout %ds)", timeout)
		}

		time.Sleep(time.Duration(10) * time.Millisecond)
	}
}

func (uk *unikernel) ukInit(ctx context.Context, timeout int) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukInit", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	var err error
	//FC version set and Check
	if uk.info.Version, err = uk.getVersionNumber(); err != nil {
		return err
	}

	//if err := uk.checkVersion(uk.info.Version); err != nil {
		//return err
	//}

	var cmd *exec.Cmd
	var args []string

	if uk.ukConfigPath, err = uk.ukJailResource(uk.ukConfigPath, ukdefaultFcConfig); err != nil {
		return err
	}

	//https://github.com/unikernel-microvm/unikernel/blob/master/docs/jailer.md#jailer-usage
	//--seccomp-level specifies whether seccomp filters should be installed and how restrictive they should be. Possible values are:
	//0 : disabled.
	//1 : basic filtering. This prohibits syscalls not whitelisted by Unikernel.
	//2 (default): advanced filtering. This adds further checks on some of the parameters of the allowed syscalls.
	if uk.jailed {
		jailedArgs := []string{
			"--id", uk.id,
			"--node", "0", //FIXME: Comprehend NUMA topology or explicit ignore
			"--exec-file", uk.config.HypervisorPath,
			"--uid", "0", //https://github.com/kata-containers/runtime/issues/1869
			"--gid", "0",
			"--chroot-base-dir", uk.chrootBaseDir,
			"--daemonize",
		}
		args = append(args, jailedArgs...)
		if uk.netNSPath != "" {
			args = append(args, "--netns", uk.netNSPath)
		}
		args = append(args, "--", "--config-file", uk.ukConfigPath)

		cmd = exec.Command(uk.config.JailerPath, args...)
	} else {
		args = append(args,
			"--api-sock", uk.socketPath,
			"--config-file", uk.ukConfigPath)
		cmd = exec.Command(uk.config.HypervisorPath, args...)
	}

	if uk.config.Debug {
		cmd.Stderr = uk.console
		cmd.Stdout = uk.console
	}

	uk.Logger().WithField("hypervisor args", args).Debug()
	uk.Logger().WithField("hypervisor cmd", cmd).Debug()

	uk.Logger().Info("Starting VM")
	if err := cmd.Start(); err != nil {
		uk.Logger().WithField("Error starting unikernel", err).Debug()
		return err
	}

	uk.info.PID = cmd.Process.Pid
	uk.unikerneld = cmd
	//uk.connection = uk.newFireClient(ctx)

	if err := uk.waitVMMRunning(ctx, timeout); err != nil {
		uk.Logger().WithField("ukInit failed:", err).Debug()
		return err
	}
	return nil
}

func (uk *unikernel) ukEnd(ctx context.Context, waitOnly bool) (err error) {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukEnd", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	uk.Logger().Info("Stopping unikernel VM")

	defer func() {
		if err != nil {
			uk.Logger().Info("ukEnd failed")
		} else {
			uk.Logger().Info("Unikernel VM stopped")
		}
	}()

	pid := uk.info.PID

	shutdownSignal := syscall.SIGTERM

	if waitOnly {
		// NOP
		shutdownSignal = syscall.Signal(0)
	}

	// Wait for the VM process to terminate
	return utils.WaitLocalProcess(pid, ukStopSandboxTimeout, shutdownSignal, uk.Logger())
}

/*
func (uk *unikernel) client(ctx context.Context) *client.Unikernel {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "client", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	if uk.connection == nil {
		uk.connection = uk.newFireClient(ctx)
	}

	return uk.connection
} */

func (uk *unikernel) createJailedDrive(name string) (string, error) {
	// Don't bind mount the resource, just create a raw file
	// that can be bind-mounted later
	r := filepath.Join(uk.jailerRoot, name)
	f, err := os.Create(r)
	if err != nil {
		return "", err
	}
	f.Close()

	if uk.jailed {
		// use path relative to the jail
		r = filepath.Join("/", name)
	}

	return r, nil
}

// when running with jailer, unikernel binary will firstly be copied into uk.jailerRoot,
// and then being executed there. Therefore we need to ensure uk.JailerRoot has exec permissions.
func (uk *unikernel) ukRemountJailerRootWithExec() error {
	if err := bindMount(context.Background(), uk.jailerRoot, uk.jailerRoot, false, "shared"); err != nil {
		uk.Logger().WithField("JailerRoot", uk.jailerRoot).Errorf("bindMount failed: %v", err)
		return err
	}

	// /run is normally mounted with rw, nosuid(MS_NOSUID), relatime(MS_RELATIME), noexec(MS_NOEXEC).
	// we re-mount jailerRoot to deliberately leave out MS_NOEXEC.
	if err := remount(context.Background(), syscall.MS_NOSUID|syscall.MS_RELATIME, uk.jailerRoot); err != nil {
		uk.Logger().WithField("JailerRoot", uk.jailerRoot).Errorf("Re-mount failed: %v", err)
		return err
	}

	return nil
}

func (uk *unikernel) ukJailResource(src, dst string) (string, error) {
	if src == "" || dst == "" {
		return "", fmt.Errorf("ukJailResource: invalid jail locations: src:%v, dst:%v",
			src, dst)
	}
	jailedLocation := filepath.Join(uk.jailerRoot, dst)
	if err := bindMount(context.Background(), src, jailedLocation, false, "slave"); err != nil {
		uk.Logger().WithField("bindMount failed", err).Error()
		return "", err
	}

	if !uk.jailed {
		return jailedLocation, nil
	}

	// This is the path within the jailed root
	absPath := filepath.Join("/", dst)
	return absPath, nil
}

func (uk *unikernel) ukSetBootSource(ctx context.Context, path, params string) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukSetBootSource", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()
	uk.Logger().WithFields(logrus.Fields{"kernel-path": path,
		"kernel-params": params}).Debug("ukSetBootSource")

	kernelPath, err := uk.ukJailResource(path, ukKernel)
	if err != nil {
		return err
	}

	src := &models.BootSource{
		KernelImagePath: &kernelPath,
		BootArgs:        params,
	}

	uk.ukConfig.BootSource = src

	return nil
}

func (uk *unikernel) ukSetVMRootfs(ctx context.Context, path string) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukSetVMRootfs", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	jailedRootfs, err := uk.ukJailResource(path, ukRootfs)
	if err != nil {
		return err
	}

	driveID := "rootfs"
	isReadOnly := true
	//Add it as a regular block device
	//This allows us to use a partitoned root block device
	isRootDevice := false
	// This is the path within the jailed root
	drive := &models.Drive{
		DriveID:      &driveID,
		IsReadOnly:   &isReadOnly,
		IsRootDevice: &isRootDevice,
		PathOnHost:   &jailedRootfs,
	}

	uk.ukConfig.Drives = append(uk.ukConfig.Drives, drive)

	return nil
}

func (uk *unikernel) ukSetVMBaseConfig(ctx context.Context, mem int64, vcpus int64, htEnabled bool) {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukSetVMBaseConfig", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()
	uk.Logger().WithFields(logrus.Fields{"mem": mem,
		"vcpus":     vcpus,
		"htEnabled": htEnabled}).Debug("ukSetVMBaseConfig")

	cfg := &models.MachineConfiguration{
		HtEnabled:  &htEnabled,
		MemSizeMib: &mem,
		VcpuCount:  &vcpus,
	}

	uk.ukConfig.MachineConfig = cfg
}

func (uk *unikernel) ukSetLogger(ctx context.Context) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukSetLogger", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	ukLogLevel := "Error"
	if uk.config.Debug {
		ukLogLevel = "Debug"
	}

	// listen to log fifo file and transfer error info
	jailedLogFifo, err := uk.ukListenToFifo(ukLogFifo, nil)
	if err != nil {
		return fmt.Errorf("Failed setting log: %s", err)
	}

	uk.ukConfig.Logger = &models.Logger{
		Level:   &ukLogLevel,
		LogPath: &jailedLogFifo,
	}

	return err
}

func (uk *unikernel) ukSetMetrics(ctx context.Context) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukSetMetrics", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	// listen to metrics file and transfer error info
	jailedMetricsFifo, err := uk.ukListenToFifo(ukMetricsFifo, nil)//uk.updateMetrics)
	if err != nil {
		return fmt.Errorf("Failed setting log: %s", err)
	}

	uk.ukConfig.Metrics = &models.Metrics{
		MetricsPath: &jailedMetricsFifo,
	}

	return err
	//return nil
}

/*func (uk *unikernel) updateMetrics(line string) {
	var fm UnikernelMetrics
	if err := json.Unmarshal([]byte(line), &fm); err != nil {
		uk.Logger().WithError(err).WithField("data", line).Error("failed to unmarshal uk metrics")
		return
	}
	updateUnikernelMetrics(&fm)
}*/

type ukfifoConsumer func(string)

func (uk *unikernel) ukListenToFifo(fifoName string, consumer ukfifoConsumer) (string, error) {
	ukFifoPath := filepath.Join(uk.vmPath, fifoName)
	ukFifo, err := fifo.OpenFifo(context.Background(), ukFifoPath, syscall.O_CREAT|syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("Failed to open/create fifo file %s", err)
	}

	jailedFifoPath, err := uk.ukJailResource(ukFifoPath, fifoName)
	if err != nil {
		return "", err
	}

	go func() {
		scanner := bufio.NewScanner(ukFifo)
		for scanner.Scan() {
			if consumer != nil {
				consumer(scanner.Text())
			} else {
				uk.Logger().WithFields(logrus.Fields{
					"fifoName": fifoName,
					"contents": scanner.Text()}).Debug("read unikernel fifo")
			}
		}

		if err := scanner.Err(); err != nil {
			uk.Logger().WithError(err).Errorf("Failed reading unikernel fifo file")
		}

		if err := ukFifo.Close(); err != nil {
			uk.Logger().WithError(err).Errorf("Failed closing unikernel fifo file")
		}
	}()

	return jailedFifoPath, nil
}

func (uk *unikernel) ukInitConfiguration(ctx context.Context) error {
	// Unikernel API socket(unikernel.socket) is automatically created
	// under /run dir.
	err := os.MkdirAll(filepath.Join(uk.jailerRoot, "run"), DirMode)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if err := os.RemoveAll(uk.vmPath); err != nil {
				uk.Logger().WithError(err).Error("Fail to clean up vm directory")
			}
		}
	}()

	if uk.config.JailerPath != "" {
		uk.jailed = true
		if err := uk.ukRemountJailerRootWithExec(); err != nil {
			return err
		}
	}

	uk.ukSetVMBaseConfig(ctx, int64(uk.config.MemorySize),
		int64(uk.config.NumVCPUs), false)

	kernelPath, err := uk.config.KernelAssetPath()
	if err != nil {
		return err
	}

	if uk.config.Debug {
		ukKernelParams = append(ukKernelParams, Param{"console", "ttyS0"})
	} else {
		ukKernelParams = append(ukKernelParams, []Param{
			{"8250.nr_uarts", "0"},
			// Tell agent where to send the logs
			{"agent.log_vport", fmt.Sprintf("%d", vSockLogsPort)},
		}...)
	}

	kernelParams := append(uk.config.KernelParams, ukKernelParams...)
	strParams := SerializeParams(kernelParams, "=")
	formattedParams := strings.Join(strParams, " ")
	if err := uk.ukSetBootSource(ctx, kernelPath, formattedParams); err != nil {
		return err
	}

	image, err := uk.config.InitrdAssetPath()
	if err != nil {
		return err
	}

	if image == "" {
		image, err = uk.config.ImageAssetPath()
		if err != nil {
			return err
		}
	}

	if err := uk.ukSetVMRootfs(ctx, image); err != nil {
		return err
	}

	if err := uk.createDiskPool(ctx); err != nil {
		return err
	}

	if err := uk.ukSetLogger(ctx); err != nil {
		return err
	}

	if err := uk.ukSetMetrics(ctx); err != nil {
		return err
	}

	uk.state.set(ukcfReady)
	for _, d := range uk.pendingDevices {
		if err := uk.AddDevice(ctx, d.dev, d.devType); err != nil {
			return err
		}
	}

	// register unikernel specificed metrics
	//registerUnikernelMetrics()

	return nil
}

// startSandbox will start the hypervisor for the given sandbox.
// In the context of unikernel, this will start the hypervisor,
// for configuration, but not yet start the actual virtual machine
func (uk *unikernel) StartVM(ctx context.Context, timeout int) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "StartVM", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	if err := uk.ukInitConfiguration(ctx); err != nil {
		return err
	}

	data, errJSON := json.MarshalIndent(uk.ukConfig, "", "\t")
	if errJSON != nil {
		return errJSON
	}

	if err := os.WriteFile(uk.ukConfigPath, data, 0640); err != nil {
		return err
	}

	var err error
	defer func() {
		if err != nil {
			uk.ukEnd(ctx, false)
		}
	}()

	// This needs to be done as late as possible, since all processes that
	// are executed by kata-runtime after this call, run with the SELinux
	// label. If these processes require privileged, we do not want to run
	// them under confinement.
	if !uk.config.DisableSeLinux {

		if err := label.SetProcessLabel(uk.config.SELinuxProcessLabel); err != nil {
			return err
		}
		defer label.SetProcessLabel("")
	}

	err = uk.ukInit(ctx, ukTimeout)
	if err != nil {
		return err
	}

	// make sure 'others' don't have access to this socket
	//err = os.Chmod(uk.hybridSocketPath, 0640)
	//if err != nil {
		//return fmt.Errorf("Could not change socket permissions: %v", err)
	//}

	uk.state.set(ukvmReady)
	return nil
}

func ukDriveIndexToID(i int) string {
	return "drive_" + strconv.Itoa(i)
}

func (uk *unikernel) createDiskPool(ctx context.Context) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "createDiskPool", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	for i := 0; i < ukDiskPoolSize; i++ {
		driveID := ukDriveIndexToID(i)
		isReadOnly := false
		isRootDevice := false

		// Create a temporary file as a placeholder backend for the drive
		jailedDrive, err := uk.createJailedDrive(driveID)
		if err != nil {
			return err
		}

		drive := &models.Drive{
			DriveID:      &driveID,
			IsReadOnly:   &isReadOnly,
			IsRootDevice: &isRootDevice,
			PathOnHost:   &jailedDrive,
		}

		uk.ukConfig.Drives = append(uk.ukConfig.Drives, drive)
	}

	return nil
}

func (uk *unikernel) umountResource(jailedPath string) {
	hostPath := filepath.Join(uk.jailerRoot, jailedPath)
	uk.Logger().WithField("resource", hostPath).Debug("Unmounting resource")
	err := syscall.Unmount(hostPath, syscall.MNT_DETACH)
	if err != nil {
		uk.Logger().WithError(err).Error("Failed to umount resource")
	}
}

// cleanup all jail artifacts
func (uk *unikernel) cleanupJail(ctx context.Context) {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "cleanupJail", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	uk.umountResource(ukKernel)
	uk.umountResource(ukRootfs)
	uk.umountResource(ukLogFifo)
	uk.umountResource(ukMetricsFifo)
	uk.umountResource(ukdefaultFcConfig)
	// if running with jailer, we also need to umount uk.jailerRoot
	if uk.config.JailerPath != "" {
		if err := syscall.Unmount(uk.jailerRoot, syscall.MNT_DETACH); err != nil {
			uk.Logger().WithField("JailerRoot", uk.jailerRoot).WithError(err).Error("Failed to umount")
		}
	}

	uk.Logger().WithField("cleaningJail", uk.vmPath).Info()
	if err := os.RemoveAll(uk.vmPath); err != nil {
		uk.Logger().WithField("cleanupJail failed", err).Error()
	}
}

// stopSandbox will stop the Sandbox's VM.
func (uk *unikernel) StopVM(ctx context.Context, waitOnly bool) (err error) {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "StopVM", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	return uk.ukEnd(ctx, waitOnly)
}

func (uk *unikernel) PauseVM(ctx context.Context) error {
	return nil
}

func (uk *unikernel) SaveVM() error {
	return nil
}

func (uk *unikernel) ResumeVM(ctx context.Context) error {
	return nil
}

func (uk *unikernel) ukAddVsock(ctx context.Context, hvs types.HybridVSock) {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukAddVsock", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	udsPath := hvs.UdsPath
	if uk.jailed {
		udsPath = filepath.Join("/", ukdefaultHybridVSocketName)
	}

	vsockID := "root"
	ctxID := ukdefaultGuestVSockCID
	vsock := &models.Vsock{
		GuestCid: &ctxID,
		UdsPath:  &udsPath,
		VsockID:  &vsockID,
	}

	uk.ukConfig.Vsock = vsock
}

func (uk *unikernel) ukAddNetDevice(ctx context.Context, endpoint Endpoint) {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukAddNetDevice", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	ifaceID := endpoint.Name()

	// The implementation of rate limiter is based on TBF.
	// Rate Limiter defines a token bucket with a maximum capacity (size) to store tokens, and an interval for refilling purposes (refill_time).
	// The refill-rate is derived from size and refill_time, and it is the constant rate at which the tokens replenish.
	refillTime := uint64(utils.DefaultRateLimiterRefillTimeMilliSecs)
	var rxRateLimiter models.RateLimiter
	rxSize := uk.config.RxRateLimiterMaxRate
	if rxSize > 0 {
		uk.Logger().Info("Add rx rate limiter")

		// kata-defined rxSize is in bits with scaling factors of 1000, but unikernel-defined
		// rxSize is in bytes with scaling factors of 1024, need reversion.
		rxSize = utils.RevertBytes(rxSize / 8)
		rxTokenBucket := models.TokenBucket{
			RefillTime: &refillTime,
			Size:       &rxSize,
		}
		rxRateLimiter = models.RateLimiter{
			Bandwidth: &rxTokenBucket,
		}
	}

	var txRateLimiter models.RateLimiter
	txSize := uk.config.TxRateLimiterMaxRate
	if txSize > 0 {
		uk.Logger().Info("Add tx rate limiter")

		// kata-defined txSize is in bits with scaling factors of 1000, but unikernel-defined
		// txSize is in bytes with scaling factors of 1024, need reversion.
		txSize = utils.RevertBytes(txSize / 8)
		txTokenBucket := models.TokenBucket{
			RefillTime: &refillTime,
			Size:       &txSize,
		}
		txRateLimiter = models.RateLimiter{
			Bandwidth: &txTokenBucket,
		}
	}

	ifaceCfg := &models.NetworkInterface{
		AllowMmdsRequests: false,
		GuestMac:          endpoint.HardwareAddr(),
		IfaceID:           &ifaceID,
		HostDevName:       &endpoint.NetworkPair().TapInterface.TAPIface.Name,
		RxRateLimiter:     &rxRateLimiter,
		TxRateLimiter:     &txRateLimiter,
	}

	uk.ukConfig.NetworkInterfaces = append(uk.ukConfig.NetworkInterfaces, ifaceCfg)
}

func (uk *unikernel) ukAddBlockDrive(ctx context.Context, drive config.BlockDrive) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "ukAddBlockDrive", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	driveID := drive.ID
	isReadOnly := false
	isRootDevice := false

	jailedDrive, err := uk.ukJailResource(drive.File, driveID)
	if err != nil {
		uk.Logger().WithField("ukAddBlockDrive failed", err).Error()
		return err
	}
	driveFc := &models.Drive{
		DriveID:      &driveID,
		IsReadOnly:   &isReadOnly,
		IsRootDevice: &isRootDevice,
		PathOnHost:   &jailedDrive,
	}

	uk.ukConfig.Drives = append(uk.ukConfig.Drives, driveFc)

	return nil
}
// addDevice will add extra devices to unikernel.  Limited to configure before the
// virtual machine starts.  Devices include drivers and network interfaces only.
func (uk *unikernel) AddDevice(ctx context.Context, devInfo interface{}, devType DeviceType) error {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "AddDevice", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	uk.state.RLock()
	defer uk.state.RUnlock()

	if uk.state.state == uknotReady {
		dev := unikernelDevice{
			dev:     devInfo,
			devType: devType,
		}
		uk.Logger().Info("FC not ready, queueing device")
		uk.pendingDevices = append(uk.pendingDevices, dev)
		return nil
	}

	var err error
	switch v := devInfo.(type) {
	case Endpoint:
		uk.Logger().WithField("device-type-endpoint", devInfo).Info("Adding device")
		uk.ukAddNetDevice(ctx, v)
	case config.BlockDrive:
		uk.Logger().WithField("device-type-blockdrive", devInfo).Info("Adding device")
		err = uk.ukAddBlockDrive(ctx, v)
	case types.HybridVSock:
		uk.Logger().WithField("device-type-hybrid-vsock", devInfo).Info("Adding device")
		uk.ukAddVsock(ctx, v)
	default:
		uk.Logger().WithField("unknown-device-type", devInfo).Error("Adding device")
	}

	return err
}

// Firecracker supports replacing the host drive used once the VM has booted up
func (uk *firecracker) ukUpdateBlockDrive(ctx context.Context, path, id string) error {
	//span, _ := katatrace.Trace(ctx, uk.Logger(), "ukUpdateBlockDrive", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	//defer span.End()

	// Use the global block index as an index into the pool of the devices
	// created for firecracker.
	//driveParams := ops.NewPatchGuestDriveByIDParams()
	//driveParams.SetDriveID(id)

	uk.Logger().WithField("hypervisor args", path).Debug()
	uk.Logger().WithField("hypervisor args",  id).Debug()
	/*driveFc := &models.PartialDrive{
		DriveID:    &id,
		PathOnHost: &path, //This is the only property that can be modified
	}*/

	//driveParams.SetBody(driveFc)
	//if _, err := uk.client(ctx).Operations.PatchGuestDriveByID(driveParams); err != nil {
		//return err
	//}

	return nil
}




// hotplugBlockDevice supported in Unikernel VMM
// hot add or remove a block device.
func (uk *unikernel) hotplugBlockDevice(ctx context.Context, drive config.BlockDrive, op Operation) (interface{}, error) {
	if drive.Swap {
		return nil, fmt.Errorf("unikernel doesn't support swap")
	}

	var path string
	var err error
	driveID := ukDriveIndexToID(drive.Index)

	if op == AddDevice {
		//The drive placeholder has to exist prior to Update
		path, err = uk.ukJailResource(drive.File, driveID)
		if err != nil {
			uk.Logger().WithError(err).WithField("resource", drive.File).Error("Could not jail resource")
			return nil, err
		}
	} else {
		// umount the disk, it's no longer needed.
		uk.umountResource(driveID)
		// use previous raw file created at createDiskPool, that way
		// the resource is released by unikernel and it can be destroyed in the host
		if uk.jailed {
			// use path relative to the jail
			path = filepath.Join("/", driveID)
		} else {
			path = filepath.Join(uk.jailerRoot, driveID)
		}
	}
	uk.Logger().WithError(err).WithField("resource", path).Error("Could not jail resource")
	uk.Logger().WithError(err).WithField("resource", driveID).Error("Could not jail resource")

	//return nil, uk.ukUpdateBlockDrive(ctx, path, driveID)
	return nil, nil
}

// hotplugAddDevice supported in Unikernel VMM
func (uk *unikernel) HotplugAddDevice(ctx context.Context, devInfo interface{}, devType DeviceType) (interface{}, error) {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "HotplugAddDevice", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	switch devType {
	case BlockDev:
		return uk.hotplugBlockDevice(ctx, *devInfo.(*config.BlockDrive), AddDevice)
	default:
		uk.Logger().WithFields(logrus.Fields{"devInfo": devInfo,
			"deviceType": devType}).Warn("HotplugAddDevice: unsupported device")
		return nil, fmt.Errorf("Could not hot add device: unsupported device: %v, type: %v",
			devInfo, devType)
	}
}

// hotplugRemoveDevice supported in Unikernel VMM
func (uk *unikernel) HotplugRemoveDevice(ctx context.Context, devInfo interface{}, devType DeviceType) (interface{}, error) {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "HotplugRemoveDevice", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()

	switch devType {
	case BlockDev:
		return uk.hotplugBlockDevice(ctx, *devInfo.(*config.BlockDrive), RemoveDevice)
	default:
		uk.Logger().WithFields(logrus.Fields{"devInfo": devInfo,
			"deviceType": devType}).Error("HotplugRemoveDevice: unsupported device")
		return nil, fmt.Errorf("Could not hot remove device: unsupported device: %v, type: %v",
			devInfo, devType)
	}
}

// getSandboxConsole builds the path of the console where we can read
// logs coming from the sandbox.
func (uk *unikernel) GetVMConsole(ctx context.Context, id string) (string, string, error) {
	master, slave, err := console.NewPty()
	if err != nil {
		uk.Logger().Debugf("Error create pseudo tty: %v", err)
		return consoleProtoPty, "", err
	}
	uk.console = master

	return consoleProtoPty, slave, nil
}

func (uk *unikernel) Disconnect(ctx context.Context) {
	uk.state.set(uknotReady)
}

// Adds all capabilities supported by unikernel implementation of hypervisor interface
func (uk *unikernel) Capabilities(ctx context.Context) types.Capabilities {
	span, _ := katatrace.Trace(ctx, uk.Logger(), "Capabilities", ukTracingTags, map[string]string{"sandbox_id": uk.id})
	defer span.End()
	var caps types.Capabilities
	caps.SetBlockDeviceHotplugSupport()

	return caps
}

func (uk *unikernel) HypervisorConfig() HypervisorConfig {
	return uk.config
}

func (uk *unikernel) ResizeMemory(ctx context.Context, reqMemMB uint32, memoryBlockSizeMB uint32, probe bool) (uint32, MemoryDevice, error) {
	return 0, MemoryDevice{}, nil
}

func (uk *unikernel) ResizeVCPUs(ctx context.Context, reqVCPUs uint32) (currentVCPUs uint32, newVCPUs uint32, err error) {
	return 0, 0, nil
}

// This is used to apply cgroup information on the host.
//
// As suggested by https://github.com/unikernel-microvm/unikernel/issues/718,
// let's use `ps -T -p <pid>` to get uk vcpu info.
func (uk *unikernel) GetThreadIDs(ctx context.Context) (VcpuThreadIDs, error) {
	var vcpuInfo VcpuThreadIDs

	vcpuInfo.vcpus = make(map[int]int)
	parent, err := utils.NewProc(uk.info.PID)
	if err != nil {
		return vcpuInfo, err
	}
	children, err := parent.Children()
	if err != nil {
		return vcpuInfo, err
	}
	for _, child := range children {
		comm, err := child.Comm()
		if err != nil {
			return vcpuInfo, errors.New("Invalid uk thread info")
		}
		if !strings.HasPrefix(comm, "uk_vcpu") {
			continue
		}
		cpus := strings.SplitAfter(comm, "uk_vcpu")
		if len(cpus) != 2 {
			return vcpuInfo, errors.Errorf("Invalid uk thread info: %v", comm)
		}

		//Remove the leading whitespace
		cpuIdStr := strings.TrimSpace(cpus[1])

		cpuID, err := strconv.ParseInt(cpuIdStr, 10, 32)
		if err != nil {
			return vcpuInfo, errors.Wrapf(err, "Invalid uk thread info: %v", comm)
		}
		vcpuInfo.vcpus[int(cpuID)] = child.PID
	}

	return vcpuInfo, nil
}

func (uk *unikernel) Cleanup(ctx context.Context) error {
	uk.cleanupJail(ctx)
	return nil
}

func (uk *unikernel) GetPids() []int {
	return []int{uk.info.PID}
}

func (uk *unikernel) GetVirtioFsPid() *int {
	return nil
}

func (uk *unikernel) fromGrpc(ctx context.Context, hypervisorConfig *HypervisorConfig, j []byte) error {
	return errors.New("unikernel is not supported by VM cache")
}

func (uk *unikernel) toGrpc(ctx context.Context) ([]byte, error) {
	return nil, errors.New("unikernel is not supported by VM cache")
}

func (uk *unikernel) Save() (s hv.HypervisorState) {
	s.Pid = uk.info.PID
	s.Type = string(UnikernelHypervisor)
	return
}

func (uk *unikernel) Load(s hv.HypervisorState) {
	uk.info.PID = s.Pid
}

func (uk *unikernel) Check() error {
	if err := syscall.Kill(uk.info.PID, syscall.Signal(0)); err != nil {
		return errors.Wrapf(err, "failed to ping uk process")
	}

	return nil
}

func (uk *unikernel) GenerateSocket(id string) (interface{}, error) {
	uk.Logger().Debug("Using hybrid-vsock endpoint")

	// Method is being run outside of the normal container workflow
	if uk.jailerRoot == "" {
		uk.id = id
		uk.setPaths(&uk.config)
	}

	return types.HybridVSock{
		UdsPath: uk.hybridSocketPath,
		Port:    uint32(vSockPort),
	}, nil
}

func (uk *unikernel) IsRateLimiterBuiltin() bool {
	return true
}
