package containerdshim

import (
	"context"
	"encoding/json"
	"io"
	"net"
	osexec "os/exec"
	"strings"
	"time"

	"github.com/containerd/containerd/api/types/task"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/sirupsen/logrus"
)

// {"cmdline":"redis-server","net":{"if":"ukvmif0","cloner":"True","type":"inet","method":"static","addr":"10.10.10.2","mask":"16"}}

type HvtArgsNetwork struct {
	If     string `json:"if"`
	Cloner string `json:"cloner"`
	Type   string `json:"type"`
	Method string `json:"method"`
	Addr   string `json:"addr"`
	Mask   string `json:"mask"`
	// Gw     string `json:"gw"`
}

type HvtArgsBlock struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Fstype string `json:"fstype"`
	Mount  string `json:"mountpoint"`
}

type HvtArgs struct {
	Cmdline string         `json:"cmdline"`
	Net     HvtArgsNetwork `json:"net"`
	Blk     *HvtArgsBlock  `json:"blk,omitempty"`
	Env     []string       `json:"env,omitempty"`
	Cwd     string         `json:"cwd,omitempty"`
	Mem     string         `json:"mem,omitempty"`
}

type Command struct {
	cmdString string
	container *container
	id        string
	stdin     string
	stdout    string
	stderr    string
	bundle    string
	exec      *osexec.Cmd
}

func CmdLine(execData virtcontainers.ExecData) string {

	// BinaryType string
	// BinaryPath string
	// IPAddress  string
	// Mask       string
	// Tap        string
	// Container  *Container
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "CmdLine"}
	shimLog.WithField("BinaryType", execData.BinaryType).WithFields(logF).Error("ExecData")
	shimLog.WithField("BinaryPath", execData.BinaryPath).WithFields(logF).Error("ExecData")
	shimLog.WithField("IPAddress", execData.IPAddress).WithFields(logF).Error("ExecData")
	shimLog.WithField("Mask", execData.Mask).WithFields(logF).Error("ExecData")
	shimLog.WithField("Tap", execData.Tap).WithFields(logF).Error("ExecData")
	shimLog.WithField("Container", execData.Container.ID()).WithFields(logF).Error("ExecData")

	switch execData.BinaryType {
	case "pause":
		return execData.BinaryPath
	case "hvt":
		return HvtCmd(execData)
	case "qemu":
		return QemuCmd(execData)
	case "binary":
		return execData.BinaryPath
	default:
		return ""
	}
}

func HvtCmd(execData virtcontainers.ExecData) string {
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "HvtCmd"}
	logrus.WithFields(logF).Error("")
	ifaces, _ := net.Interfaces()
	execData.Tap = ifaces[len(ifaces)-1].Name
	execData.Tap = "tap0_kata"
	nsParts := strings.Split(execData.NetNs, "/")
	ns := nsParts[len(nsParts)-1]
	logrus.WithFields(logF).WithField("NetNs1", execData.NetNs).Error("")
	logrus.WithFields(logF).WithField("NetNs2", ns).Error("")

	HvtMonitor := "/home/gntouts/bin/solo5-hvt"
	// ./tenders/hvt/solo5-hvt --net:service0=tap192  tests/test_net/test_net.hvt
	// return HvtMonitor + "--net:service0=" + execData.Tap + " " + execData.BinaryPath
	// /solo5-hvt --net=tap100 -- redis.hvt '{"cmdline":"redis-server","net":{"if":"ukvmif0","cloner":"True","type":"inet","method":"static","addr":"10.10.10.2","mask":"16"}}'

	hvtNet := HvtArgsNetwork{
		If:     "ukvmif0",
		Cloner: "True",
		Type:   "inet",
		Method: "static",
		Addr:   "10.10.10.2",
		Mask:   "16",
	}

	hvtArgs := HvtArgs{
		Cmdline: "redis-server",
		Net:     hvtNet,
	}
	b, _ := json.Marshal(hvtArgs)
	cmdString := ""
	if execData.BlkDevice != "" {
		cmdString = "ip netns exec " + ns + " " + HvtMonitor + " --net=" + execData.Tap + " --disk=" + execData.BlkDevice + " " + execData.BinaryPath + " " + string(b)
	} else {
		cmdString = "ip netns exec " + ns + " " + HvtMonitor + " --net=" + execData.Tap + " " + execData.BinaryPath + " " + string(b)
	}

	// stripped := strings.Replace(cmdString, "\\", "", -1)
	// unquoted := fmt.Sprintln(stripped)
	// unqoted, err := strconv.Unquote(stripped)
	// if err != nil {
	// 	logrus.WithFields(logF).WithField("err", err.Error()).Error("")
	// }
	logrus.WithFields(logF).WithField("cmd", cmdString).Error("")
	// cmdParts := strings.Split(stripped, " ")

	// name, args := cmdParts[0], cmdParts[1:]
	// output, _ := osexec.Command(name, args...).CombinedOutput()
	// logrus.WithFields(logF).WithField("out", string(output)).Error("")

	logrus.WithFields(logF).WithField("ifaces", len(ifaces)).Error("")
	for _, iface := range ifaces {
		logrus.WithFields(logF).WithField("name", iface.Name).Error("")
	}

	// output, _ := osexec.Command(name, args...).CombinedOutput()
	// logrus.WithFields(logF).WithField("out", string(output)).Error("")\
	// na doume kai to GW mhpws xreiazetai!

	return cmdString

}

func QemuCmd(execData virtcontainers.ExecData) string {
	qemuCmd := "qemu-system-x86_64 -cpu host"
	qemuCmd += " -enable-kvm"
	qemuCmd += " -m 128"
	qemuCmd += " -nodefaults -no-acpi "
	qemuCmd += " -display none -serial stdio "
	qemuCmd += " -device isa-debug-exit "
	qemuCmd += " -net nic,model=virtio "
	qemuCmd += " -net tap,script=no,ifname=" + execData.Tap
	qemuCmd += " -kernel " + execData.BinaryPath
	qemuCmd += " -append \"netdev.ipv4_addr=" + execData.IPAddress + "netdev.ipv4_gw_addr=" + execData.Gateway + " netdev.ipv4_subnet_mask=255.255.255.255 --"

	// qemu-system-x86_64 \
	//     -cpu host \
	//     -enable-kvm \
	//     -m 128 \
	//     -nodefaults -no-acpi \
	//     -display none -serial stdio \
	//     -device isa-debug-exit \
	//     -net nic,model=virtio \
	//     -net tap,script=no,ifname=tap106 \
	//     -kernel /app-helloworld_kvm-x86_64 \
	//     -append "netdev.ipv4_addr=$IP netdev.ipv4_gw_addr=169.254.1.1 netdev.ipv4_subnet_mask=255.255.255.255 --"
	return qemuCmd

}

func CreateCommand(execData virtcontainers.ExecData, container *container) *Command {
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "CreateCommand"}
	cmdString := CmdLine(execData)
	shimLog.WithField("BinaryType", execData.BinaryType).WithFields(logF).Error("exec info")
	shimLog.WithField("cmdString", cmdString).WithFields(logF).Error("exec info")

	args := strings.Split(cmdString, " ")
	var newCmd *osexec.Cmd
	if len(args) == 1 {
		shimLog.WithField("cmdString", args[0]).WithFields(logF).Error("exec info")
		newCmd = osexec.Command(args[0])
	} else {
		name, args := args[0], args[1:]
		newCmd = osexec.Command(name, args...)
	}
	return &Command{cmdString: cmdString, container: container, id: container.id, stdin: container.stdin, stdout: container.stdout, stderr: container.stderr, bundle: container.bundle, exec: newCmd}
}

func (c *Command) ioPipes() (io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
	stdin, err := c.exec.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	stdout, err := c.exec.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	stderr, err := c.exec.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	return stdin, stdout, stderr, nil
}

func (c *Command) SetIO(ctx context.Context) error {
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "SetIO"}
	shimLog.WithFields(logF).WithField("path", c.exec.Path).Error("stdout, stderr redirected")

	stdin, stdout, stderr, err := c.ioPipes()
	shimLog.WithFields(logF).Error("ioPipes retrieved")

	if err != nil {
		shimLog.WithFields(logF).WithField("err", err.Error()).Error("ioPipes retrieved")

		return err
	}

	c.container.stdinPipe = stdin
	shimLog.WithFields(logF).Error("container stdin redirected")

	if c.container.stdin != "" || c.container.stdout != "" || c.container.stderr != "" {
		tty, err := newTtyIO(ctx, c.stdin, c.stdout, c.stderr, c.container.terminal)
		if err != nil {
			return err
		}
		c.container.ttyio = tty
		shimLog.WithFields(logF).Error("container ttyio set")

		go ioCopy(shimLog.WithField("container", c.id), c.container.exitIOch, c.container.stdinCloser, tty, stdin, stdout, stderr)
	}
	return nil
}
func (c *Command) Start() error {
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "Start"}

	err := c.exec.Start()
	shimLog.WithFields(logF).WithField("path", c.exec.Path).Error("CMD STARTED")
	c.container.status = task.StatusRunning
	return err
}

func (c *Command) Wait() error {
	time.Sleep(500 * time.Millisecond)
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "Wait"}

	c.exec.Wait()
	shimLog.WithFields(logF).Error("exec returned")

	shimLog.WithFields(logF).Error("cmd completed")

	close(c.container.exitIOch)
	shimLog.WithFields(logF).Error("exitIOch closed")

	close(c.container.stdinCloser)
	shimLog.WithFields(logF).Error("stdinCloser closed")

	c.container.status = task.StatusStopped
	shimLog.WithFields(logF).Error("container.status: StatusStopped")
	return nil
}
