package containerdshim

import (
	"context"
	"io"
	osexec "os/exec"
	"strings"
	"time"

	"github.com/containerd/containerd/api/types/task"
	"github.com/sirupsen/logrus"
)

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

func CreateCommand(cmdString string, container *container) *Command {
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "CreateCommand"}
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
	newCmd.Dir = container.bundle
	return &Command{cmdString: cmdString, container: container, id: container.id, stdin: container.stdin, stdout: container.stdout, stderr: container.stderr, bundle: container.bundle, exec: newCmd}
}

func (c *Command) Run() {
	c.container.status = task.StatusRunning
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "Run"}
	shimLog.WithField("containerType", c.container.cType).WithFields(logF).Error("container info")
	cmdF := logrus.Fields{"id": c.id, "stdin": c.stdin, "stdout": c.stdout, "stderr": c.stderr}
	shimLog.WithFields(cmdF).WithFields(logF).Error("cmd info")
	osexec.Command(c.cmdString)
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

	//close(c.container.exitIOch)
	shimLog.WithFields(logF).Error("exitIOch closed")

	//close(c.container.stdinCloser)
	shimLog.WithFields(logF).Error("stdinCloser closed")

	c.container.status = task.StatusStopped
	shimLog.WithFields(logF).Error("container.status: StatusStopped")
	return nil
}

func (c *Command) WaitTest() error {
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "WaitTest"}
	shimLog.WithFields(logF).WithField("path", c.exec.Path).Error("running cmd")
	go func() {
		shimLog.WithFields(logF).Error("sleep ended")
		c.exec.Start()
	}()

	go func() {
		// [TODO] check if sleep is needed, remove if not
		time.Sleep(500 * time.Millisecond)

		c.exec.Wait()
		shimLog.WithFields(logF).Error("exec returned")

		shimLog.WithFields(logF).Error("cmd completed")

		// ananos' diff
		// close(c.container.exitIOch)
		// shimLog.WithFields(logF).Error("exitIOch closed")

		// ananos' diff
		// close(c.container.stdinCloser)
		// shimLog.WithFields(logF).Error("stdinCloser closed")

		c.container.status = task.StatusStopped
		shimLog.WithFields(logF).Error("container.status: StatusStopped")
	}()

	return nil
}

// c.status = task.StatusRunning
// 	shimLog.WithField("c.status", c.status).WithFields(logF).Error("cs/start.go/startContainer")

// 	stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, c.id)
// 	if err != nil {
// 		return err
// 	}

// 	c.stdinPipe = stdin

// 	if c.stdin != "" || c.stdout != "" || c.stderr != "" {
// 		tty, err := newTtyIO(ctx, c.stdin, c.stdout, c.stderr, c.terminal)
// 		if err != nil {
// 			return err
// 		}
// 		c.ttyio = tty

// 		go ioCopy(shimLog.WithField("container", c.id), c.exitIOch, c.stdinCloser, tty, stdin, stdout, stderr)

// type Ccontainer struct {
// 	s           *service
// 	ttyio       *ttyIO
// 	spec        *specs.Spec
// 	exitTime    time.Time
// 	execs       map[string]*exec
// 	exitIOch    chan struct{}
// 	stdinPipe   io.WriteCloser
// 	stdinCloser chan struct{}
// 	exitCh      chan uint32
// 	id          string
// 	stdin       string
// 	stdout      string
// 	stderr      string
// 	bundle      string
// 	cType       vc.ContainerType
// 	exit        uint32
// 	status      task.Status
// 	terminal    bool
// 	mounted     bool
// }

// type cmdExec struct {
// 	container *container
// 	cmds      *types.Cmd
// 	tty       *tty
// 	ttyio     *ttyIO

// 	stdinPipe io.WriteCloser

// 	exitTime time.Time

// 	exitIOch    chan struct{}
// 	stdinCloser chan struct{}

// 	exitCh chan uint32

// 	id string

// 	exitCode int32

// 	status task.Status
// }

// type cmdTty struct {
// 	stdin    string
// 	stdout   string
// 	stderr   string
// 	height   uint32
// 	width    uint32
// 	terminal bool
// }

// func test() {
// 	osexec.Command("ls")
// }
