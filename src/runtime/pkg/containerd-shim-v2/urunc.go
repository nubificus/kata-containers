package containerdshim

import "github.com/sirupsen/logrus"

type Command struct {
	cmd       string
	container *container
	id        string
	stdin     string
	stdout    string
	stderr    string
	bundle    string
}

func (c *Command) Run() {
	logF := logrus.Fields{"src": "uruncio", "file": "cs/urunc.go", "func": "run"}
	shimLog.WithField("containerType", c.container.cType).WithFields(logF).Error("container info")
}

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
