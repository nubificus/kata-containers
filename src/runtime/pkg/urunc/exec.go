package urunc

import (
	"fmt"
	"os/exec"
)

type Exec struct {
	Cmd string
	Pid int
}

func NewExec(path string) Exec {
	return newExec(path)
}

func newExec(path string) Exec {
	return Exec{
		Cmd: "ls",
		Pid: 1,
	}
	// return exec.Cmd{
	// 	Path:         path,
	// 	Args:         []string{},
	// 	Env:          []string{},
	// 	Dir:          "",
	// 	Stdin:        nil,
	// 	Stdout:       nil,
	// 	Stderr:       nil,
	// 	ExtraFiles:   []*os.File{},
	// 	SysProcAttr:  &syscall.SysProcAttr{},
	// 	Process:      &os.Process{},
	// 	ProcessState: &os.ProcessState{},
	// }
}

func Main() {
	fmt.Println("HI")
	cmd := exec.Command("ls")
	fmt.Println(cmd.Path)
}

func (e *Exec) GetPid() int {
	return e.Pid
}
