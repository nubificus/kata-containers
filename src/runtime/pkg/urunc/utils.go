package urunc

import (
	"os"
	"os/exec"
)

// dummy function to check if importing works (go is strange). it is no longer needed
func Hello() bool {
	return true
}

func Command(name string, arg ...string) int {
	cmd := exec.Command(name, arg...)

	// We need to change that to proper pipes
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// This would wait for process to return
	// cmd.Run()

	err := cmd.Start()
	if err != nil {
		return -1
	}
	return cmd.Process.Pid
}
