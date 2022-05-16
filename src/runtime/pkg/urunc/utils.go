package urunc

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/sirupsen/logrus"
)

var uruncLog = logrus.WithFields(logrus.Fields{
	"src":  "uruncio",
	"name": "containerd-shim-v2",
})

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
	uruncLog.WithField("msg", "executing command").Error("urunc/utils.go/Command")
	return cmd.Process.Pid
}

func FindExecutable() (string, error) {
	path, err := os.Getwd()
	if err != nil {
		return "", err
	}

	files, err := ioutil.ReadDir(path + "/rootfs/unikernel/")
	if err != nil {
		return "", err
	}

	if len(files) != 1 {
		return "", errors.New("urunc/exec: multiple files found at /rootfs/unikernel/ dir")
	}

	unikernelFile := files[0].Name()
	unikernelFile = path + "/rootfs/unikernel/" + unikernelFile
	return unikernelFile, nil

}
