// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package vaccel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)



// vAccelInfo contains information related to the vAccelrt agent
type vAccelInfo struct {
	PID     int
	Version string
}


type vAccelType int


const (
	vsock vAccelType = iota // vAccel vsock transport
	virtio // vAccel virtio trasport
)

type guestBackend struct {
	vaccelType vAccelType
	//vaccel interface
}

// firecracker is an Hypervisor interface implementation for the firecracker VMM.
type Vaccel struct {
	VaccelPath    string //Path to vaccel installation on host
	HostBackend   string //Vaccel backend framework
	GuestBackend  guestBackend //Vaccel transport layer (vsock or virtio)
	SocketPath    string

	info vAccelInfo

	vaccelrtd *exec.Cmd           //Tracks the firecracker process itself
}

/*// This should be implemented in virtcontainers/fc.go for firecracker
func (fc *firecracker) Accelarators(ctx context.Context, timeout int) error {
        accelerators := fc.config.MachineAccelerators
        if accelerators != "" {
		for _, accelerator := range strings.Split(h.MachineAccelerators, ",") {
	                switch strings.TrimSpace(accelerator){
			case "vaccel-vsock":
				// add vaccl.VaccelPath and vsockPath and call vaccel.VaccelInit
			case "vaccel-virtio":
				//TODO call vaccel.VaccelInit with vAccelType = virtio
			default:

			}
		}

        }
}
*/

/*func (vaccel *Vaccel) VaccelInit() {
	switch vaccel.guestBackend.vaccelType {
	case vsock:
		//call vaccelrtAgent()
	case virtio:
		//*TODO* os.Setenv VACCEL_BACKENDS, IMAGESNET etc
	default:
	}
}*/

// This is the vsock implementation (will be renamed to vaccelrtAgent
func (vaccel *Vaccel) VaccelInit() error {

	var cmd *exec.Cmd
	var args []string

	vaccelrtBin := filepath.Join(vaccel.VaccelPath, "bin", "vaccelrt-agent")
	fmt.Println("vaccelrt-agent:", vaccelrtBin)
	vaccelrtLibs := filepath.Join(vaccel.VaccelPath, "lib")
	fmt.Println("vaccelrtLibs:", vaccelrtLibs)
	vaccelrtBack := filepath.Join(vaccelrtLibs, vaccel.HostBackend)
	fmt.Println("vaccelrtBack:", vaccelrtBack)
	fmt.Println("vaccelSocketPath:", vaccel.SocketPath)
	args = append(args, "--server-address", vaccel.SocketPath)
	fmt.Println("args:", args)
	vaccel_backends := "VACCEL_BACKENDS=" + vaccelrtBack
	vaccel_debug := "VACCEL_DEBUG_LEVEL=" + "4"
	ld_path := "LD_LIBRARY_PATH=" + vaccelrtLibs
	fmt.Println("EXTRA ENV:", vaccel_backends, ld_path, vaccel_debug)
	cmd = exec.Command(vaccelrtBin, args...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, vaccel_backends, ld_path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Println("calling cmd.Start\n")

	if err := cmd.Start(); err != nil {
		return err
	}

	vaccel.info.PID = cmd.Process.Pid
	fmt.Println("Started wih PID:", vaccel.info.PID)
	vaccel.vaccelrtd = cmd
	return nil
}

func (vaccel *Vaccel) VaccelEnd() (err error) {

	pid := vaccel.info.PID

	// Send a SIGTERM to the vAccel agent to try to stop it properly
	if err = syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if err == syscall.ESRCH {
			return nil
		}
		return err
	}

	// Wait for the vAccel process to terminate
	tInit := time.Now()
	for {
		if err = syscall.Kill(pid, syscall.Signal(0)); err != nil {
			return nil
		}

		if time.Since(tInit).Seconds() >= 5 {
			break
		}

		// Let's avoid to run a too busy loop
		time.Sleep(time.Duration(50) * time.Millisecond)
	}

	// Let's try with a hammer now, a SIGKILL should get rid of the
	// VM process.
	return syscall.Kill(pid, syscall.SIGKILL)
}
