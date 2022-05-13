// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"errors"
	"fmt"
	osexec "os/exec"

	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/api/types/task"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/urunc"
)

func startContainer(ctx context.Context, s *service, c *container) (retErr error) {
	shimLog.WithField("container", c.id).Debug("start container")
	defer func() {
		if retErr != nil {
			shimLog.WithField("src", "uruncio").WithField("msg", "retErr not nil").Error("pkg/start.go/startContainer")
			// notify the wait goroutine to continue
			c.exitCh <- exitCode255
		}
	}()
	// start a container
	if c.cType == "" {
		err := fmt.Errorf("Bug, the container %s type is empty", c.id)
		return err
	}

	if s.sandbox == nil {
		err := fmt.Errorf("Bug, the sandbox hasn't been created for this container %s", c.id)
		shimLog.WithField("src", "uruncio").WithField("message", "s.sandbox is nil").Error("pkg/start.go/startContainer")

		return err
	}

	shimLog.WithField("src", "uruncio").WithField("message", "s.sandbox was not nil").Error("pkg/start.go/startContainer")
	shimLog.WithField("src", "uruncio").WithField("c.cType.IsSandbox", c.cType.IsSandbox()).Error("pkg/start.go/startContainer")

	unikernelFound := false
	var unikernelBin string

	// If unikernel set in config, check for file
	if s.config.HypervisorConfig.Unikernel {
		shimLog.WithField("src", "uruncio").WithField("unikernel", true).Error("pkg/start.go/startContainer")
		bin, err := urunc.FindExecutable()
		if err == nil {
			unikernelFound = true
			unikernelBin = bin
		}
	}

	var cmd *osexec.Cmd
	cmdFound := false

	// if unikernel found, create a cmd
	if c.cType.IsSandbox() && unikernelFound {
		shimLog.WithField("src", "uruncio").WithField("unikernelBin", unikernelBin).Error("pkg/start.go/startContainer")
		cmd = osexec.Command(unikernelBin)
		cmdFound = true
		shimLog.WithField("src", "uruncio").WithField("cmd", cmd.Path).Error("pkg/start.go/startContainer")

		// err := s.sandbox.Start(ctx)
		// if err != nil {
		// 	return err
		// }
		// // Start monitor after starting sandbox
		// s.monitor, err = s.sandbox.Monitor(ctx)
		// if err != nil {
		// 	return err
		// }
		// go watchSandbox(ctx, s)

		// // We use s.ctx(`ctx` derived from `s.ctx`) to check for cancellation of the
		// // shim context and the context passed to startContainer for tracing.
		// go watchOOMEvents(ctx, s)
	} else if c.cType.IsSandbox() {
		err := s.sandbox.Start(ctx)
		if err != nil {
			return err
		}
		// Start monitor after starting sandbox
		s.monitor, err = s.sandbox.Monitor(ctx)
		if err != nil {
			return err
		}
		go watchSandbox(ctx, s)

		// We use s.ctx(`ctx` derived from `s.ctx`) to check for cancellation of the
		// shim context and the context passed to startContainer for tracing.
		go watchOOMEvents(ctx, s)
	} else {
		_, err := s.sandbox.StartContainer(ctx, c.id)
		if err != nil {
			return err
		}
	}

	// Run post-start OCI hooks.
	err := katautils.EnterNetNS(s.sandbox.GetNetNs(), func() error {
		return katautils.PostStartHooks(ctx, *c.spec, s.sandbox.ID(), c.bundle)
	})
	if err != nil {
		// log warning and continue, as defined in oci runtime spec
		// https://github.com/opencontainers/runtime-spec/blob/master/runtime.md#lifecycle
		shimLog.WithError(err).Warn("Failed to run post-start hooks")
	}
	// normaly c.status is CREATED
	shimLog.WithField("src", "uruncio").WithField("c.status", c.status).Error("pkg/start.go/startContainer")

	c.status = task.StatusRunning

	// normaly c.status is RUNNING
	shimLog.WithField("src", "uruncio").WithField("c.status", c.status).Error("pkg/start.go/startContainer")
	shimLog.WithField("src", "uruncio").WithField("cmdFound", cmdFound).Error("pkg/start.go/startContainer")

	if cmdFound {
		shimLog.WithField("src", "uruncio").WithField("cmd", cmd.Path).Error("pkg/start.go/startContainer")
		return errors.New("urunc/exec: exec not implemented yet")
	}
	shimLog.WithField("src", "uruncio").WithField("msg", "no cmd was found").Error("pkg/start.go/startContainer")

	stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, c.id)

	shimLog.WithField("src", "uruncio").WithField("msg", "got io pipes").Error("pkg/start.go/startContainer")

	if err != nil {
		return err
	}

	c.stdinPipe = stdin

	shimLog.WithField("src", "uruncio").WithField("msg", "redirected stdin pipe").Error("pkg/start.go/startContainer")

	if c.stdin != "" || c.stdout != "" || c.stderr != "" {
		shimLog.WithField("src", "uruncio").WithField("msg", "new tty will be created").Error("pkg/start.go/startContainer")

		tty, err := newTtyIO(ctx, c.stdin, c.stdout, c.stderr, c.terminal)
		shimLog.WithField("src", "uruncio").WithField("msg", "new tty created").Error("pkg/start.go/startContainer")

		if err != nil {
			return err
		}

		shimLog.WithField("src", "uruncio").WithField("msg", "tty will be set").Error("pkg/start.go/startContainer")

		c.ttyio = tty
		shimLog.WithField("src", "uruncio").WithField("msg", "tty set").Error("pkg/start.go/startContainer")

		go ioCopy(shimLog.WithField("container", c.id), c.exitIOch, c.stdinCloser, tty, stdin, stdout, stderr)
	} else {
		shimLog.WithField("src", "uruncio").WithField("msg", "closing channels").Error("pkg/start.go/startContainer")

		// close the io exit channel, since there is no io for this container,
		// otherwise the following wait goroutine will hang on this channel.
		close(c.exitIOch)
		// close the stdin closer channel to notify that it's safe to close process's
		// io.
		close(c.stdinCloser)
	}
	shimLog.WithField("src", "uruncio").WithField("msg", "before go wait").Error("pkg/start.go/startContainer")

	go wait(ctx, s, c, "")
	shimLog.WithField("src", "uruncio").WithField("msg", "after go wait").Error("pkg/start.go/startContainer")

	return nil
}

func startExec(ctx context.Context, s *service, containerID, execID string) (e *exec, retErr error) {
	shimLog.WithFields(logrus.Fields{
		"container": containerID,
		"exec":      execID,
	}).Debug("start container execution")
	// start an exec
	c, err := s.getContainer(containerID)
	if err != nil {
		return nil, err
	}

	execs, err := c.getExec(execID)
	if err != nil {
		return nil, err
	}

	defer func() {
		if retErr != nil {
			// notify the wait goroutine to continue
			execs.exitCh <- exitCode255
		}
	}()

	_, proc, err := s.sandbox.EnterContainer(ctx, containerID, *execs.cmds)
	if err != nil {
		err := fmt.Errorf("cannot enter container %s, with err %s", containerID, err)
		return nil, err
	}
	execs.id = proc.Token

	execs.status = task.StatusRunning
	if execs.tty.height != 0 && execs.tty.width != 0 {
		err = s.sandbox.WinsizeProcess(ctx, c.id, execs.id, execs.tty.height, execs.tty.width)
		if err != nil {
			return nil, err
		}
	}

	stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, execs.id)
	if err != nil {
		return nil, err
	}

	execs.stdinPipe = stdin

	tty, err := newTtyIO(ctx, execs.tty.stdin, execs.tty.stdout, execs.tty.stderr, execs.tty.terminal)
	if err != nil {
		return nil, err
	}
	execs.ttyio = tty

	go ioCopy(shimLog.WithFields(logrus.Fields{
		"container": c.id,
		"exec":      execID,
	}), execs.exitIOch, execs.stdinCloser, tty, stdin, stdout, stderr)

	go wait(ctx, s, c, execID)

	return execs, nil
}
