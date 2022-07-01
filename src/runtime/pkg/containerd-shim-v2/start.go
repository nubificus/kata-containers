// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/containerd/api/types/task"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
	"github.com/sirupsen/logrus"
)

func startContainer(ctx context.Context, s *service, c *container) (retErr error) {
	shimLog.WithField("container", c.id).Debug("start container")
	logF := logrus.Fields{"src": "uruncio", "file": "cs/start.go", "func": "startContainer"}
	unikernelCreated := false
	var cmd *Command

	defer func() {
		if retErr != nil {
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
		return err
	}
	shimLog.WithField("s.sandbox", "not nil").WithFields(logF).Error("sandbox not nil")

	// Before we procced to the existing kata workflow, check if hypervisor supports unikernel
	// Also check if ExecData were provided from urunc_agent

	shimLog.WithField("container", c.id).Debug("start container")

	// start a container
	// hopefully we can get the agent.ExecData field
	execData := s.sandbox.Agent().GetExecData()
	// logrus.WithFields(logF).Error(execData.BinaryPath)
	shimLog.WithFields(logF).WithField("BinaryPath", execData.BinaryPath).Error("coninfo")
	shimLog.WithFields(logF).WithField("BinaryType", execData.BinaryType).Error("coninfo")
	shimLog.WithFields(logF).WithField("IPAddress", execData.IPAddress).Error("coninfo")
	shimLog.WithFields(logF).WithField("Mask", execData.Mask).Error("coninfo")
	shimLog.WithFields(logF).WithField("Gateway", execData.Gateway).Error("coninfo")
	shimLog.WithFields(logF).WithField("Tap", execData.Tap).Error("coninfo")
	shimLog.WithField("container type", c.cType).WithFields(logF).Error("coninfo")
	shimLog.WithField("hyperVisorpid", s.hpid).WithFields(logF).Error("coninfo")
	shimLog.WithField("shimpid", s.pid).WithFields(logF).Error("coninfo")
	shimLog.WithField("hypervisorUnikernel", s.config.HypervisorConfig.Unikernel).WithFields(logF).Error("coninfo")

	// Check if config has unikernel set to true and binary exists in rootfs
	binaryType := s.sandbox.Agent().GetExecData().BinaryType
	if s.config.HypervisorConfig.Unikernel && binaryType == "" {
		return errors.New("unikernel not found in rootfs")
	}

	// If the hypervisor is not urunc, execute the normal flow
	if c.cType.IsSandbox() {

		if s.config.HypervisorConfig.Unikernel {
			unikernelFile := s.sandbox.Agent().GetExecData().BinaryPath
			shimLog.WithField("unikernelFile", unikernelFile).WithFields(logF).Error("is unikernel and is sandbox")
			if c.cType.IsSandbox() {
				shimLog.WithFields(logF).Error("starting sandbox")
				s.sandbox.Start(ctx)
				shimLog.WithFields(logF).Error("sandbox started")
			}

			shimLog.WithFields(logF).Error("starting container")

			_, err := s.sandbox.StartContainer(ctx, c.id+"-unikernel")
			if err != nil {
				return err
			}
			shimLog.WithFields(logF).Error("container started")

			shimLog.WithFields(logF).WithField("ip", s.sandbox.Agent().GetExecData().IPAddress).Error("net info")

			unikernelCreated = true
		} else {

			shimLog.WithField("cType", c.cType).WithFields(logF).Error("start unikernel exec")

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
		}
	} else {

		if s.config.HypervisorConfig.Unikernel {
			unikernelFile := s.sandbox.Agent().GetExecData().BinaryPath
			shimLog.WithField("unikernelFile", unikernelFile).WithFields(logF).Error("is unikernel and is sandbox")
			if c.cType.IsSandbox() {
				shimLog.WithFields(logF).Error("starting sandbox")
				s.sandbox.Start(ctx)
				shimLog.WithFields(logF).Error("sandbox started")
			}

			shimLog.WithFields(logF).Error("starting container")

			_, err := s.sandbox.StartContainer(ctx, c.id+"-unikernel")
			if err != nil {
				return err
			}
			shimLog.WithFields(logF).Error("container started")

			shimLog.WithFields(logF).WithField("ip", s.sandbox.Agent().GetExecData().IPAddress).Error("net info")

			unikernelCreated = true
		} else {

			_, err := s.sandbox.StartContainer(ctx, c.id)
			if err != nil {
				return err
			}

		}

	}

	// Run post-start OCI hooks.
	shimLog.WithFields(logF).Error("post-start OCI hook")
	err := katautils.EnterNetNS(s.sandbox.GetNetNs(), func() error {
		return katautils.PostStartHooks(ctx, *c.spec, s.sandbox.ID(), c.bundle)
	})
	if err != nil {
		// log warning and continue, as defined in oci runtime spec
		// https://github.com/opencontainers/runtime-spec/blob/master/runtime.md#lifecycle
		shimLog.WithError(err).Warn("Failed to run post-start hooks")
	}

	if unikernelCreated {
		shimLog.WithFields(logF).Error("ready to start unikernel")

		cmd = CreateCommand(s.sandbox.Agent().GetExecData(), c)

		//shimLog.WithField("unikPath", cmd.cmdString).WithFields(logF).Error("letsgo")
		err := cmd.SetIO(ctx)
		if err != nil {
			return err
		}
		err = cmd.Start()
		if err != nil {
			return err
		}
		go cmd.Wait()

		// cmd run will connect the pipes or return them
		// we will also need a goroutine to Wait for the command
		// to run in order to notify the container's channels
		// and terminate gracefully
		// err = cmd.Wait()

		// ananos' diff
		// go wait(ctx, s, c, "")
		// return nil

		// } else if s.sandbox.Agent().GetExecData().BinaryType != "pause" {
		//return nil

	} else {
		c.status = task.StatusRunning
		shimLog.WithField("c.status", c.status).WithFields(logF).Error("cs/start.go/startContainer")

		stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, c.id)
		if err != nil {
			return err
		}

		c.stdinPipe = stdin

		if c.stdin != "" || c.stdout != "" || c.stderr != "" {
			tty, err := newTtyIO(ctx, c.stdin, c.stdout, c.stderr, c.terminal)
			if err != nil {
				return err
			}
			c.ttyio = tty

			go ioCopy(shimLog.WithField("container", c.id), c.exitIOch, c.stdinCloser, tty, stdin, stdout, stderr)
		} else {
			// close the io exit channel, since there is no io for this container,
			// otherwise the following wait goroutine will hang on this channel.
			close(c.exitIOch)
			// close the stdin closer channel to notify that it's safe to close process's
			// io.
			close(c.stdinCloser)
		}
	}

	go wait(ctx, s, c, "")

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
