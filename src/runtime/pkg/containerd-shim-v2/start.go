// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/api/types/task"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/urunc"
)

func startContainer(ctx context.Context, s *service, c *container) (retErr error) {
	shimLog.WithField("container", c.id).Debug("start container")
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
		shimLog.WithField("src", "uruncio").WithField("message", "s.sandbox is nil").Error("pkg/start.go/startContainer")

		return err
	}
	shimLog.WithField("src", "uruncio").WithField("message", "s.sandbox was not nil").Error("pkg/start.go/startContainer")

	shimLog.WithField("src", "uruncio").WithField("c.cType.IsSandbox", c.cType.IsSandbox()).Error("pkg/start.go/startContainer")

	if s.config.HypervisorConfig.Unikernel {
		shimLog.WithField("src", "uruncio").WithField("unikernel", true).Error("pkg/start.go/startContainer")

		// The command here gets executed
		// Not sure if this is the correct place to inject it though
		uruncPid := urunc.Command("echo", "HI")
		shimLog.WithField("src", "uruncio").WithField("unikernelPid", uruncPid).Error("pkg/start.go/startContainer")
		if uruncPid == -1 {
			return errors.New("urunc/exec: process didn't execute")
		}

		// we will need the bundle tho
		// the bundle is located in the current working dir
		path, err := os.Getwd()
		if err != nil {
			return err
		}

		files, err := ioutil.ReadDir(path)
		if err != nil {
			return err
		}

		fileString := ""
		for _, f := range files {
			fileString = fileString + f.Name() + ", "
		}

		shimLog.WithField("src", "uruncio").WithField("currentPath", path).Error("pkg/start.go/startContainer")
		shimLog.WithField("src", "uruncio").WithField("files", fileString).Error("pkg/start.go/startContainer")

		// [TODO] we need to define a standard method of identifying the unikernel binary inside the bundle in order to extract it consistently.
		// For testing purposes, the scripts expects the unikernel at path + "/rootfs/unikernel/UNIKERNEL"

		files, err = ioutil.ReadDir(path + "/rootfs/unikernel/")
		if err == nil {

			if len(files) != 1 {
				return errors.New("urunc/exec: multiple files found at /rootfs/unikernel/ dir")
			}

			unikernelFile := files[0].Name()
			shimLog.WithField("src", "uruncio").WithField("unikernelFile", unikernelFile).Error("pkg/start.go/startContainer")
		} else {
			shimLog.WithField("src", "uruncio").WithField("unikernelFile", "unikernel file not found in rootfs").Error("pkg/start.go/startContainer")
		}
		// I am not sure if we need any information provided by the config.json at this step
	}

	if c.cType.IsSandbox() {
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

	c.status = task.StatusRunning

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
