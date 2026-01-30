// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/system"
)

//======================================================================

func RunForExitCode(prog string, args []string, env []string) (int, error) {
	return RunForStderr(prog, args, env, io.Discard)
}

func RunForStderr(prog string, args []string, env []string, stderr io.Writer) (int, error) {
	var err error
	exitCode := -1 // default bad
	cmd := exec.Command(prog, args...)
	if env != nil {
		cmd.Env = env
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	err = cmd.Run()
	if err != nil {
		var exerr *exec.ExitError
		if errors.As(err, &exerr) {
			ws := exerr.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		}
	} else {
		ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
		exitCode = ws.ExitStatus()
	}

	return exitCode, err
}

//======================================================================

type IProcess interface {
	Kill() error
	Pid() int
}

func KillIfPossible(p IProcess) error {
	if p == nil {
		return nil
	}
	err := p.Kill()
	if errProcessAlreadyFinished(err) {
		return nil
	} else {
		return err
	}
}

func errProcessAlreadyFinished(err error) bool {
	return errors.Is(err, os.ErrProcessDone)
}

func SafePid(p IProcess) int {
	if p == nil {
		return -1
	}
	return p.Pid()
}

//======================================================================

// ApplyArguments turns ["echo", "hello", "$2"] + ["big", "world"] into
// ["echo", "hello", "world"]
func ApplyArguments(cmd []string, args []string) ([]string, int) {
	total := 0
	res := make([]string, len(cmd))
	for i, c := range cmd {
		changed := false
		matches := argRe.FindStringSubmatch(c)
		if len(matches) > 1 {
			unum, _ := strconv.ParseUint(matches[1], 10, 32)
			num := int(unum)
			num -= 1 // 1 indexed
			if num < len(args) {
				res[i] = args[num]
				changed = true
				total += 1
			}
		}
		if !changed {
			res[i] = c
		}
	}
	return res, total
}

func BrowseUrl(url string) error {
	urlCmd := profiles.ConfStringSlice(
		"main.browse-command",
		system.OpenURL,
	)

	if len(urlCmd) == 0 {
		return gowid.WithKVs(BadCommand, map[string]interface{}{"message": "browse command is nil"})
	}

	urlCmdPP, changed := ApplyArguments(urlCmd, []string{url})
	if changed == 0 {
		urlCmdPP = append(urlCmd, url)
	}

	cmd := exec.Command(urlCmdPP[0], urlCmdPP[1:]...)

	return cmd.Run()
}

//======================================================================

type ICommandOutput interface {
	ProcessOutput(output string) error
}

type ICommandError interface {
	ProcessCommandError(err error) error
}

type ICommandDone interface {
	ProcessCommandDone()
}

type ICommandKillError interface {
	ProcessKillError(err error) error
}

type ICommandTimeout interface {
	ProcessCommandTimeout() error
}

type ICommandWaitTicker interface {
	ProcessWaitTick() error
}

func CopyCommand(input io.Reader, cb interface{}) error {
	var err error

	copyCmd := profiles.ConfStringSlice(
		"main.copy-command",
		system.CopyToClipboard,
	)

	if len(copyCmd) == 0 {
		return gowid.WithKVs(BadCommand, map[string]interface{}{"message": "copy command is nil"})
	}

	cmd := exec.Command(copyCmd[0], copyCmd[1:]...)
	cmd.Stdin = input
	outBuf := bytes.Buffer{}
	cmd.Stdout = &outBuf

	cmdTimeout := profiles.ConfInt("main.copy-command-timeout", 5)
	if err := cmd.Start(); err != nil {
		return gowid.WithKVs(BadCommand, map[string]interface{}{"err": err})
	}

	Go(func() {

		defer func() {
			if po, ok := cb.(ICommandDone); ok {
				po.ProcessCommandDone()
			}
		}()

		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		tick := time.NewTicker(time.Duration(200) * time.Millisecond)
		defer tick.Stop()
		tchan := time.After(time.Duration(cmdTimeout) * time.Second)

	Loop:
		for {
			select {
			case <-tick.C:
				if po, ok := cb.(ICommandWaitTicker); ok {
					err = po.ProcessWaitTick()
					if err != nil {
						break Loop
					}
				}

			case <-tchan:
				if err := cmd.Process.Kill(); err != nil {
					if po, ok := cb.(ICommandKillError); ok {
						err = po.ProcessKillError(err)
						if err != nil {
							break Loop
						}
					}
				} else {
					if po, ok := cb.(ICommandTimeout); ok {
						err = po.ProcessCommandTimeout()
						if err != nil {
							break Loop
						}
					}
				}
				break Loop

			case err := <-done:
				if err != nil {
					if po, ok := cb.(ICommandError); ok {
						po.ProcessCommandError(err)
					}
				} else {
					if po, ok := cb.(ICommandOutput); ok {
						outStr := outBuf.String()
						po.ProcessOutput(outStr)
					}
				}
				break Loop
			}
		}

	})

	return nil
}
