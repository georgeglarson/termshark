// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package main


import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/cli"
	"github.com/gcla/termshark/v2/pkg/system"
	"github.com/gcla/termshark/v2/pkg/tailfile"
	"github.com/gcla/termshark/v2/ui"
	flags "github.com/jessevdk/go-flags"
	"github.com/mattn/go-isatty"
)

func handleSpecialModes(tsopts *cli.Tshark) (exitCode int, continueNormal bool) {
	// Windows tail mode
	if tsopts.TailFileValue() != "" {
		err := tailfile.Tail(tsopts.TailFileValue())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v", err)
			return 1, false
		}
		return 0, false
	}

	// Internal capture mode
	if os.Getenv("TERMSHARK_CAPTURE_MODE") == "1" {
		err := system.DumpcapExt(termshark.DumpcapBin(), termshark.TSharkBin(), os.Args[1:]...)
		if err != nil {
			return 1, false
		}
		return 0, false
	}

	return 0, true
}

// handleTsharkPassthrough checks if we should pass through to tshark.
// Returns exit code and whether to continue with normal operation.
func handleTsharkPassthrough(tsopts *cli.Tshark, passthru bool) (exitCode int, continueNormal bool) {
	// Don't pass through to tshark if --web mode is requested
	for _, arg := range os.Args[1:] {
		if arg == "--web" || strings.HasPrefix(arg, "--web=") {
			return 0, true
		}
	}

	if passthru &&
		(cli.FlagIsTrue(tsopts.PassThru) ||
			(tsopts.PassThru == "auto" && !isatty.IsTerminal(os.Stdout.Fd())) ||
			tsopts.PrintIfaces) {

		tsharkBin, kverr := termshark.TSharkPath()
		if kverr != nil {
			fmt.Fprintf(os.Stderr, kverr.KeyVals["msg"].(string))
			return 1, false
		}

		args := []string{}
		for _, arg := range os.Args[1:] {
			if !slices.Contains(cli.TermsharkOnly, arg) && !termshark.StringIsArgPrefixOf(arg, cli.TermsharkOnly) {
				args = append(args, arg)
			}
		}
		args = append([]string{tsharkBin}, args...)

		if runtime.GOOS != "windows" {
			err := syscall.Exec(tsharkBin, args, os.Environ())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error execing tshark binary: %v\n", err)
				return 1, false
			}
		} else {
			c := exec.Command(args[0], args[1:]...)
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr

			err := c.Start()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error starting tshark: %v\n", err)
				return 1, false
			}

			err = c.Wait()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error waiting for tshark: %v\n", err)
				return 1, false
			}

			return 0, false
		}
	}
	return 0, true
}

// handleHelpAndVersion handles --help and --version flags.
// Returns exit code and whether to continue with normal operation.
func handleHelpAndVersion(opts *cli.Termshark, tmFlags *flags.Parser) (exitCode int, continueNormal bool) {
	if opts.Help {
		ui.WriteHelp(tmFlags, os.Stdout)
		return 0, false
	}

	if len(opts.Version) > 0 {
		res := 0
		ui.WriteVersion(tmFlags, os.Stdout)
		if len(opts.Version) > 1 {
			if tsharkBin, kverr := termshark.TSharkPath(); kverr != nil {
				fmt.Fprintf(os.Stderr, kverr.KeyVals["msg"].(string))
				res = 1
			} else {
				if ver, err := termshark.TSharkVersion(tsharkBin); err != nil {
					fmt.Fprintf(os.Stderr, "Could not determine version of tshark from binary %s\n", tsharkBin)
					res = 1
				} else {
					ui.WriteTsharkVersion(tmFlags, tsharkBin, ver, os.Stdout)
				}
			}
		}
		return res, false
	}

	return 0, true
}

