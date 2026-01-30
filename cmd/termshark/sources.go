// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package main


import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/cli"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/system"
)

func resolvePacketSources(opts *cli.Termshark, filterArgs []string) ([]pcap.IPacketSource, []string, error) {
	var psrcs []pcap.IPacketSource
	pcapf := string(opts.Pcap)

	// If no interface specified, and no pcap specified via -r, then we assume the first
	// argument is a pcap file e.g. termshark foo.pcap
	if pcapf == "" && len(opts.Ifaces) == 0 {
		pcapf = string(opts.Args.FilterOrPcap)
		if pcapf == "" {
			if termshark.IsTerminal(os.Stdin.Fd()) {
				pfile, err := system.PickFile()
				switch err {
				case nil:
					psrcs = append(psrcs, pcap.TemporaryFileSource{FileSource: pcap.FileSource{Filename: pfile}})
				case system.NoPicker:
					psrcs = append(psrcs, pcap.InterfaceSource{Iface: "1"})
				default:
					if err = system.PickFileError(err.Error()); err != nil {
						fmt.Fprintf(os.Stderr, err.Error())
					}
					return nil, nil, fmt.Errorf("file picker error")
				}
			} else {
				psrcs = append(psrcs, pcap.FileSource{Filename: "-"})
			}
		}
	} else {
		filterArgs = append(filterArgs, opts.Args.FilterOrPcap)
	}

	if pcapf != "" && len(opts.Ifaces) > 0 {
		return nil, nil, fmt.Errorf("please supply either a pcap or one or more live captures")
	}

	if len(psrcs) == 0 {
		switch {
		case pcapf != "":
			psrcs = append(psrcs, pcap.FileSource{Filename: pcapf})
		case len(opts.Ifaces) > 0:
			for _, iface := range opts.Ifaces {
				psrcs = append(psrcs, pcap.InterfaceSource{Iface: iface})
			}
		}
	}

	return psrcs, filterArgs, nil
}

// resolvePacketSourcesForWeb determines packet sources for web UI mode.
// Similar to resolvePacketSources but defaults to interface "1" when no source specified
// (no file picker or stdin support in web mode).
func resolvePacketSourcesForWeb(opts *cli.Termshark, filterArgs []string) ([]pcap.IPacketSource, []string, error) {
	var psrcs []pcap.IPacketSource
	pcapf := string(opts.Pcap)

	// Check for pcap file from positional arg if not specified via -r
	if pcapf == "" && len(opts.Ifaces) == 0 {
		pcapf = string(opts.Args.FilterOrPcap)
		if pcapf == "" {
			// Web mode: default to interface "1" (first interface)
			psrcs = append(psrcs, pcap.InterfaceSource{Iface: "1"})
		}
	} else {
		filterArgs = append(filterArgs, opts.Args.FilterOrPcap)
	}

	if pcapf != "" && len(opts.Ifaces) > 0 {
		return nil, nil, fmt.Errorf("please supply either a pcap or one or more live captures")
	}

	if len(psrcs) == 0 {
		switch {
		case pcapf != "":
			psrcs = append(psrcs, pcap.FileSource{Filename: pcapf})
		case len(opts.Ifaces) > 0:
			for _, iface := range opts.Ifaces {
				psrcs = append(psrcs, pcap.InterfaceSource{Iface: iface})
			}
		}
	}

	return psrcs, filterArgs, nil
}

// validateAndTransformSources validates packet sources and transforms stdin/fifo sources.
func validateAndTransformSources(psrcs []pcap.IPacketSource) ([]pcap.IPacketSource, error) {
	haveStdin := false
	for pi, psrc := range psrcs {
		switch {
		case psrc.Name() == "-":
			if haveStdin {
				return nil, fmt.Errorf("requested live capture %v (\"stdin\") cannot be supplied more than once", psrc.Name())
			}
			if termshark.IsTerminal(os.Stdin.Fd()) {
				return nil, fmt.Errorf("requested live capture is %v (\"stdin\") but stdin is a tty", psrc.Name())
			}
			if runtime.GOOS != "windows" {
				psrcs[pi] = pcap.PipeSource{Descriptor: "/dev/fd/0", Fd: int(os.Stdin.Fd())}
				haveStdin = true
			} else {
				return nil, fmt.Errorf("termshark does not yet support piped input on Windows")
			}
		default:
			stat, err := os.Stat(psrc.Name())
			if err != nil {
				if psrc.IsFile() || psrc.IsFifo() {
					return nil, fmt.Errorf("error reading file %s: %v", psrc.Name(), err)
				}
				continue
			}
			if stat.Mode()&os.ModeNamedPipe != 0 {
				psrcs[pi] = pcap.FifoSource{Filename: psrc.Name()}
			} else {
				if pcapffile, err := os.Open(psrc.Name()); err != nil {
					return nil, fmt.Errorf("error reading file %s: %v", psrc.Name(), err)
				} else {
					pcapffile.Close()
				}
			}
		}
	}
	return psrcs, nil
}

// validateSourceCombinations ensures valid combinations of file and interface sources.
func validateSourceCombinations(psrcs []pcap.IPacketSource) error {
	fileSrcs := pcap.FileSystemSources(psrcs)
	if len(fileSrcs) == 1 {
		if len(psrcs) > 1 {
			return fmt.Errorf("you can't specify both a pcap and a live capture")
		}
	} else if len(fileSrcs) > 1 {
		return fmt.Errorf("you can't specify more than one pcap")
	}
	return nil
}

// resolveFilters determines capture and display filters from arguments.
func resolveFilters(opts *cli.Termshark, psrcs []pcap.IPacketSource, filterArgs []string) (captureFilter, displayFilter string, err error) {
	fileSrcs := pcap.FileSystemSources(psrcs)

	termshark.ReverseStringSlice(filterArgs)
	argsFilter := strings.Join(filterArgs, " ")

	captureFilter = opts.CaptureFilter
	displayFilter = opts.DisplayFilter

	// If only live captures and filter args provided, use as capture filter
	if len(fileSrcs) == 0 && argsFilter != "" {
		if opts.CaptureFilter != "" {
			return "", "", fmt.Errorf("two capture filters provided - '%s' and '%s' - please supply one only",
				opts.CaptureFilter, argsFilter)
		}
		captureFilter = argsFilter
	}

	// Validate filters for file sources
	if len(fileSrcs) > 0 {
		if captureFilter != "" {
			return "", "", fmt.Errorf("cannot use a capture filter when reading from a pcap file")
		}
		if argsFilter != "" {
			if opts.DisplayFilter != "" {
				return "", "", fmt.Errorf("two display filters provided - '%s' and '%s' - please supply one only",
					opts.DisplayFilter, argsFilter)
			}
			displayFilter = argsFilter
		}
	}

	return captureFilter, displayFilter, nil
}

// validateWriteTarget validates the -w flag target.
func validateWriteTarget(opts *cli.Termshark, psrcs []pcap.IPacketSource) error {
	if opts.WriteTo == "" {
		return nil
	}

	fileSrcs := pcap.FileSystemSources(psrcs)
	if len(fileSrcs) > 0 {
		return fmt.Errorf("the -w flag is incompatible with regular capture sources %v", fileSrcs)
	}
	if opts.WriteTo == "-" {
		return fmt.Errorf("cannot set -w to stdout. Target file must be regular or a symlink")
	}
	if _, err := os.Stat(string(opts.WriteTo)); err == nil || !os.IsNotExist(err) {
		if !system.FileRegularOrLink(string(opts.WriteTo)) {
			return fmt.Errorf("cannot set -w to %s. Target file must be regular or a symlink", opts.WriteTo)
		}
	}
	return nil
}

// resolveInterfaceNames resolves numeric interface indices to canonical names.
func resolveInterfaceNames(psrcs []pcap.IPacketSource) ([]pcap.IPacketSource, error) {
	var systemInterfaces map[int][]string
	var err error

	for pi, psrc := range psrcs {
		checkInterfaceName := false
		ifaceIdx := -1
		if psrc.IsInterface() {
			if i, err := strconv.Atoi(psrc.Name()); err == nil {
				ifaceIdx = i
			}
			if ifaceIdx != -1 {
				checkInterfaceName = true
			} else if runtime.GOOS == "windows" {
				checkInterfaceName = true
			}
		}

		if checkInterfaceName {
			if systemInterfaces == nil {
				systemInterfaces, err = termshark.Interfaces()
				if err != nil {
					return nil, fmt.Errorf("could not enumerate network interfaces: %v\n\nTo capture packets, run with sudo:\n  sudo termshark -i <interface>\n\nOr analyze an existing pcap file:\n  termshark -r <file.pcap>", err)
				}
			}

			gotit := false
			var canonicalName string
		iLoop:
			for n, i := range systemInterfaces {
				if n == ifaceIdx {
					gotit = true
					canonicalName = i[0]
					break
				} else {
					for _, iname := range i {
						if iname == psrc.Name() {
							gotit = true
							canonicalName = i[0]
							break iLoop
						}
					}
				}
			}
			if gotit {
				psrcs[pi] = pcap.InterfaceSource{Iface: canonicalName}
			} else {
				return nil, fmt.Errorf("could not find network interface %s", psrc.Name())
			}
		}
	}
	return psrcs, nil
}

