// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/blang/semver"
	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2/configs/profiles"
	log "github.com/sirupsen/logrus"
)

//======================================================================

func IsCommandInPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func DirOfPathCommandUnsafe(bin string) string {
	d, err := DirOfPathCommand(bin)
	if err != nil {
		panic(err)
	}
	return d
}

func DirOfPathCommand(bin string) (string, error) {
	return exec.LookPath(bin)
}

//======================================================================

var TSharkVersionUnknown = fmt.Errorf("Could not determine version of tshark")

func TSharkVersionFromOutput(output string) (semver.Version, error) {
	res := tsharkVersionRe.FindStringSubmatch(output)

	if len(res) > 0 {
		if v, err := semver.Make(res[1]); err == nil {
			return v, nil
		} else {
			return semver.Version{}, err
		}
	}

	return semver.Version{}, TSharkVersionUnknown
}

func TSharkVersion(tshark string) (semver.Version, error) {
	cmd := exec.Command(tshark, "--version")
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	cmd.Run() // don't check error - older versions return error code 1. Just search output.
	output := cmdOutput.Bytes()

	return TSharkVersionFromOutput(string(output))
}

// Depends on empty.pcap being present
func TSharkSupportsColor(tshark string) (bool, error) {
	exitCode, err := RunForExitCode(
		tshark,
		[]string{"-r", CacheFile("empty.pcap"), "-T", "psml", "--color"},
		nil,
	)
	return exitCode == 0, err
}

// TSharkPath will return the full path of the tshark binary, if it's found in the path, otherwise an error
func TSharkPath() (string, *gowid.KeyValueError) {
	tsharkBin := profiles.ConfString("main.tshark", "")
	if tsharkBin != "" {
		confirmedTshark := false
		if _, err := os.Stat(tsharkBin); err == nil {
			confirmedTshark = true
		} else if IsCommandInPath(tsharkBin) {
			confirmedTshark = true
		}
		// This message is for a configured tshark binary that is invalid
		if !confirmedTshark {
			err := gowid.WithKVs(ConfigErr, map[string]interface{}{
				"msg": fmt.Sprintf("Could not run tshark binary '%s'. The tshark binary is required to run termshark.\n", tsharkBin) +
					fmt.Sprintf("Check your config file %s\n", ConfFile("toml")),
			})
			return "", &err
		}
	} else {
		tsharkBin = "tshark"
		if !IsCommandInPath(tsharkBin) {
			// This message is for an unconfigured tshark bin (via PATH) that is invalid
			errstr := fmt.Sprintf("Could not find tshark in your PATH. The tshark binary is required to run termshark.\n")
			if strings.Contains(os.Getenv("PREFIX"), "com.termux") {
				errstr += fmt.Sprintf("Try installing with: pkg install root-repo && pkg install tshark")
			} else if IsCommandInPath("apt") {
				errstr += fmt.Sprintf("Try installing with: apt install tshark")
			} else if IsCommandInPath("apt-get") {
				errstr += fmt.Sprintf("Try installing with: apt-get install tshark")
			} else if IsCommandInPath("yum") {
				errstr += fmt.Sprintf("Try installing with: yum install wireshark")
			} else if IsCommandInPath("brew") {
				errstr += fmt.Sprintf("Try installing with: brew install wireshark")
			}
			errstr += "\n"
			err := gowid.WithKVs(ConfigErr, map[string]interface{}{
				"msg": errstr,
			})
			return "", &err
		}
	}
	// Here we know it's in PATH
	tsharkBin = DirOfPathCommandUnsafe(tsharkBin)
	return tsharkBin, nil
}

//======================================================================

func TSharkBin() string {
	return profiles.ConfString("main.tshark", "tshark")
}

func DumpcapBin() string {
	return profiles.ConfString("main.dumpcap", "dumpcap")
}

func CapinfosBin() string {
	return profiles.ConfString("main.capinfos", "capinfos")
}

// SharkdBin returns the path to the sharkd binary.
func SharkdBin() string {
	return profiles.ConfString("main.sharkd", "sharkd")
}

// CaptureBin is the binary the user intends to use to capture
// packets i.e. with the -i switch. This might be distinct from
// DumpcapBin because dumpcap can't capture on extcap interfaces
// like randpkt, but while tshark can, it can drop packets more
// readily than dumpcap. This value is interpreted as the name
// of a binary, resolved against PATH. Note that the default is
// termshark - this invokes termshark in a special mode where it
// first tries DumpcapBin, then if that fails, TSharkBin - for
// the best of both worlds. To detect this, termshark will run
// CaptureBin with TERMSHARK_CAPTURE_MODE=1 in the environment,
// so when termshark itself is invoked with this in the environment,
// it switches to capture mode.
func CaptureBin() string {
	if runtime.GOOS == "windows" {
		return profiles.ConfString("main.capture-command", DumpcapBin())
	} else {
		return profiles.ConfString("main.capture-command", os.Args[0])
	}
}

// PrivilegedBin returns a capture binary that may require setcap
// privileges on Linux. This is a simple UI to cover the fact that
// termshark's default capture method is to run dumpcap and tshark
// as a fallback. I don't want to tell the user the capture binary
// is termshark - that'd be confusing. We know that on Linux, termshark
// will run dumpcap first, then fall back to tshark if needed. Only
// dumpcap should need access to live interfaces; tshark is needed
// for extcap interfaces only. This is used to provide advice to
// the user if packet capture fails.
func PrivilegedBin() string {
	cap := CaptureBin()
	if cap == "termshark" {
		return DumpcapBin()
	} else {
		return cap
	}
}

func TailCommand() []string {
	def := []string{"tail", "-f", "-c", "+0"}
	if runtime.GOOS == "windows" {
		def = []string{os.Args[0], "--tail"}
	}
	return profiles.ConfStringSlice("main.tail-command", def)
}

//======================================================================

var UnexpectedOutput = fmt.Errorf("Unexpected output")

// Use tshark's output, because the indices can then be used to select
// an interface to sniff on, and net.Interfaces returns the interfaces in
// a different order.
func Interfaces() (map[int][]string, error) {
	cmd := exec.Command(TSharkBin(), "-D")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return interfacesFrom(bytes.NewReader(out))
}

func interfacesFrom(reader io.Reader) (map[int][]string, error) {
	res := make(map[int][]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		match := interfaceRe.FindStringSubmatch(line)
		if len(match) < 2 {
			return nil, gowid.WithKVs(UnexpectedOutput, map[string]interface{}{"Output": line})
		}
		result := make(map[string]string)
		for i, name := range interfaceRe.SubexpNames() {
			if i != 0 && match[i] != "" {
				result[name] = match[i]
			}
		}

		i, err := strconv.ParseInt(result["index"], 10, 32)
		if err != nil {
			return nil, gowid.WithKVs(UnexpectedOutput, map[string]interface{}{"Output": line})
		}

		val := make([]string, 0)
		val = append(val, result["name1"])

		if name2, ok := result["name2"]; ok {
			val = append([]string{name2}, val...)
		}
		res[int(i)] = val
	}

	return res, nil
}

//======================================================================

var foldersRE = regexp.MustCompile(`:\s*`)

// $ env TMPDIR=/foo tshark -G folders Temp
// Temp:                   /foo
// Personal configuration: /home/gcla/.config/wireshark
// Global configuration:   /usr/share/wireshark
func TsharkSetting(field string) (string, error) {
	res, err := TsharkSettings(field)
	if err != nil {
		return "", err
	}

	val, ok := res[field]
	if !ok {
		return "", fmt.Errorf("Field %s not found in output of tshark -G folders", field)
	}

	return val, nil
}

func TsharkSettings(fields ...string) (map[string]string, error) {
	out, err := exec.Command(TSharkBin(), []string{"-G", "folders"}...).Output()
	if err != nil {
		return nil, err
	}

	res := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		pieces := foldersRE.Split(line, 2)
		for _, field := range fields {
			if len(pieces) == 2 && pieces[0] == field {
				res[field] = pieces[1]
			}
		}
	}

	return res, nil
}

//======================================================================

func WiresharkProfileNames() []string {
	res := make([]string, 0, 8)
	folders, _ := TsharkSettings("Personal configuration", "Global configuration")
	for _, folder := range folders {
		profFolder := filepath.Join(folder, "profiles")

		files, err := os.ReadDir(profFolder)
		if err != nil {
			log.Warnf("Could not read wireshark config folder %s: %v", profFolder, err)
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				res = append(res, file.Name())
			}
		}
	}
	return res
}

//======================================================================

// From http://blog.kamilkisiel.net/blog/2012/07/05/using-the-go-regexp-package/
type tsregexp struct {
	*regexp.Regexp
}

func (r *tsregexp) FindStringSubmatchMap(s string) map[string]string {
	captures := make(map[string]string)

	match := r.FindStringSubmatch(s)
	if match == nil {
		return captures
	}

	for i, name := range r.SubexpNames() {
		if i == 0 {
			continue
		}
		captures[name] = match[i]
	}

	return captures
}

var flagRE = tsregexp{regexp.MustCompile(`--tshark-(?P<flag>[a-zA-Z0-9])=(?P<val>.+)`)}

func ConvertArgToTShark(arg string) (string, string, bool) {
	matches := flagRE.FindStringSubmatchMap(arg)
	if flag, ok := matches["flag"]; ok {
		if val, ok := matches["val"]; ok {
			if val == "false" {
				return "", "", false
			} else if val == "true" {
				return flag, "", true
			} else {
				return flag, val, true
			}
		}
	}
	return "", "", false
}
