// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package main


import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/adrg/xdg"
	"github.com/blang/semver"
	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/fields"
	"github.com/gcla/termshark/v2/ui"
	"github.com/mattn/go-isatty"
	log "github.com/sirupsen/logrus"
)

func setupConfigDirs() string {
	cacheDir := filepath.Join(xdg.CacheHome, "termshark")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create cache dir: %v\n", err)
	}
	configDir := filepath.Join(xdg.ConfigHome, "termshark")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create config dir: %v\n", err)
	} else {
		if err = os.MkdirAll(filepath.Join(configDir, "profiles"), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create profiles dir: %v\n", err)
		}
	}
	return configDir
}

// setupLogging configures the logging output, either to a file or to stderr.
func setupLogging(logToTty bool) error {
	if !logToTty {
		logfile := termshark.CacheFile("termshark.log")
		logfd, err := os.OpenFile(logfile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			return fmt.Errorf("could not create log file %s: %w", logfile, err)
		}
		// Don't close it - just let the descriptor be closed at exit. logrus is used
		// in many places, some outside of this main function, and closing results in
		// an error often on freebsd.
		log.SetOutput(logfd)
	}
	return nil
}

// validateTsharkBinary checks that the tshark binary exists and is a supported version.
// Returns the path to the tshark binary.
func validateTsharkBinary() (string, error) {
	tsharkBin, kverr := termshark.TSharkPath()
	if kverr != nil {
		return "", fmt.Errorf(kverr.KeyVals["msg"].(string))
	}

	valids := profiles.ConfStrings("main.validated-tsharks")

	if !slices.Contains(valids, tsharkBin) {
		tver, err := termshark.TSharkVersion(tsharkBin)
		if err != nil {
			return "", fmt.Errorf("could not determine tshark version: %w", err)
		}
		// This is the earliest version that gives reliable results in termshark.
		mver, _ := semver.Make("1.10.2")
		if tver.LT(mver) {
			return "", fmt.Errorf("termshark will not operate correctly with a tshark older than %v (found %v)", mver, tver)
		}

		valids = append(valids, tsharkBin)
		profiles.SetConf("main.validated-tsharks", valids)
	}

	// If the last tshark we used isn't the same as the current one, then remove the cached fields
	// data structure so it can be regenerated.
	if tsharkBin != profiles.ConfString("main.last-used-tshark", "") {
		fields.DeleteCachedFields()
	}

	// Write out the last-used tshark path.
	profiles.SetConf("main.last-used-tshark", tsharkBin)

	return tsharkBin, nil
}

// checkTsharkColorSupport determines if the current tshark binary supports color output.
func checkTsharkColorSupport(tsharkBin string) bool {
	colorTsharks := profiles.ConfStrings("main.color-tsharks")

	if slices.Contains(colorTsharks, tsharkBin) {
		return true
	}

	supported, err := termshark.TSharkSupportsColor(tsharkBin)
	if err != nil {
		return false
	}

	if supported {
		colorTsharks = append(colorTsharks, tsharkBin)
		profiles.SetConf("main.color-tsharks", colorTsharks)
	}

	return supported
}

// createCacheDirs creates the necessary cache directories for termshark.
func createCacheDirs() error {
	for _, dir := range []string{termshark.CacheDir(), termshark.DefaultPcapDir(), termshark.PcapDir()} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("unexpected error making dir %s: %w", dir, err)
		}
	}

	// Write the empty pcap file used for color validation
	emptyPcap := termshark.CacheFile("empty.pcap")
	if _, err := os.Stat(emptyPcap); os.IsNotExist(err) {
		if err = termshark.WriteEmptyPcap(emptyPcap); err != nil {
			return fmt.Errorf("could not create dummy pcap %s: %w", emptyPcap, err)
		}
	}

	return nil
}

// validateTTY validates the specified TTY device, returning the path to use.
// If ttyPath is empty, returns the default "/dev/tty".
func validateTTY(ttyPath string) (string, error) {
	if ttyPath != "" {
		ttyf, err := os.Open(ttyPath)
		if err != nil {
			return "", fmt.Errorf("could not open terminal %s: %w", ttyPath, err)
		}
		defer ttyf.Close()

		if !isatty.IsTerminal(ttyf.Fd()) {
			return "", fmt.Errorf("%s is not a terminal", ttyPath)
		}
		return ttyPath, nil
	}
	// Always override - in case the user has GOWID_TTY in a shell script
	return "/dev/tty", nil
}

// applyTermOverride applies the TERM environment variable override from config.
func applyTermOverride() {
	termVar := profiles.ConfString("main.term", "")
	if termVar != "" {
		fmt.Fprintf(os.Stderr, "Configuration file overrides TERM setting, using TERM=%s\n", termVar)
		os.Setenv("TERM", termVar)
	}
}

// initUIState initializes the UI state from configuration settings.
func initUIState() {
	ui.InitDarkMode(profiles.ConfBool("main.dark-mode", true))
	ui.InitAutoScroll(profiles.ConfBool("main.auto-scroll", true))
	ui.InitPacketColors(profiles.ConfBool("main.packet-colors", true))
}

// loadTsharkArgs loads the tshark command-line arguments from configuration.
func loadTsharkArgs(timestampFormat string) (pdmlArgs, psmlArgs, tsharkArgs []string) {
	pdmlArgs = profiles.ConfStringSlice("main.pdml-args", []string{})
	psmlArgs = profiles.ConfStringSlice("main.psml-args", []string{})
	if timestampFormat != "" {
		psmlArgs = append(psmlArgs, "-t", timestampFormat)
	}
	tsharkArgs = profiles.ConfStringSlice("main.tshark-args", []string{})
	return
}

// loadCacheSettings loads pcap cache configuration settings.
func loadCacheSettings() (cacheSize, bundleSize int) {
	cacheSize = profiles.ConfInt("main.pcap-cache-size", 64)
	bundleSize = profiles.ConfInt("main.pcap-bundle-size", 1000)
	if bundleSize <= 0 {
		maxBundleSize := 100000
		log.Infof("Config specifies pcap-bundle-size as %d - setting to max (%d)", bundleSize, maxBundleSize)
		bundleSize = maxBundleSize
	}
	return
}

func configureBase16Colors() {
	// Determine whether to ignore base16 color remapping
	if profiles.ConfKeyExists("main.ignore-base16-colors") {
		gowid.IgnoreBase16 = profiles.ConfBool("main.ignore-base16-colors", false)
	} else {
		// Try to auto-detect whether or not base16-shell is installed and in-use
		gowid.IgnoreBase16 = (os.Getenv("BASE16_SHELL") != "")
	}

	if gowid.IgnoreBase16 {
		log.Infof("Will not consider colors 0-21 from the terminal 256-color-space when interpolating theme colors")
		// If main.respect-colorterm=true then termshark will leave COLORTERM set and use
		// 24-bit color if possible. The problem with this, in the presence of base16, is that
		// some terminal-emulators still map RGB ANSI codes to colors 0-21 in the 256-color space.
		// Termshark will fall back to 256-colors if base16 is detected.
		if os.Getenv("COLORTERM") != "" && !profiles.ConfBool("main.respect-colorterm", false) {
			log.Infof("Pessimistically disabling 24-bit color to avoid conflicts with base16")
			os.Unsetenv("COLORTERM")
		}
	}
}

