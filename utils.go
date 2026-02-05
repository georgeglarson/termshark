// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"slices"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2/pkg/lifecycle"
	"github.com/gdamore/tcell/v2"
	"github.com/gdamore/tcell/v2/terminfo"
	"github.com/gdamore/tcell/v2/terminfo/dynamic"
	"github.com/mattn/go-isatty"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type BadStateError struct{}

var _ error = BadStateError{}

func (e BadStateError) Error() string {
	return "Bad state"
}

var BadState = BadStateError{}

//======================================================================

type BadCommandError struct{}

var _ error = BadCommandError{}

func (e BadCommandError) Error() string {
	return "Error running command"
}

var BadCommand = BadCommandError{}

//======================================================================

type ConfigError struct{}

var _ error = ConfigError{}

func (e ConfigError) Error() string {
	return "Configuration error"
}

var ConfigErr = ConfigError{}

//======================================================================

type InternalError struct{}

var _ error = InternalError{}

func (e InternalError) Error() string {
	return "Internal error"
}

var InternalErr = InternalError{}

//======================================================================

const (
	UserGuideURL = "https://github.com/georgeglarson/termshark/blob/master/docs/UserGuide.md"
	FAQURL       = "https://github.com/georgeglarson/termshark/blob/master/docs/FAQ.md"
	BugURL       = "https://github.com/georgeglarson/termshark/issues/new?assignees=&labels=&template=bug_report.md&title="
	FeatureURL   = "https://github.com/georgeglarson/termshark/issues/new?assignees=&labels=&template=feature_request.md&title="
)

var (
	OriginalEnv          []string
	ShouldSwitchTerminal bool
	ShouldSwitchBack     bool
	unitsRe              *regexp.Regexp = regexp.MustCompile(`^([0-9,]+)\s*(bytes|kB|MB)?`)
	tsharkVersionRe      *regexp.Regexp = regexp.MustCompile(`^TShark .*?(\d+\.\d+\.\d+)`)
	interfaceRe          *regexp.Regexp = regexp.MustCompile(`^(?P<index>[0-9]+)\.\s+(?P<name1>[^\s]+)(\s*\((?P<name2>[^)]+)\))?`)
	argRe                *regexp.Regexp = regexp.MustCompile(`^\$([1-9][0-9]{0,4})$`)
)

//======================================================================

func ReverseStringSlice(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}


func KeyPressIsPrintable(key gowid.IKey) bool {
	return unicode.IsPrint(key.Rune()) && key.Modifiers() & ^tcell.ModShift == 0
}



// Must succeed - use on internal templates
func TemplateToString(tmpl *template.Template, name string, data interface{}) string {
	var res bytes.Buffer
	if err := tmpl.ExecuteTemplate(&res, name, data); err != nil {
		log.Fatal(err)
	}

	return res.String()
}

func StringIsArgPrefixOf(a string, list []string) bool {
	for _, b := range list {
		if strings.HasPrefix(a, fmt.Sprintf("%s=", b)) {
			return true
		}
	}
	return false
}

func RunOnDoubleTicker(ch <-chan struct{}, fn func(), dur1 time.Duration, dur2 time.Duration, loops int) {
	ctx := Context()
	ticker := time.NewTicker(dur1)
	counter := 0
Loop:
	for {
		select {
		case <-ticker.C:
			fn()
			counter++
			if counter == loops {
				ticker.Stop()
				ticker = time.NewTicker(dur2)
			}
		case <-ch:
			ticker.Stop()
			break Loop
		case <-ctx.Done():
			ticker.Stop()
			break Loop
		}
	}
}

// globalTracker is the centralized goroutine lifecycle tracker.
// Set via SetTracker() from main().
var globalTracker *lifecycle.Tracker

// SetTracker sets the global lifecycle tracker. Call this from main()
// before starting any goroutines.
func SetTracker(t *lifecycle.Tracker) {
	globalTracker = t
}

// Tracker returns the global lifecycle tracker.
func Tracker() *lifecycle.Tracker {
	return globalTracker
}

// TrackedGo starts a goroutine tracked by the provided WaitGroups.
// Deprecated: Use Tracker().Go() instead when globalTracker is set.
func TrackedGo(fn func(), wgs ...*sync.WaitGroup) {
	for _, wg := range wgs {
		wg.Add(1)
	}
	go func() {
		for _, wg := range wgs {
			defer wg.Done()
		}
		fn()
	}()
}

// Go starts a tracked goroutine using the global tracker.
// This is the preferred way to start goroutines.
func Go(fn func()) {
	if globalTracker != nil {
		globalTracker.Go(fn)
	} else {
		// Fallback if tracker not set (shouldn't happen in normal operation)
		go fn()
	}
}

// GoWithContext starts a tracked goroutine and provides the tracker's context.
// The function should monitor ctx.Done() for shutdown signals.
func GoWithContext(fn func(ctx context.Context)) {
	if globalTracker != nil {
		globalTracker.GoWithContext(fn)
	} else {
		// Fallback if tracker not set
		go fn(context.Background())
	}
}

// Context returns the global tracker's context, or a background context if
// the tracker is not set. Useful for goroutines that need to detect shutdown.
func Context() context.Context {
	if globalTracker != nil {
		return globalTracker.Context()
	}
	return context.Background()
}

//======================================================================

func ErrLogger(key string, val string) *io.PipeWriter {
	l := log.StandardLogger()
	return log.NewEntry(l).WithField(key, val).WriterLevel(log.ErrorLevel)
}

// KeyValueErrorString returns a string representation of
// a gowid KeyValueError intended to be suitable for displaying in
// a termshark error dialog.
func KeyValueErrorString(err gowid.KeyValueError) string {
	res := fmt.Sprintf("%v\n\n", err.Cause())
	kvs := make([]string, 0, len(err.KeyVals))
	ks := make([]string, 0, len(err.KeyVals))
	for k := range err.KeyVals {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	for _, k := range ks {
		kvs = append(kvs, fmt.Sprintf("%v: %v", k, err.KeyVals[k]))
	}
	res = res + strings.Join(kvs, "\n\n")
	return res
}

//======================================================================

func IsTerminal(fd uintptr) bool {
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

//======================================================================

type pdmlany struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Comment string     `xml:",comment"`
	Nested  []*pdmlany `xml:",any"`
	//Content string     `xml:",chardata"`
}

// IndentPdml reindents XML, disregarding content between tags (because we knoe
// PDML doesn't use that capability of XML)
func IndentPdml(in io.Reader, out io.Writer) error {
	decoder := xml.NewDecoder(in)

	n := pdmlany{}
	if err := decoder.Decode(&n); err != nil {
		return err
	}

	b, err := xml.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	out.Write(fixNewlines(b))
	return nil
}

func fixNewlines(unix []byte) []byte {
	if runtime.GOOS != "windows" {
		return unix
	}

	return bytes.Replace(unix, []byte{'\n'}, []byte{'\r', '\n'}, -1)
}

//======================================================================

type iWrappedError interface {
	Cause() error
}

func RootCause(err error) error {
	res := err
	for {
		if cerr, ok := res.(iWrappedError); ok {
			res = cerr.Cause()
		} else {
			break
		}
	}
	return res
}

//======================================================================

func RunningRemotely() bool {
	return os.Getenv("SSH_TTY") != ""
}

//======================================================================

type KeyState struct {
	NumberPrefix    int
	PartialgCmd     bool
	PartialZCmd     bool
	PartialCtrlWCmd bool
	PartialmCmd     bool
	PartialQuoteCmd bool
}

//======================================================================

func Does256ColorTermExist() error {
	return ValidateTerm(fmt.Sprintf("%s-256color", os.Getenv("TERM")))
}

func ValidateTerm(term string) error {
	var err error
	_, err = terminfo.LookupTerminfo(term)
	if err != nil {
		_, _, err = dynamic.LoadTerminfo(term)
	}
	return err
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
