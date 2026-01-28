// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/capinfo"
	"github.com/gcla/termshark/v2/pkg/pcap"
	log "github.com/sirupsen/logrus"
)

// CapinfoLoader is deprecated: use UI.Features.CapinfoLoader
var CapinfoLoader *capinfo.Loader

// CapinfoData is deprecated: use UI.Features.CapinfoData
var CapinfoData string

// CapinfoTime is deprecated: use UI.Features.CapinfoTime
var CapinfoTime time.Time

// getCapinfoLoader returns the capinfo loader from UIState or the old global.
func getCapinfoLoader() *capinfo.Loader {
	if UI != nil && UI.Features != nil && UI.Features.CapinfoLoader != nil {
		return UI.Features.CapinfoLoader
	}
	return CapinfoLoader
}

// setCapinfoLoader sets the capinfo loader in both UIState and the old global.
func setCapinfoLoader(l *capinfo.Loader) {
	if UI != nil && UI.Features != nil {
		UI.Features.CapinfoLoader = l
	}
	CapinfoLoader = l
}

// getCapinfoData returns the capinfo data from UIState or the old global.
func getCapinfoData() string {
	if UI != nil && UI.Features != nil && UI.Features.CapinfoData != "" {
		return UI.Features.CapinfoData
	}
	return CapinfoData
}

// setCapinfoData sets the capinfo data in both UIState and the old global.
func setCapinfoData(data string) {
	if UI != nil && UI.Features != nil {
		UI.Features.CapinfoData = data
	}
	CapinfoData = data
}

// getCapinfoTime returns the capinfo time from UIState or the old global.
func getCapinfoTime() time.Time {
	if UI != nil && UI.Features != nil && !UI.Features.CapinfoTime.IsZero() {
		return UI.Features.CapinfoTime
	}
	return CapinfoTime
}

// setCapinfoTime sets the capinfo time in both UIState and the old global.
func setCapinfoTime(t time.Time) {
	if UI != nil && UI.Features != nil {
		UI.Features.CapinfoTime = t
	}
	CapinfoTime = t
}

//======================================================================

func startCapinfo(app gowid.IApp) {
	if Loader.PcapPdml == "" {
		OpenError("No pcap loaded.", app)
		return
	}

	fi, err := os.Stat(Loader.PcapPdml)
	if err != nil || getCapinfoTime().Before(fi.ModTime()) {
		loader := capinfo.NewLoader(capinfo.MakeCommands(), Loader.Context())
		setCapinfoLoader(loader)

		handler := capinfoParseHandler{}

		loader.StartLoad(
			Loader.PcapPdml,
			app,
			&handler,
		)
	} else {
		OpenMessageForCopy(getCapinfoData(), appView, app)
	}
}

//======================================================================

type capinfoParseHandler struct {
	tick             *time.Ticker // for updating the spinner
	stop             chan struct{}
	pleaseWaitClosed bool
}

var _ capinfo.ICapinfoCallbacks = (*capinfoParseHandler)(nil)
var _ pcap.IBeforeBegin = (*capinfoParseHandler)(nil)
var _ pcap.IAfterEnd = (*capinfoParseHandler)(nil)

func (t *capinfoParseHandler) OnCapinfoData(data string) {
	setCapinfoData(strings.ReplaceAll(data, "\r\n", "\n")) // For windows...
	fi, err := os.Stat(Loader.PcapPdml)
	if err != nil {
		log.Warnf("Could not read mtime from pcap %s: %v", Loader.PcapPdml, err)
	} else {
		setCapinfoTime(fi.ModTime())
	}
}

func (t *capinfoParseHandler) AfterCapinfoEnd(success bool) {
}

func (t *capinfoParseHandler) BeforeBegin(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.CapinfoCode == 0 {
		return
	}
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		OpenPleaseWait(appView, app)
	}))

	t.tick = time.NewTicker(time.Duration(200) * time.Millisecond)
	t.stop = make(chan struct{})

	termshark.GoWithContext(func(ctx context.Context) {
	Loop:
		for {
			select {
			case <-t.tick.C:
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					pleaseWaitSpinner.Update()
				}))
			case <-t.stop:
				break Loop
			case <-ctx.Done():
				break Loop
			}
		}
	})
}

func (t *capinfoParseHandler) AfterEnd(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.CapinfoCode == 0 {
		return
	}
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		if !t.pleaseWaitClosed {
			t.pleaseWaitClosed = true
			ClosePleaseWait(app)
		}

		OpenMessageForCopy(getCapinfoData(), appView, app)
	}))
	close(t.stop)
}

//======================================================================

func clearCapinfoState() {
	setCapinfoTime(time.Time{})
}

//======================================================================

type ManageCapinfoCache struct{}

var _ pcap.INewSource = ManageCapinfoCache{}
var _ pcap.IClear = ManageCapinfoCache{}

// Make sure that existing stream widgets are discarded if the user loads a new pcap.
func (t ManageCapinfoCache) OnNewSource(pcap.HandlerCode, gowid.IApp) {
	clearCapinfoState()
}

func (t ManageCapinfoCache) OnClear(pcap.HandlerCode, gowid.IApp) {
	clearCapinfoState()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
