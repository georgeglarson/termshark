// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/widgets/wormhole"
	log "github.com/sirupsen/logrus"
)

//======================================================================

// CurrentWormholeWidget is deprecated: use UI.Features.CurrentWormholeWidget
var CurrentWormholeWidget *wormhole.Widget

// getWormholeWidget returns the current wormhole widget from UIState or the old global.
func getWormholeWidget() *wormhole.Widget {
	if UI != nil && UI.Features != nil && UI.Features.CurrentWormholeWidget != nil {
		return UI.Features.CurrentWormholeWidget
	}
	return CurrentWormholeWidget
}

// setWormholeWidget sets the wormhole widget in both UIState and the old global.
func setWormholeWidget(w *wormhole.Widget) {
	if UI != nil && UI.Features != nil {
		UI.Features.CurrentWormholeWidget = w
	}
	CurrentWormholeWidget = w // keep old global in sync during transition
}

func openWormhole(app gowid.IApp) {
	wormholeWidget := getWormholeWidget()

	var numWords int
	if wormholeWidget == nil {
		numWords = profiles.ConfInt("main.wormhole-length", 2)
	} else {
		numWords = wormholeWidget.CodeLength()
	}

	if wormholeWidget == nil {
		var err error
		wormholeWidget, err = wormhole.New(Loader.PcapPdml, app, wormhole.Options{
			ErrorHandler: func(err error, app gowid.IApp) {
				msg := fmt.Sprintf("Problem sending pcap: %v", err)
				log.Error(msg)
				OpenError(msg, app)
			},
			CodeLength:          numWords,
			TransitRelayAddress: profiles.ConfString("main.wormhole-transit-relay", ""),
			RendezvousURL:       profiles.ConfString("main.wormhole-rendezvous-url", ""),
		})
		if err != nil {
			msg := fmt.Sprintf("%v", err)
			log.Error(msg)
			OpenError(msg, app)
			return
		}
		setWormholeWidget(wormholeWidget)
	}

	wormholeDialog := dialog.New(
		framed.NewSpace(
			wormholeWidget,
		),
		dialog.Options{
			Buttons:         []dialog.Button{dialog.CloseD},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)

	// space for the frame; then XXX-word1-word2-... - max length of word in
	// pgp word list is 11. Yuck.
	maxl := (2 * 3) + len(" - cancelled!") + wormhole.UpperBoundOnLength(numWords)

	wormholeDialog.Open(appView, ratioupto(0.8, maxl), app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
