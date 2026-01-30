// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

//======================================================================

type CacheEntry struct {
	Pdml         []IPdmlPacket
	Pcap         [][]byte
	PdmlComplete bool
	PcapComplete bool
}

func (c CacheEntry) Complete() bool {
	return c.PdmlComplete && c.PcapComplete
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
