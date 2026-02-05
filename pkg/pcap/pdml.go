// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/mreiferson/go-snappystream"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type IPdmlPacket interface {
	Packet() PdmlPacket
}

type PdmlPacket struct {
	XMLName xml.Name `xml:"packet"`
	Content []byte   `xml:",innerxml"`
}

var _ IPdmlPacket = PdmlPacket{}

func (p PdmlPacket) Packet() PdmlPacket {
	return p
}

//======================================================================

type GzippedPdmlPacket struct {
	Data bytes.Buffer
}

var _ IPdmlPacket = GzippedPdmlPacket{}

func (p GzippedPdmlPacket) Packet() PdmlPacket {
	return p.Uncompress()
}

func (p GzippedPdmlPacket) Uncompress() PdmlPacket {
	greader, err := gzip.NewReader(&p.Data)
	if err != nil {
		log.Warnf("Failed to create gzip reader for cached packet: %v", err)
		return PdmlPacket{}
	}
	decoder := gob.NewDecoder(greader)
	var res PdmlPacket
	err = decoder.Decode(&res)
	if err != nil {
		log.Warnf("Failed to decode cached packet: %v", err)
		return PdmlPacket{}
	}

	return res
}

func GzipPdmlPacket(p PdmlPacket) IPdmlPacket {
	res := GzippedPdmlPacket{}
	gwriter := gzip.NewWriter(&res.Data)
	encoder := gob.NewEncoder(gwriter)
	err := encoder.Encode(p)
	if err != nil {
		log.Warnf("Failed to encode packet for cache: %v", err)
		return p // return uncompressed as fallback
	}
	if err := gwriter.Close(); err != nil {
		log.Warnf("Failed to close gzip writer: %v", err)
		return p
	}
	return res
}

//======================================================================

type SnappiedPdmlPacket struct {
	Data bytes.Buffer
}

var _ IPdmlPacket = SnappiedPdmlPacket{}

func (p SnappiedPdmlPacket) Packet() PdmlPacket {
	return p.Uncompress()
}

func (p SnappiedPdmlPacket) Uncompress() PdmlPacket {
	var res PdmlPacket
	if err := UnsnappyMe(&res, &p.Data); err != nil {
		log.Warnf("Failed to decompress cached packet: %v", err)
		return PdmlPacket{}
	}
	return res
}

func SnappyPdmlPacket(p PdmlPacket) IPdmlPacket {
	res := SnappiedPdmlPacket{}
	if err := SnappyMe(p, &res.Data); err != nil {
		log.Warnf("Failed to compress packet for cache: %v", err)
		return p // return uncompressed as fallback
	}
	return res
}

//======================================================================

// SnappyMe compresses the object within interface p to the
// writer w.
func SnappyMe(p any, w io.Writer) error {
	gwriter := snappystream.NewBufferedWriter(w)
	encoder := gob.NewEncoder(gwriter)
	if err := encoder.Encode(p); err != nil {
		return fmt.Errorf("snappy encode: %w", err)
	}
	if err := gwriter.Close(); err != nil {
		return fmt.Errorf("snappy close: %w", err)
	}
	return nil
}

// UnsnappyMe decompresses from reader r into res. Afterwards,
// res will be an interface whose type is a pointer to whatever
// was serialized in the first place.
func UnsnappyMe(res any, r io.Reader) error {
	greader := snappystream.NewReader(r, false)
	decoder := gob.NewDecoder(greader)
	if err := decoder.Decode(res); err != nil {
		return fmt.Errorf("snappy decode: %w", err)
	}
	return nil
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
