// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bufio"
	"encoding/xml"
	"errors"
	"io"
	"strconv"

	"github.com/gcla/termshark/v2/pkg/format"
)

//======================================================================

// PsmlPacketData holds the parsed data for a single PSML packet
type PsmlPacketData struct {
	Fields []string
	FG     string
	BG     string
}

// PsmlParseResult contains the complete result of parsing PSML XML
type PsmlParseResult struct {
	Headers       []string
	Packets       []PsmlPacketData
	PacketNumbers []int // The packet number (frame number) for each packet
}

// ParsePdmlPackets parses PDML XML from a reader, extracting packet elements.
// If maxPackets > 0, parsing stops after that many packets.
// If compress is true, packets are snappy-compressed for storage efficiency.
// Returns the parsed packets and any error encountered.
func ParsePdmlPackets(r io.Reader, maxPackets int, compress bool) ([]IPdmlPacket, error) {
	d := xml.NewDecoder(r)
	packets := make([]IPdmlPacket, 0)

	var packet PdmlPacket
	var cpacket IPdmlPacket

	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return packets, nil
			}
			// Check for expected EOF-like errors from XML parsing
			if syntaxErr, ok := err.(*xml.SyntaxError); ok {
				if syntaxErr.Msg == "unexpected EOF" {
					return packets, nil
				}
			}
			return packets, err
		}

		switch tok := tok.(type) {
		case xml.StartElement:
			if tok.Name.Local == "packet" {
				err := d.DecodeElement(&packet, &tok)
				if err != nil {
					if errors.Is(err, io.EOF) {
						return packets, nil
					}
					if syntaxErr, ok := err.(*xml.SyntaxError); ok {
						if syntaxErr.Msg == "unexpected EOF" {
							return packets, nil
						}
					}
					return packets, err
				}

				if compress {
					cpacket = SnappyPdmlPacket(packet)
				} else {
					cpacket = packet
				}
				packets = append(packets, cpacket)

				if maxPackets > 0 && len(packets) >= maxPackets {
					return packets, nil
				}
			}
		}
	}
}

// ParsePcapHexDump parses tshark hex dump output (from -x flag) from a reader.
// Each packet's hex bytes are separated by a blank line.
// If maxPackets > 0, parsing stops after that many packets.
// Returns the parsed packets (as byte slices) and any error encountered.
func ParsePcapHexDump(r io.Reader, maxPackets int) ([][]byte, error) {
	packets := make([][]byte, 0)
	packet := make([]byte, 0)
	rd := bufio.NewReader(r)

	for {
		line, err := rd.ReadString('\n')

		// Process the line first, even if there's an error (EOF with partial line)
		parseResults := hexByteRe.FindAllStringSubmatch(line, -1)

		if len(parseResults) < 1 {
			// Blank line or non-hex line indicates end of packet
			if len(packet) > 0 {
				packets = append(packets, packet)
				packet = make([]byte, 0)

				if maxPackets > 0 && len(packets) >= maxPackets {
					return packets, nil
				}
			}
		} else {
			// Parse hex bytes from this line (skip the line number which is parseResults[0])
			for _, parsedByte := range parseResults[1:] {
				b, parseErr := strconv.ParseUint(parsedByte[0][0:2], 16, 8)
				if parseErr != nil {
					return packets, parseErr
				}
				packet = append(packet, byte(b))
			}
		}

		// Now check for read errors after processing the line
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Don't lose the last packet if there's no trailing newline
				if len(packet) > 0 {
					packets = append(packets, packet)
				}
				return packets, nil
			}
			return packets, err
		}
	}
}

// ParsePsmlXML parses PSML XML from a reader.
// PSML format contains a <structure> element with column headers,
// followed by <packet> elements with <section> children for each column.
// Returns the parsed result and any error encountered.
func ParsePsmlXML(r io.Reader) (*PsmlParseResult, error) {
	result := &PsmlParseResult{
		Headers:       make([]string, 0),
		Packets:       make([]PsmlPacketData, 0),
		PacketNumbers: make([]int, 0),
	}

	d := xml.NewDecoder(r)

	var curPsml []string
	var fg, bg string
	ready := false
	empty := true
	structure := false

	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return result, nil
			}
			return result, err
		}

		switch tok := tok.(type) {
		case xml.EndElement:
			switch tok.Name.Local {
			case "structure":
				structure = false
			case "packet":
				if len(curPsml) > 0 {
					// First field is the packet number
					packetNum, err := strconv.Atoi(curPsml[0])
					if err != nil {
						return result, err
					}
					result.PacketNumbers = append(result.PacketNumbers, packetNum)
					result.Packets = append(result.Packets, PsmlPacketData{
						Fields: curPsml[1:], // Skip the packet number field
						FG:     fg,
						BG:     bg,
					})
				}
			case "section":
				ready = false
				if empty {
					curPsml = append(curPsml, "")
				}
			}

		case xml.StartElement:
			switch tok.Name.Local {
			case "structure":
				structure = true
			case "packet":
				curPsml = make([]string, 0, 10)
				fg = ""
				bg = ""
				for _, attr := range tok.Attr {
					switch attr.Name.Local {
					case "foreground":
						fg = attr.Value
					case "background":
						bg = attr.Value
					}
				}
			case "section":
				ready = true
				empty = true
			}

		case xml.CharData:
			if ready {
				if structure {
					result.Headers = append(result.Headers, string(tok))
				} else {
					curPsml = append(curPsml, string(format.TranslateHexCodes(tok)))
					empty = false
				}
			}
		}
	}
}

// ParsePsmlColors converts foreground/background color strings to PacketColors.
// Returns nil for FG/BG if the color string is empty or invalid.
func ParsePsmlColors(fg, bg string) PacketColors {
	return PacketColors{
		FG: psmlColorToIColor(fg),
		BG: psmlColorToIColor(bg),
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
