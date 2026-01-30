// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/adam-hanna/arrayOperations"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/vim"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/generic"
	"github.com/gcla/termshark/v2/widgets/resizable"
	"github.com/adrg/xdg"
	log "github.com/sirupsen/logrus"
)

//======================================================================

func ConfFile(file string) string {
	return filepath.Join(xdg.ConfigHome, "termshark", file)
}

func CacheFile(bin string) string {
	return filepath.Join(CacheDir(), bin)
}

func CacheDir() string {
	return filepath.Join(xdg.CacheHome, "termshark")
}

// A separate dir from CacheDir because I need to use inotify under some
// circumstances for a non-existent file, meaning I need to track a directory,
// and I don't want to be constantly triggered by log file updates.
func PcapDir() string {
	var res string
	// If use-tshark-temp-for-cache is set, use that
	if profiles.ConfBool("main.use-tshark-temp-for-pcap-cache", false) {
		tmp, err := TsharkSetting("Temp")
		if err == nil {
			res = tmp
		}
	}
	// Otherwise try the user's preference
	if res == "" {
		res = profiles.ConfString("main.pcap-cache-dir", "")
	}
	if res == "" {
		res = DefaultPcapDir()
	}
	return res
}

// DefaultPcapDir returns ~/.cache/pcaps by default. Termshark will check a
// couple of user settings first before using this.
func DefaultPcapDir() string {
	return filepath.Join(CacheDir(), "pcaps")
}

//======================================================================

type KeyMapping struct {
	From vim.KeyPress
	To   vim.KeySequence
}

func AddKeyMapping(km KeyMapping) {
	mappings := LoadKeyMappings()
	newMappings := make([]KeyMapping, 0)
	for _, mapping := range mappings {
		if mapping.From != km.From {
			newMappings = append(newMappings, mapping)
		}
	}
	newMappings = append(newMappings, km)
	SaveKeyMappings(newMappings)
}

func RemoveKeyMapping(kp vim.KeyPress) {
	mappings := LoadKeyMappings()
	newMappings := make([]KeyMapping, 0)
	for _, mapping := range mappings {
		if mapping.From != kp {
			newMappings = append(newMappings, mapping)
		}
	}
	SaveKeyMappings(newMappings)
}

func LoadKeyMappings() []KeyMapping {
	mappings := profiles.ConfStringSlice("main.key-mappings", []string{})
	res := make([]KeyMapping, 0)
	for _, mapping := range mappings {
		pair := strings.Split(mapping, " ")
		if len(pair) != 2 {
			log.Warnf("Could not parse vim key mapping (missing separator?): %s", mapping)
			continue
		}
		from := vim.VimStringToKeys(pair[0])
		if len(from) != 1 {
			log.Warnf("Could not parse 'source' vim keypress: %s", pair[0])
			continue
		}
		to := vim.VimStringToKeys(pair[1])
		if len(to) < 1 {
			log.Warnf("Could not parse 'target' vim keypresses: %s", pair[1])
			continue
		}
		res = append(res, KeyMapping{From: from[0], To: to})
	}
	return res
}

func SaveKeyMappings(mappings []KeyMapping) {
	ser := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		ser = append(ser, fmt.Sprintf("%v %v", mapping.From, vim.KeySequence(mapping.To)))
	}
	profiles.SetConf("main.key-mappings", ser)
}

//======================================================================

// RemoveFromStringSlice removes element from comps and prepends it.
// Deprecated: Use generic.MoveToFront instead.
func RemoveFromStringSlice(element string, comps []string) []string {
	return generic.MoveToFront(comps, element)
}

//======================================================================

func SetConvTypes(convs []string) {
	profiles.SetConf("main.conv-types", convs)
}

func ConvTypes() []string {
	defs := []string{"eth", "ip", "ipv6", "tcp", "udp"}
	ctypes := profiles.ConfStrings("main.conv-types")
	if len(ctypes) > 0 {
		z, ok := arrayOperations.Intersect(defs, ctypes)
		if ok {
			res, ok := z.Interface().([]string)
			if ok {
				return res
			}
		}
	}
	return defs
}

func AddToRecentFiles(pcap string) {
	comps := profiles.ConfStrings("main.recent-files")
	if len(comps) == 0 || comps[0] != pcap {
		comps = RemoveFromStringSlice(pcap, comps)
		if len(comps) > 16 {
			comps = comps[0 : 16-1]
		}
		profiles.SetConf("main.recent-files", comps)
	}
}

func AddToRecentFilters(val string) {
	addToRecent("main.recent-filters", val)
}

func addToRecent(field string, val string) {
	comps := profiles.ConfStrings(field)
	if (len(comps) == 0 || comps[0] != val) && strings.TrimSpace(val) != "" {
		comps = RemoveFromStringSlice(val, comps)
		if len(comps) > 64 {
			comps = comps[0 : 64-1]
		}
		profiles.SetConf(field, comps)
	}
}

//======================================================================

func LoadOffsetFromConfig(name string) ([]resizable.Offset, error) {
	offsStr := profiles.ConfString("main."+name, "")
	if offsStr == "" {
		return nil, gowid.WithKVs(ConfigErr, map[string]interface{}{
			"name": name,
			"msg":  "No offsets found",
		})
	}
	res := make([]resizable.Offset, 0)
	err := json.Unmarshal([]byte(offsStr), &res)
	if err != nil {
		return nil, gowid.WithKVs(ConfigErr, map[string]interface{}{
			"name": name,
			"msg":  "Could not unmarshal offsets",
		})
	}
	return res, nil
}

func SaveOffsetToConfig(name string, offsets2 []resizable.Offset) {
	offsets := make([]resizable.Offset, 0)
	for _, off := range offsets2 {
		if off.Adjust != 0 {
			offsets = append(offsets, off)
		}
	}
	if len(offsets) == 0 {
		profiles.DeleteConf("main." + name)
	} else {
		offs, err := json.Marshal(offsets)
		if err != nil {
			log.Fatal(err)
		}
		profiles.SetConf("main."+name, string(offs))
	}
	// Hack to make viper save if I only deleted from the map
	profiles.SetConf("main.lastupdate", time.Now().String())
}

//======================================================================

// Need to publish fields for template use
type JumpPos struct {
	Summary string `json:"summary"`
	Pos     int    `json:"position"`
}

type GlobalJumpPos struct {
	JumpPos
	Filename string `json:"filename"`
}

// For ease of use in the template
func (g GlobalJumpPos) Base() string {
	return filepath.Base(g.Filename)
}

type globalJumpPosMapping struct {
	Key           rune `json:"key"`
	GlobalJumpPos      // embedding without a field name makes the json more concise
}

func LoadGlobalMarks(m map[rune]GlobalJumpPos) error {
	marksStr := profiles.ConfString("main.marks", "")
	if marksStr == "" {
		return nil
	}

	mappings := make([]globalJumpPosMapping, 0)
	err := json.Unmarshal([]byte(marksStr), &mappings)
	if err != nil {
		return gowid.WithKVs(ConfigErr, map[string]interface{}{
			"name": "marks",
			"msg":  "Could not unmarshal marks",
		})
	}

	for _, mapping := range mappings {
		m[mapping.Key] = mapping.GlobalJumpPos
	}

	return nil
}

func SaveGlobalMarks(m map[rune]GlobalJumpPos) {
	marks := make([]globalJumpPosMapping, 0)
	for k, v := range m {
		marks = append(marks, globalJumpPosMapping{Key: k, GlobalJumpPos: v})
	}
	if len(marks) == 0 {
		profiles.DeleteConf("main.marks")
	} else {
		marksJ, err := json.Marshal(marks)
		if err != nil {
			log.Fatal(err)
		}
		profiles.SetConf("main.marks", string(marksJ))
	}
	// Hack to make viper save if I only deleted from the map
	profiles.SetConf("main.lastupdate", time.Now().String())
}
