// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/gob"
	"os"
	"path/filepath"
	"slices"

	"github.com/gcla/termshark/v2/configs/profiles"
	log "github.com/sirupsen/logrus"
)

//======================================================================

const magicMicroseconds = 0xA1B2C3D4
const versionMajor = 2
const versionMinor = 4
const dlt_en10mb = 1

func WriteEmptyPcap(filename string) error {
	var buf [24]byte
	binary.LittleEndian.PutUint32(buf[0:4], magicMicroseconds)
	binary.LittleEndian.PutUint16(buf[4:6], versionMajor)
	binary.LittleEndian.PutUint16(buf[6:8], versionMinor)
	// bytes 8:12 stay 0 (timezone = UTC)
	// bytes 12:16 stay 0 (sigfigs is always set to zero, according to
	//   http://wiki.wireshark.org/Development/LibpcapFileFormat
	binary.LittleEndian.PutUint32(buf[16:20], 10000)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(dlt_en10mb))

	err := os.WriteFile(filename, buf[:], 0644)

	return err
}

//======================================================================

func FileNewerThan(f1, f2 string) (bool, error) {
	file1, err := os.Open(f1)
	if err != nil {
		return false, err
	}
	defer file1.Close()
	file2, err := os.Open(f2)
	if err != nil {
		return false, err
	}
	defer file2.Close()
	f1s, err := file1.Stat()
	if err != nil {
		return false, err
	}
	f2s, err := file2.Stat()
	if err != nil {
		return false, err
	}
	return f1s.ModTime().After(f2s.ModTime()), nil
}

//======================================================================

func ReadGob(filePath string, object interface{}) error {
	file, err := os.Open(filePath)
	if err == nil {
		defer file.Close()
		gr, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gr.Close()
		decoder := gob.NewDecoder(gr)
		err = decoder.Decode(object)
	}
	return err
}

func WriteGob(filePath string, object interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipper := gzip.NewWriter(file)
	encoder := gob.NewEncoder(gzipper)
	if err := encoder.Encode(object); err != nil {
		gzipper.Close() // attempt to close, but return encode error
		return err
	}
	// gzipper.Close() flushes data and can fail - must check this error
	return gzipper.Close()
}

//======================================================================

func PrunePcapCache() error {
	// This is a new option. Best to err on the side of caution and, if not, present
	// assume the cache can grow indefinitely - in case users are now relying on this
	// to keep old pcaps around. I don't want to delete any files without the user's
	// explicit permission.
	var diskCacheSize int64 = int64(profiles.ConfInt("main.disk-cache-size-mb", -1))

	if diskCacheSize == -1 {
		log.Infof("No pcap disk cache size set. Skipping cache pruning.")
		return nil
	}

	// Let user use MB as the most sensible unit of disk size. Convert to
	// bytes for comparing to file sizes.
	diskCacheSize = diskCacheSize * 1024 * 1024

	log.Infof("Pruning termshark's pcap disk cache at %s...", PcapDir())

	type cachedFile struct {
		path string
		info os.FileInfo
	}

	var totalSize int64
	var files []cachedFile
	err := filepath.Walk(PcapDir(),
		func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				totalSize += info.Size()
				files = append(files, cachedFile{path: path, info: info})
			}
			return nil
		},
	)
	if err != nil {
		return err
	}

	slices.SortFunc(files, func(a, b cachedFile) int {
		return a.info.ModTime().Compare(b.info.ModTime())
	})

	filesRemoved := 0
	curCacheSize := totalSize
	for len(files) > 0 && curCacheSize > diskCacheSize {
		err = os.Remove(files[0].path)
		if err != nil {
			log.Warnf("Could not remove pcap cache file %s while pruning - %v", files[0].path, err)
		} else {
			curCacheSize = curCacheSize - files[0].info.Size()
			filesRemoved++
		}
		files = files[1:]
	}

	if filesRemoved > 0 {
		log.Infof("Pruning complete. Removed %d old pcaps. Cache size is now %d MB",
			filesRemoved, curCacheSize/(1024*1024))
	} else {
		log.Infof("Pruning complete. No old pcaps removed. Cache size is %d MB",
			curCacheSize/(1024*1024))
	}

	return nil
}

//======================================================================

// Returns true if error, too
func FileSizeDifferentTo(filename string, cur int64) (int64, bool) {
	var newSize int64
	diff := true
	fi, err := os.Stat(filename)
	if err == nil {
		newSize = fi.Size()
		if cur == newSize {
			diff = false
		}
	}
	return newSize, diff
}
