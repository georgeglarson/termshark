// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/gcla/gowid/gwutil"
	log "github.com/sirupsen/logrus"
)

//======================================================================

var cpuProfileRunning atomic.Bool

// Down to the second for profiling, etc
func DateStringForFilename() string {
	return time.Now().Format("2006-01-02--15-04-05")
}

func ProfileCPUFor(secs int) bool {
	if !cpuProfileRunning.CompareAndSwap(false, true) {
		log.Infof("CPU profile already running.")
		return false
	}
	file := filepath.Join(CacheDir(), fmt.Sprintf("cpu-%s.prof", DateStringForFilename()))
	log.Infof("Starting CPU profile for %d seconds in %s", secs, file)
	gwutil.StartProfilingCPU(file)
	go func() {
		time.Sleep(time.Duration(secs) * time.Second)
		log.Infof("Stopping CPU profile")
		gwutil.StopProfilingCPU()
		cpuProfileRunning.Store(false)
	}()

	return true
}

func ProfileHeap() {
	file := filepath.Join(CacheDir(), fmt.Sprintf("mem-%s.prof", DateStringForFilename()))
	log.Infof("Creating memory profile in %s", file)
	gwutil.ProfileHeap(file)
}

func LocalIPs() []string {
	res := make([]string, 0)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return res
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			res = append(res, ipnet.IP.String())
		}
	}
	return res
}
