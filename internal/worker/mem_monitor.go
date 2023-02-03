// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import "time"

// memMonitor is used to probe memory consumption
// in a separate Go routine.
type memMonitor struct {
	stp chan struct{} // for stopping the monitor
	res chan uint64   // for communicating results
}

// newMemMonitor creates and starts new monitor that
// samples memory consumption.
//
// If threshold > 0, then when memory consumption reaches threshold,
// the monitor will call onThreshold and stop.
func newMemMonitor(threshold uint64, onThreshold func()) *memMonitor {
	m := &memMonitor{make(chan struct{}), make(chan uint64)}
	var max uint64
	go func() {
		for {
			select {
			case <-m.stp:
				m.res <- max
				return
			default:
				h := currHeapUsage()
				if h > max {
					max = h
				}
				if threshold > 0 && h > threshold {
					onThreshold()
					m.res <- max
					return
				}
				// We sample memory every 50ms.
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()
	return m
}

// stop stops the monitor and returns the peak
// memory consumption in bytes.
func (m *memMonitor) stop() uint64 {
	if m == nil {
		return 0
	}
	close(m.stp)
	return <-m.res
}
