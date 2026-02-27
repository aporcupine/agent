//go:build windows

package clock

import (
	"syscall"
	"time"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetTickCount64 = kernel32.NewProc("GetTickCount64")
)

// NowMonoNS returns monotonic nanoseconds since system boot.
//
// NOTE(review): GetTickCount64 returns milliseconds, so precision is limited
// to ~1ms. This is fine for grant expiry (seconds granularity) but worth
// documenting for any future sub-millisecond use cases.
func (c *Clock) NowMonoNS() int64 {
	ms, _, callErr := procGetTickCount64.Call()
	if callErr == syscall.Errno(0) {
		return int64(ms) * int64(time.Millisecond)
	}
	return time.Since(c.started).Nanoseconds()
}
