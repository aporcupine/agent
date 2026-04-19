package clock

import (
	"time"

	"golang.org/x/sys/unix"
)

// UnixClock provides monotonic and wall-clock time using OS-level syscalls.
type UnixClock struct {
	started time.Time
}

// NewUnixClock constructs a Unix clock implementation.
func NewUnixClock() *UnixClock {
	return &UnixClock{
		started: time.Now(),
	}
}

// NowMonoNS returns monotonic nanoseconds since boot when available.
func (c *UnixClock) NowMonoNS() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(clockSource, &ts); err == nil {
		return ts.Nano()
	}
	// Safe fallback if syscall fails.
	return time.Since(c.started).Nanoseconds()
}

// NowWallUTC returns the current wall time in UTC.
func (*UnixClock) NowWallUTC() time.Time {
	return time.Now().UTC()
}
