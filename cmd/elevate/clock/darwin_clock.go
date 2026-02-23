package clock

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DarwinClock reads monotonic uptime via sysctl kern.boottime on macOS.
type DarwinClock struct {
	started      time.Time
	readBootTime func() ([]byte, error)
	now          func() time.Time
}

// NewDarwinClock constructs a macOS clock implementation.
func NewDarwinClock() *DarwinClock {
	return &DarwinClock{
		started:      time.Now(),
		readBootTime: func() ([]byte, error) { return exec.Command("sysctl", "-n", "kern.boottime").Output() },
		now:          time.Now,
	}
}

// NowMonoNS returns monotonic nanoseconds since boot derived from kern.boottime.
func (c *DarwinClock) NowMonoNS() int64 {
	raw, err := c.readBootTime()
	if err != nil {
		// Fallback keeps the process functional if sysctl is unavailable.
		return time.Since(c.started).Nanoseconds()
	}

	bootTime, err := parseBootTime(string(raw))
	if err != nil {
		return time.Since(c.started).Nanoseconds()
	}

	uptime := c.now().Sub(bootTime)
	if uptime < 0 {
		return time.Since(c.started).Nanoseconds()
	}

	return uptime.Nanoseconds()
}

// NowWallUTC returns the current wall time in UTC.
func (*DarwinClock) NowWallUTC() time.Time {
	return time.Now().UTC()
}

// parseBootTime parses the output of sysctl -n kern.boottime.
// Expected format: "{ sec = 1740000000, usec = 500000 } Thu Feb 20 10:00:00 2025"
func parseBootTime(raw string) (time.Time, error) {
	start := strings.Index(raw, "{")
	end := strings.Index(raw, "}")
	if start < 0 || end < 0 || end <= start {
		return time.Time{}, fmt.Errorf("invalid boot time format")
	}

	inner := raw[start+1 : end]
	var sec, usec int64
	var foundSec, foundUsec bool

	for _, part := range strings.Split(inner, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		switch key {
		case "sec":
			v, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("parse sec: %w", err)
			}
			sec = v
			foundSec = true
		case "usec":
			v, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("parse usec: %w", err)
			}
			usec = v
			foundUsec = true
		}
	}

	if !foundSec || !foundUsec {
		return time.Time{}, fmt.Errorf("missing sec or usec in boot time")
	}

	return time.Unix(sec, usec*1000), nil
}
