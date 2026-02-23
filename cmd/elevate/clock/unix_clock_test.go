package clock

import (
	"testing"
	"time"
)

func TestUnixClockNowMonoNS_ReturnsPositive(t *testing.T) {
	c := NewUnixClock()

	got := c.NowMonoNS()
	if got <= 0 {
		t.Fatalf("expected positive monotonic ns, got %d", got)
	}
}

func TestUnixClockNowMonoNS_IsMonotonic(t *testing.T) {
	c := NewUnixClock()

	a := c.NowMonoNS()
	time.Sleep(10 * time.Millisecond)
	b := c.NowMonoNS()

	if b <= a {
		t.Fatalf("expected monotonic increase: a=%d b=%d", a, b)
	}
}

func TestUnixClockNowWallUTC_IsUTC(t *testing.T) {
	c := NewUnixClock()

	now := c.NowWallUTC()
	if now.Location() != time.UTC {
		t.Fatalf("expected UTC location, got %v", now.Location())
	}
}

func TestUnixClockNowWallUTC_IsRecent(t *testing.T) {
	c := NewUnixClock()

	now := c.NowWallUTC()
	diff := time.Since(now)
	if diff < -1*time.Second || diff > 1*time.Second {
		t.Fatalf("wall clock too far from system time: diff=%v", diff)
	}
}
