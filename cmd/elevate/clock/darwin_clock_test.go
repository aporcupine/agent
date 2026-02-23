package clock

import (
	"errors"
	"testing"
	"time"
)

func TestDarwinClockNowMonoNS_ParsesBootTime(t *testing.T) {
	c := NewDarwinClock()
	c.readBootTime = func() ([]byte, error) {
		return []byte("{ sec = 1000, usec = 0 } Mon Jan  1 00:16:40 1970\n"), nil
	}
	c.now = func() time.Time {
		return time.Unix(1012, 500000000)
	}

	got := c.NowMonoNS()
	want := int64(12.5 * float64(time.Second))
	if got != want {
		t.Fatalf("unexpected monotonic ns: got %d want %d", got, want)
	}
}

func TestDarwinClockNowMonoNS_FallbackOnReadError(t *testing.T) {
	c := NewDarwinClock()
	c.started = time.Now().Add(-2 * time.Second)
	c.readBootTime = func() ([]byte, error) {
		return nil, errors.New("boom")
	}

	got := c.NowMonoNS()
	if got < int64(1*time.Second) || got > int64(10*time.Second) {
		t.Fatalf("unexpected fallback monotonic ns: got %d", got)
	}
}

func TestDarwinClockNowMonoNS_FallbackOnParseError(t *testing.T) {
	c := NewDarwinClock()
	c.started = time.Now().Add(-1500 * time.Millisecond)
	c.readBootTime = func() ([]byte, error) {
		return []byte("not-valid-sysctl-output"), nil
	}

	got := c.NowMonoNS()
	if got < int64(1*time.Second) || got > int64(10*time.Second) {
		t.Fatalf("unexpected fallback monotonic ns: got %d", got)
	}
}
