//go:build darwin

package clock

import "golang.org/x/sys/unix"

var clockSource int32 = unix.CLOCK_MONOTONIC
