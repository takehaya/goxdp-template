//go:build integration

package coreelf

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// Go runtime signals can interrupt poll even when no packet is delivered.
func pollPackets(fds []unix.PollFd, timeout int) (int, error) {
	deadline := time.Now().Add(time.Duration(timeout) * time.Millisecond)
	for {
		n, err := unix.Poll(fds, timeout)
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil
		}
		timeout = int((remaining + time.Millisecond - 1) / time.Millisecond)
	}
}
