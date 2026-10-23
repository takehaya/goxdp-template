package coreelf

import (
	"strings"
	"testing"
)

func TestTCBroadcastRejectsMissingInterface(t *testing.T) {
	_, err := ReadTCBroadcastCollection([]uint32{^uint32(0)})
	if err == nil || !strings.Contains(err.Error(), "find TC egress ifindex") {
		t.Fatalf("missing interface: %v", err)
	}
}
