package main

import (
	"strings"
	"testing"

	"github.com/takehaya/goxdp-template/pkg/coreelf"
)

func TestCLIOptions(t *testing.T) {
	negativeCPUError := "unavailable"
	if !coreelf.CPUMAPEnabled {
		negativeCPUError = "disabled in this build"
	}
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"unknown backend", []string{"--backend", "unknown"}, "unknown backend"},
		{"TC FIB backend", []string{"--backend", "tc", "--mode", "fib"}, "supported in broadcast and vxlan"},
		{"no ingress", nil, "--device"},
		{"unknown mode", []string{"--mode", "unknown", "--device", "lo"}, "unknown mode"},
		{"no group", []string{"--mode", "broadcast", "--device", "lo"}, "--egress"},
		{"group in vxlan mode", []string{"--device", "lo", "--egress", "lo"}, "only supported in broadcast"},
		{"duplicate ingress", []string{"--device", "lo", "--device", "lo"}, "duplicate interface"},
		{"duplicate egress", []string{"--mode", "broadcast", "--device", "lo", "--egress", "lo", "--egress", "lo"}, "duplicate interface"},
		{"VXLAN config required", []string{"--device", "lo"}, "requires --config"},
		{"config in broadcast mode", []string{"--mode", "broadcast", "--config", "unused.json"}, "only supported in vxlan"},
		{"config in fib mode", []string{"--mode", "fib", "--config", "unused.json"}, "only supported in vxlan"},
		{"CPU without redirect", []string{"--cpu", "0"}, "requires --cpu-redirect"},
		{"CPU in broadcast mode", []string{"--mode", "broadcast", "--cpu-redirect"}, "supported in vxlan and fib"},
		{"negative CPU", []string{"--cpu-redirect", "--cpu", "-1"}, negativeCPUError},
		{"local delivery in fib mode", []string{"--mode", "fib", "--local-delivery", "lo"}, "supported in broadcast and vxlan"},
		{"duplicate local receiver", []string{"--mode", "broadcast", "--device", "lo", "--egress", "lo", "--local-delivery", "lo", "--local-delivery", "lo"}, "duplicate interface"},
		{"receiver is forwarding port", []string{"--mode", "broadcast", "--device", "lo", "--egress", "lo", "--local-delivery", "lo"}, "separate from forwarding ports"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := newApp("test").Run(append([]string{"goxdp"}, tt.args...))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Run() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestDisabledCPUCLI(t *testing.T) {
	if coreelf.CPUMAPEnabled {
		t.Skip("requires nocpumap build")
	}
	for _, mode := range []string{"fib", "vxlan"} {
		err := newApp("test").Run([]string{"goxdp", "--mode", mode, "--cpu-redirect"})
		if err != coreelf.ErrCPUMAPDisabled {
			t.Fatalf("%s CPU redirect: %v", mode, err)
		}
	}
}

func TestLocalDeliveryValidation(t *testing.T) {
	if err := validateLocalDelivery([]string{"lo"}); err == nil || !strings.Contains(err.Error(), "Ethernet") {
		t.Fatalf("loopback receiver: %v", err)
	}
	if err := validateLocalDelivery([]string{"lo"}, nil, []string{"lo"}); err == nil || !strings.Contains(err.Error(), "separate") {
		t.Fatalf("receiver conflicts with egress: %v", err)
	}
}
