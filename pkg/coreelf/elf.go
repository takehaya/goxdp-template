package coreelf

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf xdp ../../src/xdp_prog.c -- -I./../../include -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wnull-character -g -c -O2 -D__KERNEL__

func ReadCollection() (*xdpObjects, error) {
	obj := &xdpObjects{}
	// TODO: BPF log level remove hardcoding. yaml in config?
	err := loadXdpObjects(obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 2,
			LogSize:  102400 * 1024,
		},
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return obj, nil
}
