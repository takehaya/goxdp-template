// Command counters samples XDPerf's per-CPU TX and RX maps without enabling
// BPF runtime accounting, which would add a timer to every program execution.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

type record struct {
	Packets        uint64 `json:"packets"`
	Bytes          uint64 `json:"bytes"`
	DiffErrors     uint64 `json:"diff_errors"`
	ChecksumErrors uint64 `json:"checksum_errors"`
}

type sample struct {
	AtNS          int64               `json:"at_ns"`
	EndNS         int64               `json:"end_ns"`
	MapAtNS       map[string]int64    `json:"map_at_ns"`
	PerCPUPackets map[string][]uint64 `json:"per_cpu_packets"`
	Maps          map[string]record   `json:"maps"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	maps := make(map[string]*ebpf.Map)
	var names []string
	defer func() {
		for _, m := range maps {
			m.Close()
		}
	}()
	for _, arg := range os.Args[1:] {
		name, raw, ok := strings.Cut(arg, "=")
		id, err := strconv.ParseUint(raw, 10, 32)
		if !ok || name == "" || err != nil {
			return fmt.Errorf("expected label=mapID, got %q", arg)
		}
		if maps[name] != nil {
			return fmt.Errorf("duplicate label %q", name)
		}
		m, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			return fmt.Errorf("open %s: %w", name, err)
		}
		if m.Type() != ebpf.PerCPUArray || m.ValueSize() != 32 {
			m.Close()
			return fmt.Errorf("%s is not an XDPerf 32-byte per-CPU stats array", name)
		}
		maps[name] = m
		names = append(names, name)
	}
	if len(maps) == 0 {
		return fmt.Errorf("specify at least one label=mapID")
	}
	start := time.Now()
	input := bufio.NewScanner(os.Stdin)
	output := json.NewEncoder(os.Stdout)
	values := make([]record, cpus)
	for input.Scan() {
		result := sample{AtNS: time.Since(start).Nanoseconds(), Maps: make(map[string]record), MapAtNS: make(map[string]int64), PerCPUPackets: make(map[string][]uint64)}
		for _, name := range names {
			m := maps[name]
			begin := time.Since(start).Nanoseconds()
			if err := m.Lookup(uint32(0), &values); err != nil {
				return fmt.Errorf("read %s: %w", name, err)
			}
			result.MapAtNS[name] = (begin + time.Since(start).Nanoseconds()) / 2
			var total record
			perCPU := make([]uint64, len(values))
			for cpu, value := range values {
				perCPU[cpu] = value.Packets
				total.Packets += value.Packets
				total.Bytes += value.Bytes
				total.DiffErrors += value.DiffErrors
				total.ChecksumErrors += value.ChecksumErrors
			}
			result.Maps[name] = total
			result.PerCPUPackets[name] = perCPU
		}
		result.EndNS = time.Since(start).Nanoseconds()
		if err := output.Encode(result); err != nil {
			return err
		}
	}
	return input.Err()
}
