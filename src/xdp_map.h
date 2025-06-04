#ifndef XDP_MAP_H
#define XDP_MAP_H

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "xdp_const.h"

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct bpf_fib_lookup_mock);
  __type(value, struct fib_lookup_mock_result);
  __uint(max_entries, FIB_LOOKUP_ENTRYSIZE);
} fib_lookup_mock_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 8);
} xdp_prog_array SEC(".maps");

// https://github.com/cloudflare/xdpcap
// struct bpf_map_def SEC("maps") xdpcap_hook = XDPCAP_HOOK();
struct xdpcap_hook {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
  __uint(max_entries, 5);
} xdpcap_hook SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_CPUMAP);
  __uint(max_entries, 128);
  __type(key, __u32);
  __type(value, struct bpf_cpumap_val);
} cpus_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, struct stats_map_value);
  __uint(max_entries, 1024);
} stats_map SEC(".maps");

#endif // XDP_MAP_H