#ifndef XDP_MAP_H
#define XDP_MAP_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdp_const.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct bpf_fib_lookup_mock);
    __type(value, struct fib_lookup_mock_result);
    __uint(max_entries, FIB_LOOKUP_ENTRYSIZE);
} fib_lookup_mock_table SEC(".maps");

#endif // XDP_MAP_H