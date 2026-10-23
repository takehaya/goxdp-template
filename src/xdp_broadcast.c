#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>

// One devmap represents one replication group. Keys are slots, values are
// interface indices populated by the Go loader before attaching the program.
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 64);
  __type(key, __u32);
  __type(value, __u32);
} tx_ports SEC(".maps");

SEC("xdp")
int xdp_broadcast(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;

  if (data + sizeof(struct ethhdr) > data_end) return XDP_DROP;

  // The key is ignored with BPF_F_BROADCAST. Replicate the frame to every
  // member of the group, excluding the receiving interface even if listed.
  return bpf_redirect_map(&tx_ports, 0,
                          BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
}

char __license[] SEC("license") = "Dual MIT/GPL";
