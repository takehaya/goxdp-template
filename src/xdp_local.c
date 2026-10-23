#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

const volatile __u8 local_mac[ETH_ALEN];

SEC("xdp")
int local_receive(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* end = (void*)(long)ctx->data_end;
  struct ethhdr* eth = data;
  if ((void*)(eth + 1) > end) return XDP_DROP;
  // The local copy may still carry another interface's unicast MAC.
  if (!(eth->h_dest[0] & 1)) {
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) eth->h_dest[i] = local_mac[i];
  }
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
