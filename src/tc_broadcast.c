#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_dispatch.h"
#include "tc_utils.h"

const volatile __u32 egress_count = 0;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 64);
  __type(key, __u32);
  __type(value, __u32);
} tx_ports SEC(".maps");

SEC("xdp")
int xdp_broadcast(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* end = (void*)(long)ctx->data_end;
  if (data + ETH_HLEN > end) return XDP_DROP;
  if (write_command(ctx, PROGRAM_FORWARD, (union xdp_arguments){}))
    return XDP_DROP;
  return XDP_PASS;
}

struct tc_broadcast_context {
  struct __sk_buff* skb;
  __u32 pending;
  __u32 ingress;
};

static long tc_broadcast_member(__u64 slot,
                                struct tc_broadcast_context* context) {
  if (slot >= 64 || slot >= egress_count) return 1;
  __u32 key = slot;
  __u32* member = bpf_map_lookup_elem(&tx_ports, &key);
  if (!member || !*member || *member == context->ingress) return 0;
  __u32 destination = *member;
  __u32 mtu = 0;
  // Match devmap's mtu + Ethernet header + VLAN header allowance.
  if (bpf_check_mtu(context->skb, destination, &mtu, -4, 0)) return 0;
  if (context->pending) bpf_clone_redirect(context->skb, context->pending, 0);
  context->pending = destination;
  return 0;
}

SEC("tc")
int tc_broadcast(struct __sk_buff* skb) {
  void* data = (void*)(long)skb->data;
  struct xdp_command* command = (void*)(long)skb->data_meta;
  if ((void*)(command + 1) > data) return TC_ACT_UNSPEC;
  if (command->magic != COMMAND_MAGIC || command->program != PROGRAM_FORWARD)
    return TC_ACT_SHOT;
  if (restore_vlan(skb)) return TC_ACT_SHOT;
  struct tc_broadcast_context context = {.skb = skb, .ingress = skb->ifindex};
  bpf_loop(64, tc_broadcast_member, &context, 0);
  return context.pending ? bpf_redirect(context.pending, 0) : TC_ACT_SHOT;
}

char __license[] SEC("license") = "Dual MIT/GPL";
