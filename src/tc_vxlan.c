#define TC_BACKEND 1
#include "xdp_vxlan.c"
#include <linux/pkt_cls.h>
#include "tc_utils.h"

struct tc_group {
  __u32 count;
  __u32 ifindices[64];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, __u32);
  __type(value, struct tc_group);
} tc_groups SEC(".maps");

struct tc_forward {
  struct __sk_buff* skb;
  struct tc_group* members;
  __u32 vni;
  __u32 ingress;
  __u32 inner_len;
  __u32 destination;
  __u32 pending;
  __u32 encapsulated;
  struct cached_header header;
};

static __always_inline int tc_inner_fits(struct tc_forward* forward,
                                         __u32 output) {
  // Keep a nonzero input for Ethernet-only frames; match devmap's VLAN
  // allowance.
  __u32 length = forward->inner_len;
  return !bpf_check_mtu(forward->skb, output, &length, -ETH_HLEN - 4, 0);
}

static long tc_access(__u64 slot, struct tc_forward* forward) {
  if (slot >= 64 || slot >= forward->members->count) return 1;
  __u32 output = forward->members->ifindices[slot];
  if (!output || output == forward->ingress ||
      (forward->destination && output != forward->destination))
    return 0;
  struct port_config* port = bpf_map_lookup_elem(&ports, &output);
  void* data = (void*)(long)forward->skb->data;
  void* end = (void*)(long)forward->skb->data_end;
  if (!port || !access_allowed(port, output, forward->vni, data, end) ||
      !tc_inner_fits(forward, output))
    return 0;
  if (forward->pending) bpf_clone_redirect(forward->skb, forward->pending, 0);
  forward->pending = output;
  return 0;
}

static long tc_tunnel(__u64 slot, struct tc_forward* forward) {
  if (slot >= 64 || slot >= forward->members->count) return 1;
  __u32 output = forward->members->ifindices[slot];
  if (!output || output == forward->ingress) return 0;
  struct port_config* entry = bpf_map_lookup_elem(&ports, &output);
  if (!entry || entry->kind != TUNNEL ||
      forward->inner_len + VXLAN_OVERHEAD - ETH_HLEN > entry->mtu ||
      !tc_inner_fits(forward, output))
    return 0;
  struct port_config port = *entry;
  struct peer_config target = {};
  if (resolve_peer(forward->vni, output, &target)) return 0;
  if (forward->pending) bpf_clone_redirect(forward->skb, forward->pending, 0);
  forward->pending = 0;
  if (!forward->encapsulated) {
    // shortcut: raw Ethernet encapsulation retains Inner skb metadata;
    // add tunnel-offload handling before accepting GSO packets.
    if (forward->skb->gso_size ||
        bpf_skb_change_head(forward->skb, VXLAN_OVERHEAD, 0))
      return 1;
    forward->encapsulated = 1;
  }
  struct ethhdr* eth = (void*)forward->header.bytes;
  struct iphdr* ip = (void*)(eth + 1);
  __builtin_memcpy(eth->h_source, port.mac, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, target.mac, ETH_ALEN);
  ip->saddr = port.local_ip;
  ip->daddr = target.remote_ip;
  checksum(ip);
  if (bpf_skb_store_bytes(forward->skb, 0, forward->header.bytes,
                          VXLAN_OVERHEAD, 0))
    return 1;
  forward->pending = output;
  return 0;
}

SEC("tc")
int tc_vxlan(struct __sk_buff* skb) {
  void* data = (void*)(long)skb->data;
  void* end = (void*)(long)skb->data_end;
  struct xdp_command* command = (void*)(long)skb->data_meta;
  if ((void*)(command + 1) > data) return TC_ACT_UNSPEC;
  if (command->magic != COMMAND_MAGIC || command->program != PROGRAM_FORWARD)
    return TC_ACT_SHOT;
  __u32 vni = command->args.vxlan.vni;
  __u32 flags = command->args.vxlan.flags;
  __u32 flow_hash = command->args.vxlan.flow_hash;
  __u32 inner_len = command->args.vxlan.inner_len;
  if (flags & ~FROM_TUNNEL) return TC_ACT_SHOT;
  if (restore_vlan(skb)) return TC_ACT_SHOT;
  data = (void*)(long)skb->data;
  end = (void*)(long)skb->data_end;
  struct ethhdr* eth = data;
  if ((void*)(eth + 1) > end || skb->len != inner_len) return TC_ACT_SHOT;
  struct tc_group* members = bpf_map_lookup_elem(&tc_groups, &vni);
  if (!members || members->count > 64) return TC_ACT_SHOT;
  struct tc_forward forward = {.skb = skb,
                               .members = members,
                               .vni = vni,
                               .ingress = skb->ifindex,
                               .inner_len = skb->len};
  if (!(eth->h_dest[0] & 1)) {
    struct fdb_key key = {.vni = vni};
    __builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN);
    __u32* known = bpf_map_lookup_elem(&fdb, &key);
    if (known) forward.destination = *known;
  }

  // Access copies precede encapsulation, so the shared Inner is never restored.
  bpf_loop(64, tc_access, &forward, 0);
  if (forward.destination || (flags & FROM_TUNNEL))
    return forward.pending ? bpf_redirect(forward.pending, 0) : TC_ACT_SHOT;

  if (build_header(&forward.header, vni, forward.inner_len)) return TC_ACT_SHOT;
  __u64 key = header_key(vni, forward.inner_len);
  bpf_map_update_elem(&header_cache, &key, &forward.header, BPF_ANY);
  struct udphdr* udp =
      (void*)forward.header.bytes + ETH_HLEN + sizeof(struct iphdr);
  udp->source = flow_source_port(flow_hash);
  __u32 zero = 0;
  struct pipeline_counters* stats = bpf_map_lookup_elem(&pipeline_stats, &zero);
  if (stats) stats->header_preparations++;

  bpf_loop(64, tc_tunnel, &forward, 0);
  // Like devmap broadcast, use the original packet for the final destination.
  return forward.pending ? bpf_redirect(forward.pending, 0) : TC_ACT_SHOT;
}
