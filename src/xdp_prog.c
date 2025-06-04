#include "xdp_prog.h"
#include "hook.h"
#include "xdp_utils.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph = 0;
  struct ip6_hdr *ip6h = 0;
  __be16 l3proto = 0;
  __u8 l4proto = 0;

  unsigned long nh_off;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

  if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
    struct vlan_hdr *vhdr = data + nh_off;
    nh_off += sizeof(struct vlan_hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

    l3proto = vhdr->h_vlan_encapsulated_proto;
  } else {
    l3proto = eth->h_proto;
  }

  // IPv4, IPv6only
  if (l3proto == bpf_htons(ETH_P_IP)) {
    iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

    l4proto = iph->protocol;
  } else if (l3proto == bpf_htons(ETH_P_IPV6)) {
    ip6h = data + nh_off;
    nh_off += sizeof(struct ip6_hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

    l4proto = ip6h->ip6_nxt;
  } else {
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
  }

  // check vxlan packet
  if (l4proto == IPPROTO_UDP) {
    struct udphdr *udph = data + nh_off;
    nh_off += sizeof(struct udphdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

    // decap case
    if (udph->dest == bpf_htons(IANA_VXLAN_UDP_PORT)) {
      // struct vxlanhdr *vxlanh = data + nh_off;
      nh_off += sizeof(struct vxlanhdr);
      if (data + nh_off > data_end)
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

      // decap vxlan packet
      int remove_offset = nh_off;
      bpf_xdp_adjust_head(ctx, remove_offset);
    }
  }

  // new headers
  data_end = (void *)(long)ctx->data_end;
  data = (void *)(long)ctx->data;
  eth = data;
  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

  if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
    struct vlan_hdr *vhdr = data + nh_off;
    nh_off += sizeof(struct vlan_hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

    l3proto = vhdr->h_vlan_encapsulated_proto;
  } else {
    l3proto = eth->h_proto;
  }

  if (l3proto == bpf_htons(ETH_P_IP)) {
    iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

    l4proto = iph->protocol;
  } else if (l3proto == bpf_htons(ETH_P_IPV6)) {
    ip6h = data + nh_off;
    nh_off += sizeof(struct ip6_hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);

    l4proto = ip6h->ip6_nxt;
  } else {
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
  }

  // vxlan encap case
  // TODO: encap vxlan packet

  // mock example: fiblookup
  struct bpf_fib_lookup params = {};
  if (l3proto == bpf_htons(ETH_P_IP)) {
    if (!ipv4_fib_lookup(ctx, &params, iph, 1,
                         BPF_FIB_LOOKUP_DIRECT |
                             BPF_FIB_LOOKUP_OUTPUT)) // 1 hardcoded ifindex
    {
      DEBUG_PRINT("impl_downlink_ip4handler ipv4_fib_lookup failed");
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
    }
  } else if (l3proto == bpf_htons(ETH_P_IPV6)) {
    if (!ipv6_fib_lookup(ctx, &params, ip6h, 1,
                         BPF_FIB_LOOKUP_DIRECT |
                             BPF_FIB_LOOKUP_OUTPUT)) // 1 hardcoded ifindex
    {
      DEBUG_PRINT("impl_downlink_ip6handler ipv6_fib_lookup failed");
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
    }
  } else {
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
  }
  __builtin_memcpy(eth->h_source, params.smac, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, params.dmac, ETH_ALEN);
  return xdpcap_exit(ctx, &xdpcap_hook, XDP_TX);
}

SEC("xdp/cpumap_jump")
int xdp_main_jump(struct xdp_md *ctx) {
  bpf_tail_call(ctx, &xdp_prog_array, XDP_PROG);
  return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
}

SEC("xdp_cpu_dispatch")
int cpu_dispatch(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph = 0;
  struct ip6_hdr *ip6h = 0;
  __be16 l3proto = 0;
  __u8 l4proto = 0;

  unsigned long nh_off;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

  if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
    struct vlan_hdr *vhdr = data + nh_off;
    nh_off += sizeof(struct vlan_hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

    l3proto = vhdr->h_vlan_encapsulated_proto;
  } else {
    l3proto = eth->h_proto;
  }

  // IPv4, IPv6only
  if (l3proto == bpf_htons(ETH_P_IP)) {
    iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

    l4proto = iph->protocol;
  } else if (l3proto == bpf_htons(ETH_P_IPV6)) {
    ip6h = data + nh_off;
    nh_off += sizeof(struct ip6_hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

    l4proto = ip6h->ip6_nxt;
  } else {
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
  }
  __u32 key_hash = 0;
  // check vxlan packet
  if (l4proto == IPPROTO_UDP) {
    struct udphdr *udph = data + nh_off;
    nh_off += sizeof(struct udphdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

    // decap case
    if (udph->dest == bpf_htons(IANA_VXLAN_UDP_PORT)) {
      struct vxlanhdr *vxlanh = data + nh_off;
      nh_off += sizeof(struct vxlanhdr);
      if (data + nh_off > data_end)
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

      key_hash = vxlanh->vx_vni;
    }
  }

  __u32 cpu = key_hash % cpu_count;
  int ret = bpf_redirect_map(&cpus_map, cpu, 0);
  if (ret < 0) {
    DEBUG_PRINT("cpu_dispatch: bpf_redirect_map failed, ret=%d", ret);
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
  }
  DEBUG_PRINT("cpu_dispatch key=0x%x -> cpu=%u ret=%d", key_hash, cpu, ret);
  return xdpcap_exit(ctx, &xdpcap_hook, ret);
}

char __license[] SEC("license") = "Dual MIT/GPL";
