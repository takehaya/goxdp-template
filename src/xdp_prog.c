#include "xdp_prog.h"
#include "hook.h"
#include "xdp_utils.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "xdp_dispatch.h"

static __always_inline int process_packet(struct xdp_md* ctx,
                                          void* capture_hook, bool from_cpu) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr* eth = data;
  struct iphdr* iph = 0;
  struct ipv6hdr* ip6h = 0;
  __be16 l3proto = 0;
  __u8 l4proto = 0;

  unsigned long nh_off;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end) return xdpcap_exit(ctx, capture_hook, XDP_DROP);

  if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
    struct vlan_hdr* vhdr = data + nh_off;
    nh_off += sizeof(struct vlan_hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, capture_hook, XDP_DROP);

    l3proto = vhdr->h_vlan_encapsulated_proto;
  } else {
    l3proto = eth->h_proto;
  }

  // IPv4, IPv6only
  if (l3proto == bpf_htons(ETH_P_IP)) {
    iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, capture_hook, XDP_DROP);

    l4proto = iph->protocol;
  } else if (l3proto == bpf_htons(ETH_P_IPV6)) {
    ip6h = data + nh_off;
    nh_off += sizeof(struct ipv6hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, capture_hook, XDP_DROP);

    l4proto = ip6h->nexthdr;
  } else {
    return xdpcap_exit(ctx, capture_hook, XDP_PASS);
  }

  __u32 vni = 0;
  // check vxlan packet
  if (l4proto == IPPROTO_UDP) {
    struct udphdr* udph = data + nh_off;
    nh_off += sizeof(struct udphdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, capture_hook, XDP_DROP);

    // decap case
    if (udph->dest == bpf_htons(IANA_VXLAN_UDP_PORT)) {
      struct vxlanhdr* vxlanh = data + nh_off;
      nh_off += sizeof(struct vxlanhdr);
      if (data + nh_off > data_end)
        return xdpcap_exit(ctx, capture_hook, XDP_DROP);

      vni = VXLAN_VNI_EXTRACT(vxlanh->vx_vni);

      // decap vxlan packet
      int remove_offset = nh_off;
      if (bpf_xdp_adjust_head(ctx, remove_offset))
        return xdpcap_exit(ctx, capture_hook, XDP_DROP);
    }
  }

  // add stats map
  struct stats_map_value* stats = bpf_map_lookup_elem(&stats_map, &vni);
  if (stats) {
    stats->rx_packets++;
    stats->rx_bytes += ctx->data_end - ctx->data;
  }

  // new headers
  data_end = (void*)(long)ctx->data_end;
  data = (void*)(long)ctx->data;
  eth = data;
  nh_off = sizeof(*eth);
  if (data + nh_off > data_end) return xdpcap_exit(ctx, capture_hook, XDP_DROP);

  if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
    struct vlan_hdr* vhdr = data + nh_off;
    nh_off += sizeof(struct vlan_hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, capture_hook, XDP_DROP);

    l3proto = vhdr->h_vlan_encapsulated_proto;
  } else {
    l3proto = eth->h_proto;
  }

  if (l3proto == bpf_htons(ETH_P_IP)) {
    iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, capture_hook, XDP_DROP);

    l4proto = iph->protocol;
  } else if (l3proto == bpf_htons(ETH_P_IPV6)) {
    ip6h = data + nh_off;
    nh_off += sizeof(struct ipv6hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, capture_hook, XDP_DROP);

    l4proto = ip6h->nexthdr;
  } else {
    return xdpcap_exit(ctx, capture_hook, XDP_PASS);
  }

  // The complete VXLAN forwarding example is in xdp_vxlan.c.

  // mock example: fiblookup
  struct bpf_fib_lookup params = {};
  if (l3proto == bpf_htons(ETH_P_IP)) {
    if (!ipv4_fib_lookup(ctx, &params, iph, 1,
                         BPF_FIB_LOOKUP_DIRECT |
                             BPF_FIB_LOOKUP_OUTPUT))  // 1 hardcoded ifindex
    {
      DEBUG_PRINT("impl_downlink_ip4handler ipv4_fib_lookup failed");
      return xdpcap_exit(ctx, capture_hook, XDP_PASS);
    }
  } else if (l3proto == bpf_htons(ETH_P_IPV6)) {
    if (!ipv6_fib_lookup(ctx, &params, ip6h, 1,
                         BPF_FIB_LOOKUP_DIRECT |
                             BPF_FIB_LOOKUP_OUTPUT))  // 1 hardcoded ifindex
    {
      DEBUG_PRINT("impl_downlink_ip6handler ipv6_fib_lookup failed");
      return xdpcap_exit(ctx, capture_hook, XDP_PASS);
    }
  } else {
    return xdpcap_exit(ctx, capture_hook, XDP_PASS);
  }
  __builtin_memcpy(eth->h_source, params.smac, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, params.dmac, ETH_ALEN);
  int action = from_cpu ? bpf_redirect(ctx->ingress_ifindex, 0) : XDP_TX;
  return xdpcap_exit(ctx, capture_hook, action);
}

SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
  return process_packet(ctx, &xdpcap_hook, false);
}

#ifndef NO_CPUMAP
SEC("xdp/cpumap")
int xdp_cpumap_prog(struct xdp_md* ctx) {
  if (bpf_xdp_adjust_meta(ctx, sizeof(struct xdp_command))) return XDP_DROP;
  return process_packet(ctx, &xdpcap_cpumap_hook, true);
}

SEC("xdp/cpumap")
int xdp_main_jump(struct xdp_md* ctx) {
  return dispatch_command(ctx, &xdp_prog_array);
}

SEC("xdp")
int cpu_dispatch(struct xdp_md* ctx) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr* eth = data;
  struct iphdr* iph = 0;
  struct ipv6hdr* ip6h = 0;
  __be16 l3proto = 0;
  __u8 l4proto = 0;

  unsigned long nh_off;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end) return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

  if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
    struct vlan_hdr* vhdr = data + nh_off;
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
    nh_off += sizeof(struct ipv6hdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

    l4proto = ip6h->nexthdr;
  } else {
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
  }
  __u32 key_hash = 0;
  // check vxlan packet
  if (l4proto == IPPROTO_UDP) {
    struct udphdr* udph = data + nh_off;
    nh_off += sizeof(struct udphdr);
    if (data + nh_off > data_end)
      return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

    // decap case
    if (udph->dest == bpf_htons(IANA_VXLAN_UDP_PORT)) {
      struct vxlanhdr* vxlanh = data + nh_off;
      nh_off += sizeof(struct vxlanhdr);
      if (data + nh_off > data_end)
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

      key_hash = VXLAN_VNI_EXTRACT(vxlanh->vx_vni);
    }
  }

  __u32 slot = key_hash % cpu_count;
  __u32* selected = bpf_map_lookup_elem(&cpu_ids, &slot);
  if (!selected) return XDP_DROP;
  __u32 cpu = *selected;
  if (write_command(ctx, PROGRAM_FORWARD,
                    (union xdp_arguments){.raw = {key_hash, 0}}))
    return XDP_DROP;
  int ret = bpf_redirect_map(&cpus_map, cpu, 0);
  if (ret != XDP_REDIRECT) {
    DEBUG_PRINT("cpu_dispatch: bpf_redirect_map failed, ret=%d", ret);
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
  }
  DEBUG_PRINT("cpu_dispatch key=0x%x -> cpu=%u ret=%d", key_hash, cpu, ret);
  return xdpcap_exit(ctx, &xdpcap_hook, ret);
}

#endif

char __license[] SEC("license") = "Dual MIT/GPL";
