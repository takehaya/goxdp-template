#include "xdp_prog.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdbool.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  unsigned long nh_off;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end) return XDP_DROP;

  __be16 l3proto = 0;
  if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
    struct vlan_hdr *vhdr = data + nh_off;
    nh_off += sizeof(struct vlan_hdr);
    if (data + nh_off > data_end) return XDP_DROP;

    l3proto = vhdr->h_vlan_encapsulated_proto;
  } else {
    l3proto = eth->h_proto;
  }

  // IPv4, IPv6only
  __u8 l4proto = 0;
  if (l3proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end) return XDP_DROP;

    l4proto = iph->protocol;
  } else if (l3proto == bpf_htons(ETH_P_IPV6)) {
    struct ip6_hdr *ip6h = data + nh_off;
    nh_off += sizeof(struct ip6_hdr);
    if (data + nh_off > data_end) return XDP_DROP;

    l4proto = ip6h->ip6_nxt;
  } else {
    return XDP_PASS;
  }

  // check vxlan packet
  if (l4proto == IPPROTO_UDP) {
    struct udphdr *udph = data + nh_off;
    nh_off += sizeof(struct udphdr);
    if (data + nh_off > data_end) return XDP_DROP;

    // decap case
    if (udph->dest == bpf_htons(IANA_VXLAN_UDP_PORT)) {
      struct vxlanhdr *vxlanh = data + nh_off;
      nh_off += sizeof(struct vxlanhdr);
      if (data + nh_off > data_end) return XDP_DROP;

      // decap vxlan packet
      int remove_offset = nh_off;
      bpf_xdp_adjust_head(ctx, remove_offset);
    }
  }

  // vxlan encap case
  // TODO: encap vxlan packet

  return XDP_TX;
}

char __license[] SEC("license") = "Dual MIT/GPL";
