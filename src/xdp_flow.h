#ifndef XDP_FLOW_H
#define XDP_FLOW_H

#include <linux/ipv6.h>

static __always_inline __u32 flow_mix(__u32 hash, __u32 word) {
  word *= 0xcc9e2d51;
  word = (word << 15) | (word >> 17);
  word *= 0x1b873593;
  hash ^= word;
  hash = (hash << 13) | (hash >> 19);
  return hash * 5 + 0xe6546b64;
}

static __always_inline __u32 flow_finish(__u32 hash) {
  hash ^= hash >> 16;
  hash *= 0x85ebca6b;
  hash ^= hash >> 13;
  hash *= 0xc2b2ae35;
  return hash ^ (hash >> 16);
}

static __always_inline __u32 inner_flow_hash(void* data, void* end, __u32 vni) {
  struct ethhdr* eth = data;
  __u32 hash = flow_mix(0x9747b28c, vni);
  if ((void*)(eth + 1) > end) return flow_finish(hash);
  __be16 protocol = eth->h_proto;
  void* network = eth + 1;
#pragma unroll
  for (int i = 0; i < 2; i++) {
    if (protocol == bpf_htons(ETH_P_8021Q) ||
        protocol == bpf_htons(ETH_P_8021AD)) {
      struct {
        __be16 tci;
        __be16 protocol;
      }* tag = network;
      if ((void*)(tag + 1) > end) return flow_finish(hash);
      hash = flow_mix(hash, bpf_ntohs(tag->tci) & 0xfff);
      protocol = tag->protocol;
      network = tag + 1;
    }
  }
  hash = flow_mix(hash, bpf_ntohs(protocol));
  void* transport = 0;
  __u32 transport_len = 0;
  __u8 ip_protocol = 0;
  if (protocol == bpf_htons(ETH_P_IP)) {
    struct iphdr* ip = network;
    if ((void*)(ip + 1) > end || ip->version != 4 || ip->ihl < 5) goto layer2;
    __u32 ihl = ip->ihl * 4;
    __u32 length = bpf_ntohs(ip->tot_len);
    if (length < ihl || network + ihl > end) goto layer2;
    hash = flow_mix(hash, bpf_ntohl(ip->saddr));
    hash = flow_mix(hash, bpf_ntohl(ip->daddr));
    ip_protocol = ip->protocol;
    // All fragments use the same L3 key, including the fragment with ports.
    if (!(ip->frag_off & bpf_htons(0x3fff))) {
      transport = network + ihl;
      transport_len = length - ihl;
    }
  } else if (protocol == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr* ip = network;
    if ((void*)(ip + 1) > end || ip->version != 6) goto layer2;
#pragma unroll
    for (int i = 0; i < 4; i++) {
      hash = flow_mix(hash, bpf_ntohl(ip->saddr.s6_addr32[i]));
      hash = flow_mix(hash, bpf_ntohl(ip->daddr.s6_addr32[i]));
    }
    ip_protocol = ip->nexthdr;
    // Extension headers retain L3 affinity; this example does not walk them.
    transport = ip + 1;
    transport_len = bpf_ntohs(ip->payload_len);
  } else {
    goto layer2;
  }
  hash = flow_mix(hash, ip_protocol);
  if (transport && transport_len >= 4 && transport + 4 <= end &&
      (ip_protocol == IPPROTO_TCP || ip_protocol == IPPROTO_UDP)) {
    __be16* ports = transport;
    hash = flow_mix(hash,
                    ((__u32)bpf_ntohs(ports[0]) << 16) | bpf_ntohs(ports[1]));
  }
  return flow_finish(hash);

layer2:
#pragma unroll
  for (int i = 0; i < ETH_ALEN; i += 2) {
    hash =
        flow_mix(hash, ((__u32)eth->h_source[i] << 24) |
                           ((__u32)eth->h_source[i + 1] << 16) |
                           ((__u32)eth->h_dest[i] << 8) | eth->h_dest[i + 1]);
  }
  return flow_finish(hash);
}

static __always_inline __be16 flow_source_port(__u32 hash) {
  return bpf_htons(49152 | (hash & 0x3fff));
}

#endif
