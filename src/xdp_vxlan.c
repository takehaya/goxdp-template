#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define VXLAN_PORT 4789
#define VXLAN_I 0x08000000
#include "xdp_dispatch.h"
#include "xdp_flow.h"

#define FROM_TUNNEL 1
#define HEADER_READY 2
#define VXLAN_OVERHEAD 50

#ifndef NO_CPUMAP
const volatile __u32 cpu_count = 0;
#endif
#define ACCESS 1
#define TUNNEL 2
#define VLAN_ACCESS 3

struct vxlan_header {
  __be32 flags;
  __be32 vni;
};

struct port_config {
  __u32 kind;
  __u32 vni;
  __be32 local_ip;
  __u32 mtu;
  __u8 mac[ETH_ALEN];
  __u8 pad[2];
};

struct vni_config {
  __be32 multicast_ip;
  __u32 revision;
};

struct peer_key {
  __u32 vni;
  __u32 ifindex;
};

struct vlan_key {
  __u32 ifindex;
  __u32 vid;
};

struct peer_config {
  __be32 remote_ip;
  __u8 mac[ETH_ALEN];
  __u8 pad[2];
};

struct cached_peer {
  struct peer_config peer;
  __u32 revision;
};

struct cached_header {
  // Two bytes before Ethernet keep the IPv4 header aligned on the BPF stack.
  __u16 valid;
  __u8 bytes[VXLAN_OVERHEAD];
} __attribute__((aligned(4)));

struct fdb_key {
  __u32 vni;
  __u8 mac[ETH_ALEN];
  __u8 pad[2];
};

struct pipeline_counters {
  __u64 header_preparations;
  __u64 cpu_packets;
};

struct group_ports {
  __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
  __uint(max_entries, 64);
  __type(key, __u32);
  __uint(value_size, sizeof(struct bpf_devmap_val));
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 64);
  __type(key, __u32);
  __array(values, struct group_ports);
} vni_groups SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u32);
  __type(value, struct port_config);
} ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, struct vlan_key);
  __type(value, __u32);
} vlan_bindings SEC(".maps");

// Static admission and egress tag policy, independent of live flood subsets.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, struct peer_key);
  __type(value, __u32);
} port_vnis SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, __u32);
  __type(value, struct vni_config);
} vnis SEC(".maps");

// Configured routes survive cache eviction. Cache values belong to the CPU
// running the egress program; a new CPU must fill its own value slot.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct peer_key);
  __type(value, struct peer_config);
} peers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __uint(max_entries, 1024);
  __type(key, struct peer_key);
  __type(value, struct cached_peer);
} peer_cache SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, struct cached_header);
} header_cache SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct fdb_key);
  __type(value, __u32);
} fdb SEC(".maps");

// Tail-call tables are separate because CPUMAP and devmap attach types differ.
#ifndef NO_CPUMAP
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, PROGRAM_COUNT);
  __type(key, __u32);
  __type(value, __u32);
} cpu_programs SEC(".maps");
#endif

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, PROGRAM_COUNT);
  __type(key, __u32);
  __type(value, __u32);
} devmap_programs SEC(".maps");

#ifndef NO_CPUMAP
struct {
  __uint(type, BPF_MAP_TYPE_CPUMAP);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bpf_cpumap_val);
} cpu_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} cpu_ids SEC(".maps");
#endif

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct pipeline_counters);
} pipeline_stats SEC(".maps");

// VLAN-aware ports accept exactly one inline 802.1Q tag, VID 1..4094.
static __always_inline int inner_vlan(void* data, void* end) {
  struct ethhdr* eth = data;
  if ((void*)(eth + 1) > end || eth->h_proto != bpf_htons(ETH_P_8021Q))
    return -1;
  struct {
    __be16 tci;
    __be16 protocol;
  }* tag = (void*)(eth + 1);
  if ((void*)(tag + 1) > end ||
      tag->protocol == bpf_htons(ETH_P_8021Q) ||
      tag->protocol == bpf_htons(ETH_P_8021AD))
    return -1;
  __u32 vid = bpf_ntohs(tag->tci) & 0xfff;
  return vid && vid < 4095 ? (int)vid : -1;
}

static __always_inline int access_allowed(struct port_config* port,
                                           __u32 output, __u32 vni,
                                           void* data, void* end) {
  if (port->kind == ACCESS) return port->vni == vni;
  if (port->kind != VLAN_ACCESS) return 0;
  int vid = inner_vlan(data, end);
  if (vid < 0) return 0;
  struct peer_key key = {.vni = vni, .ifindex = output};
  __u32* expected = bpf_map_lookup_elem(&port_vnis, &key);
  return expected && *expected == (__u32)vid;
}

static __always_inline void checksum(struct iphdr* ip) {
  ip->check = 0;
  __u32 sum = 0;
  __u16* words = (void*)ip;
#pragma unroll
  for (int i = 0; i < 10; i++) sum += words[i];
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  ip->check = ~sum;
}

static __always_inline int valid_ipv4_checksum(struct iphdr* ip, void* end) {
  __u32 words = ip->ihl * 2;
  __u32 sum = 0;
#pragma unroll
  for (int i = 0; i < 30; i++) {
    if (i < words) {
      __u16* word = (void*)ip + i * 2;
      if ((void*)(word + 1) > end) return 0;
      sum += *word;
    }
  }
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return (__u16)sum == 0xffff;
}

// The shared header depends only on VNI and length, so equal keys are safe
// across packets and CPUs; no packet lifetime or last-copy tracking is needed.
static __always_inline __u64 header_key(__u32 vni, __u32 inner_len) {
  return ((__u64)vni << 32) | inner_len;
}

static __always_inline int build_header(struct cached_header* header, __u32 vni,
                                        __u32 inner_len) {
  if (inner_len > 65535 - (VXLAN_OVERHEAD - ETH_HLEN)) return -1;
  __u32 ip_len = inner_len + VXLAN_OVERHEAD - ETH_HLEN;
  *header = (struct cached_header){};
  struct ethhdr* eth = (void*)header->bytes;
  *eth = (struct ethhdr){.h_proto = bpf_htons(ETH_P_IP)};
  struct iphdr* ip = (void*)(eth + 1);
  *ip = (struct iphdr){.version = 4,
                       .ihl = 5,
                       .ttl = 64,
                       .protocol = IPPROTO_UDP,
                       .frag_off = bpf_htons(0x4000),
                       .tot_len = bpf_htons(ip_len)};
  checksum(ip);
  struct udphdr* udp = (void*)(ip + 1);
  // The flow-specific source port is filled after copying the shared template.
  *udp = (struct udphdr){.dest = bpf_htons(VXLAN_PORT),
                         .len = bpf_htons(ip_len - sizeof(*ip))};
  struct vxlan_header* vxlan = (void*)(udp + 1);
  vxlan->flags = bpf_htonl(VXLAN_I);
  vxlan->vni = bpf_htonl(vni << 8);
  header->valid = 1;
  return 0;
}

static __always_inline int valid_header(struct cached_header* header, __u32 vni,
                                        __u32 inner_len) {
  struct ethhdr* eth = (void*)header->bytes;
  struct iphdr* ip = (void*)(eth + 1);
  struct udphdr* udp = (void*)(ip + 1);
  struct vxlan_header* vxlan = (void*)(udp + 1);
  return header->valid && eth->h_proto == bpf_htons(ETH_P_IP) &&
         ip->version == 4 && ip->ihl == 5 && ip->ttl == 64 &&
         ip->protocol == IPPROTO_UDP && ip->frag_off == bpf_htons(0x4000) &&
         ip->tot_len == bpf_htons(inner_len + VXLAN_OVERHEAD - ETH_HLEN) &&
         udp->source == 0 && udp->dest == bpf_htons(VXLAN_PORT) &&
         udp->len ==
             bpf_htons(inner_len + VXLAN_OVERHEAD - ETH_HLEN - sizeof(*ip)) &&
         vxlan->flags == bpf_htonl(VXLAN_I) &&
         vxlan->vni == bpf_htonl(vni << 8);
}

// Keep data at Inner: devmap checks access MTUs before running egress handlers.
static __always_inline int prepare_header(struct xdp_md* ctx, __u32 vni) {
  __u32 inner_len = ctx->data_end - ctx->data;
  struct cached_header header;
  if (build_header(&header, vni, inner_len)) return -1;
  __u64 key = header_key(vni, inner_len);
  // Cache insertion is optional; each egress can rebuild the same template.
  bpf_map_update_elem(&header_cache, &key, &header, BPF_ANY);
  __u32 zero = 0;
  struct pipeline_counters* stats = bpf_map_lookup_elem(&pipeline_stats, &zero);
  if (stats) stats->header_preparations++;
  return 0;
}

static __always_inline int forward_frame(struct xdp_md* ctx) {
#ifdef TC_BACKEND
  return XDP_PASS;
#else
  struct xdp_command* command = read_command(ctx);
  if (!command || command->program != PROGRAM_FORWARD) return XDP_DROP;
  __u32 vni = command->args.vxlan.vni;
  __u32 flags = command->args.vxlan.flags;
  __u32 flow_hash = command->args.vxlan.flow_hash;
  __u32 inner_len = ctx->data_end - ctx->data;
  if (command->args.vxlan.inner_len != inner_len) return XDP_DROP;
  if (flags & ~FROM_TUNNEL) return XDP_DROP;
  void* members = bpf_map_lookup_elem(&vni_groups, &vni);
  if (!members) return XDP_DROP;
  void* data = (void*)(long)ctx->data;
  void* end = (void*)(long)ctx->data_end;
  struct ethhdr* eth = data;
  if ((void*)(eth + 1) > end) return XDP_DROP;
  __u32 destination = 0;
  if (!(eth->h_dest[0] & 1)) {
    struct fdb_key key = {.vni = vni};
    __builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN);
    __u32* known = bpf_map_lookup_elem(&fdb, &key);
    if (known) destination = *known;
  }
  if (bpf_xdp_adjust_meta(ctx, sizeof(struct xdp_command))) return XDP_DROP;
  if (!destination && !(flags & FROM_TUNNEL)) {
    if (prepare_header(ctx, vni)) return XDP_DROP;
    flags |= HEADER_READY;
  }
  if (write_command(
          ctx, PROGRAM_REWRITE,
          (union xdp_arguments){.vxlan = {vni, flags, inner_len, flow_hash}}))
    return XDP_DROP;
  if (destination) {
    if (destination == ctx->ingress_ifindex) return XDP_DROP;
    return bpf_redirect_map(members, destination, XDP_DROP);
  }
  return bpf_redirect_map(members, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
#endif
}

SEC("xdp")
int vxlan_ingress(struct xdp_md* ctx) {
  __u32 ingress = ctx->ingress_ifindex;
  struct port_config* port = bpf_map_lookup_elem(&ports, &ingress);
  if (!port) return XDP_PASS;

  void* data = (void*)(long)ctx->data;
  void* end = (void*)(long)ctx->data_end;
  struct ethhdr* eth = data;
  if ((void*)(eth + 1) > end) return XDP_DROP;

  __u32 vni = port->vni;
  __u32 from_tunnel = port->kind == TUNNEL;
  if (port->kind == VLAN_ACCESS) {
    int vid = inner_vlan(data, end);
    if (vid < 0) return XDP_DROP;
    struct vlan_key key = {.ifindex = ingress, .vid = vid};
    __u32* binding = bpf_map_lookup_elem(&vlan_bindings, &key);
    if (!binding) return XDP_DROP;
    vni = *binding;
  }
  if (from_tunnel) {
    // IPv4 underlay; the inner Ethernet frame can carry any EtherType.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr* ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > end || ip->version != 4 || ip->ihl < 5)
      return XDP_DROP;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    // Leave fragmented underlay traffic intact for the host stack.
    if (ip->frag_off & bpf_htons(0x3fff)) return XDP_PASS;
    __u32 ihl = ip->ihl * 4;
    struct udphdr* udp = (void*)ip + ihl;
    if ((void*)(udp + 1) > end) return XDP_DROP;
    if (udp->dest != bpf_htons(VXLAN_PORT)) return XDP_PASS;
    __u32 ip_len = bpf_ntohs(ip->tot_len);
    __u32 udp_len = bpf_ntohs(udp->len);
    if (ip_len <
            ihl + sizeof(*udp) + sizeof(struct vxlan_header) + sizeof(*eth) ||
        (void*)ip + ip_len > end || udp_len != ip_len - ihl)
      return XDP_DROP;
    struct vxlan_header* vxlan = (void*)(udp + 1);
    if ((void*)(vxlan + 1) > end || !(vxlan->flags & bpf_htonl(VXLAN_I)))
      return XDP_DROP;
    vni = bpf_ntohl(vxlan->vni) >> 8;
    struct vni_config* group = bpf_map_lookup_elem(&vnis, &vni);
    if (!group) return XDP_DROP;
    if (ip->daddr != port->local_ip && ip->daddr != group->multicast_ip)
      return XDP_PASS;
    struct peer_key member = {.vni = vni, .ifindex = ingress};
    if (!bpf_map_lookup_elem(&port_vnis, &member)) return XDP_DROP;
    if (!valid_ipv4_checksum(ip, end)) return XDP_DROP;

    // Remove Ethernet padding beyond the advertised outer IP packet as well.
    __u32 frame_len = ctx->data_end - ctx->data;
    int trim = (int)(sizeof(*eth) + ip_len) - (int)frame_len;
    if (trim && bpf_xdp_adjust_tail(ctx, trim)) return XDP_DROP;
    int offset = sizeof(*eth) + ihl + sizeof(*udp) + sizeof(*vxlan);
    if (bpf_xdp_adjust_head(ctx, offset)) return XDP_DROP;
  }

  data = (void*)(long)ctx->data;
  end = (void*)(long)ctx->data_end;
  __u32 flow_hash = inner_flow_hash(data, end, vni);
  __u32 inner_len = ctx->data_end - ctx->data;
  if (write_command(
          ctx, PROGRAM_FORWARD,
          (union xdp_arguments){.vxlan = {vni, from_tunnel ? FROM_TUNNEL : 0,
                                          inner_len, flow_hash}}))
    return XDP_DROP;
#ifndef NO_CPUMAP
  if (cpu_count) {
    __u32 slot = flow_hash % cpu_count;
    __u32* cpu = bpf_map_lookup_elem(&cpu_ids, &slot);
    if (!cpu) return XDP_DROP;
    return bpf_redirect_map(&cpu_map, *cpu, XDP_DROP);
  }
#endif
  return forward_frame(ctx);
}

#ifndef NO_CPUMAP
SEC("xdp/cpumap")
int vxlan_cpu(struct xdp_md* ctx) {
  return dispatch_command(ctx, &cpu_programs);
}

SEC("xdp/cpumap")
int vxlan_cpu_forward(struct xdp_md* ctx) {
  __u32 zero = 0;
  struct pipeline_counters* stats = bpf_map_lookup_elem(&pipeline_stats, &zero);
  if (stats) stats->cpu_packets++;
  return forward_frame(ctx);
}
#endif

SEC("xdp/devmap")
int vxlan_egress(struct xdp_md* ctx) {
  return dispatch_command(ctx, &devmap_programs);
}

static __always_inline int resolve_peer(__u32 vni, __u32 egress,
                                        struct peer_config* result) {
  struct vni_config* group = bpf_map_lookup_elem(&vnis, &vni);
  if (!group) return -1;
  struct peer_config target = {};
  target.remote_ip = group->multicast_ip;
  if (target.remote_ip) {
    __u32 address = bpf_ntohl(target.remote_ip);
    target.mac[0] = 0x01;
    target.mac[2] = 0x5e;
    target.mac[3] = (address >> 16) & 0x7f;
    target.mac[4] = (address >> 8) & 0xff;
    target.mac[5] = address & 0xff;
  } else {
    struct peer_key key = {.vni = vni, .ifindex = egress};
    __u32 revision = group->revision;
    struct cached_peer* cached = bpf_map_lookup_elem(&peer_cache, &key);
    if (cached && cached->revision == revision && revision) {
      target = cached->peer;
    } else {
      struct peer_config* configured = bpf_map_lookup_elem(&peers, &key);
      if (!configured) return -1;
      target = *configured;
      struct cached_peer fresh = {.peer = target, .revision = revision};
      // Filling the cache is optional: a full cache must not lose a packet.
      bpf_map_update_elem(&peer_cache, &key, &fresh, BPF_ANY);
    }
  }
  *result = target;
  return 0;
}

SEC("xdp/devmap")
int vxlan_rewrite(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* end = (void*)(long)ctx->data_end;
  struct xdp_command* command = read_command(ctx);
  if (!command || command->program != PROGRAM_REWRITE) return XDP_DROP;
  __u32 vni = command->args.vxlan.vni;
  __u32 flags = command->args.vxlan.flags;
  __u32 flow_hash = command->args.vxlan.flow_hash;
  __u32 inner_len = command->args.vxlan.inner_len;
  if (flags & ~(FROM_TUNNEL | HEADER_READY)) return XDP_DROP;
  __u32 egress = ctx->egress_ifindex;
  struct port_config* entry = bpf_map_lookup_elem(&ports, &egress);
  if (!entry) return XDP_DROP;
  struct port_config port = *entry;
  if (port.kind == ACCESS || port.kind == VLAN_ACCESS) {
    if (!access_allowed(&port, egress, vni, data, end)) return XDP_DROP;
    return bpf_xdp_adjust_meta(ctx, sizeof(struct xdp_command)) ? XDP_DROP
                                                                : XDP_PASS;
  }
  // Split horizon: a decapsulated frame is never sent back into the overlay.
  if (port.kind != TUNNEL || flags != HEADER_READY) return XDP_DROP;
  struct peer_config target = {};
  if (resolve_peer(vni, egress, &target)) return XDP_DROP;
  if (inner_len != ctx->data_end - ctx->data || inner_len < ETH_HLEN ||
      inner_len + VXLAN_OVERHEAD - ETH_HLEN > port.mtu)
    return XDP_DROP;
  __u64 key = header_key(vni, inner_len);
  struct cached_header header = {};
  struct cached_header* cached = bpf_map_lookup_elem(&header_cache, &key);
  if (cached) header = *cached;
  // Check the private copy: an LRU value can be recycled by another CPU.
  if (!valid_header(&header, vni, inner_len)) {
    // A shared key can have an empty value on this CPU, or be evicted entirely.
    if (build_header(&header, vni, inner_len)) return XDP_DROP;
    bpf_map_update_elem(&header_cache, &key, &header, BPF_ANY);
  }
  if (bpf_xdp_adjust_meta(ctx, sizeof(struct xdp_command)) ||
      bpf_xdp_adjust_head(ctx, -VXLAN_OVERHEAD))
    return XDP_DROP;
  data = (void*)(long)ctx->data;
  end = (void*)(long)ctx->data_end;
  if (data + VXLAN_OVERHEAD > end) return XDP_DROP;
  __builtin_memcpy(data, header.bytes, VXLAN_OVERHEAD);
  struct ethhdr* eth = data;
  struct iphdr* ip = (void*)(eth + 1);
  struct udphdr* udp = (void*)(ip + 1);
  udp->source = flow_source_port(flow_hash);
  __builtin_memcpy(eth->h_source, port.mac, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, target.mac, ETH_ALEN);
  ip->saddr = port.local_ip;
  ip->daddr = target.remote_ip;
  checksum(ip);
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
