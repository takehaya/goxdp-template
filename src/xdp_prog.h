#ifndef XDP_PROG_H
#define XDP_PROG_H
#include <linux/types.h>

volatile const __u32 cpu_count; // replace by Go program

#ifdef XDP_DEBUG
#define DEBUG_PRINT(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) (void)0
#endif

// TEST ONLY
// NOTE: ebpf map が
// unionに対応してないので、bpf_fib_lookupからunionを圧縮した構造体を作成 cf.
// https://github.com/torvalds/linux/blob/cf1182944c7cc9f1c21a8a44e0d29abe12527412/include/uapi/linux/bpf.h#L7026
struct bpf_fib_lookup_mock {
  /* input:  network family for lookup (AF_INET, AF_INET6)
   * output: network family of egress nexthop
   */
  __u8 family;

  /* set if lookup is to consider L4 data - e.g., FIB rules */
  __u8 l4_protocol;
  __be16 sport;
  __be16 dport;

  __u16 tot_len2mtu_result; // input tot_len -> output mtu_result

  /* input: L3 device index for lookup
   * output: device index from FIB lookup
   */
  __u32 ifindex;

  __be32 tos_or_flowinfo2rt_metric; // input tos_or_flowinfo -> output rt_metric

  __u32 ipv4_src_or_ipv6_src[4]; // ipv4 or ipv6 src

  __u32 ipv4_dst_or_ipv6_dst[4]; // ipv4 or ipv6 dst

  __u32 h_vlan_proto_and_TCI2tbid; // input h_vlan_proto and h_vlan_TCI ->
                                   // output tbid

  __u8 smac[6]; /* ETH_ALEN */
  __u8 dmac[6]; /* ETH_ALEN */
};

struct fib_lookup_mock_result {
  struct bpf_fib_lookup_mock params;
  __u8 status; // 0: BPF_FIB_LKUP_RET_SUCCESS, 1: BPF_FIB_LKUP_RET_BLACKHOLE,...
};

// vlan header
struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

// cf.
// https://github.com/torvalds/linux/blob/master/include/net/vxlan.h#L13C1-L41C41
#define IANA_VXLAN_UDP_PORT 4789
#define IANA_VXLAN_GPE_UDP_PORT 4790

/* VXLAN protocol (RFC 7348) header:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |R|R|R|R|I|R|R|R|               Reserved                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                VXLAN Network Identifier (VNI) |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * I = VXLAN Network Identifier (VNI) present.
 */
struct vxlanhdr {
  __be32 vx_flags;
  __be32 vx_vni;
};

/* VXLAN header flags. */
#define VXLAN_HF_VNI cpu_to_be32(BIT(27))

#define VXLAN_N_VID (1u << 24)
#define VXLAN_VID_MASK (VXLAN_N_VID - 1)
#define VXLAN_VNI_MASK cpu_to_be32(VXLAN_VID_MASK << 8)
#define VXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct vxlanhdr))

#define VNI_HASH_BITS 10
#define VNI_HASH_SIZE (1 << VNI_HASH_BITS)
#define FDB_HASH_BITS 8
#define FDB_HASH_SIZE (1 << FDB_HASH_BITS)

#endif // XDP_PROG_H
