#ifndef XDP_PROG_H
#define XDP_PROG_H
#include <linux/types.h>

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

#endif  // XDP_PROG_H
