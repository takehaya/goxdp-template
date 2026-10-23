#ifndef TC_UTILS_H
#define TC_UTILS_H

// Restore the VLAN header that the receive stack moved into skb metadata.
static __always_inline int restore_vlan(struct __sk_buff* skb) {
  if (!skb->vlan_present) return 0;
  __u8 header[18];
  __be16 protocol = skb->vlan_proto;
  __be16 tag = bpf_htons(skb->vlan_tci);
  if (bpf_skb_load_bytes(skb, 0, header, 12) ||
      bpf_skb_load_bytes(skb, 12, header + 16, 2))
    return -1;
  __builtin_memcpy(header + 12, &protocol, 2);
  __builtin_memcpy(header + 14, &tag, 2);
  if (bpf_skb_vlan_pop(skb) || bpf_skb_change_head(skb, 4, 0)) return -1;
  return bpf_skb_store_bytes(skb, 0, header, sizeof(header), 0);
}

#endif
