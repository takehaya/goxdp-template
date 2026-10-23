#include "xdp_local.c"
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>

SEC("tc")
int tc_local_receive(struct __sk_buff* skb) {
  if (skb->pkt_type != PACKET_OTHERHOST) return TC_ACT_UNSPEC;
  void* data = (void*)(long)skb->data;
  void* end = (void*)(long)skb->data_end;
  struct ethhdr* eth = data;
  if ((void*)(eth + 1) > end) return TC_ACT_SHOT;
#pragma unroll
  for (int i = 0; i < ETH_ALEN; i++)
    if (eth->h_dest[i] != local_mac[i]) return TC_ACT_UNSPEC;
  // veth can retain OTHERHOST after XDP rewrites a unicast destination MAC.
  if (bpf_skb_change_type(skb, PACKET_HOST)) return TC_ACT_SHOT;
  return TC_ACT_UNSPEC;
}
