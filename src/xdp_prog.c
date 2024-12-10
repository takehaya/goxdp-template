#include "xdp_prog.h"
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
int xdp_prog(struct xdp_md *ctx)
{
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
		return XDP_DROP;

	if (eth->h_proto == bpf_htons(ETH_P_8021Q))
	{
		struct vlan_hdr *vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return XDP_DROP;

		l3proto = vhdr->h_vlan_encapsulated_proto;
	}
	else
	{
		l3proto = eth->h_proto;
	}

	// IPv4, IPv6only
	if (l3proto == bpf_htons(ETH_P_IP))
	{
		iph = data + nh_off;
		nh_off += sizeof(struct iphdr);
		if (data + nh_off > data_end)
			return XDP_DROP;

		l4proto = iph->protocol;
	}
	else if (l3proto == bpf_htons(ETH_P_IPV6))
	{
		ip6h = data + nh_off;
		nh_off += sizeof(struct ip6_hdr);
		if (data + nh_off > data_end)
			return XDP_DROP;

		l4proto = ip6h->ip6_nxt;
	}
	else
	{
		return XDP_PASS;
	}

	// check vxlan packet
	if (l4proto == IPPROTO_UDP)
	{
		struct udphdr *udph = data + nh_off;
		nh_off += sizeof(struct udphdr);
		if (data + nh_off > data_end)
			return XDP_DROP;

		// decap case
		if (udph->dest == bpf_htons(IANA_VXLAN_UDP_PORT))
		{
			// struct vxlanhdr *vxlanh = data + nh_off;
			nh_off += sizeof(struct vxlanhdr);
			if (data + nh_off > data_end)
				return XDP_DROP;

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
		return XDP_DROP;

	if (eth->h_proto == bpf_htons(ETH_P_8021Q))
	{
		struct vlan_hdr *vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return XDP_DROP;

		l3proto = vhdr->h_vlan_encapsulated_proto;
	}
	else
	{
		l3proto = eth->h_proto;
	}

	if (l3proto == bpf_htons(ETH_P_IP))
	{
		iph = data + nh_off;
		nh_off += sizeof(struct iphdr);
		if (data + nh_off > data_end)
			return XDP_DROP;

		l4proto = iph->protocol;
	}
	else if (l3proto == bpf_htons(ETH_P_IPV6))
	{
		ip6h = data + nh_off;
		nh_off += sizeof(struct ip6_hdr);
		if (data + nh_off > data_end)
			return XDP_DROP;

		l4proto = ip6h->ip6_nxt;
	}
	else
	{
		return XDP_PASS;
	}

	// vxlan encap case
	// TODO: encap vxlan packet

	// mock example: fiblookup
	struct bpf_fib_lookup params = {};
	if (l3proto == bpf_htons(ETH_P_IP))
	{
		if (!ipv4_fib_lookup(ctx, &params, iph, 1, BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT)) // 1 hardcoded ifindex
		{
			DEBUG_PRINT("impl_downlink_ip4handler ipv4_fib_lookup failed");
			return XDP_PASS;
		}
	}
	else if (l3proto == bpf_htons(ETH_P_IPV6))
	{
		if (!ipv6_fib_lookup(ctx, &params, ip6h, 1, BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT)) // 1 hardcoded ifindex
		{
			DEBUG_PRINT("impl_downlink_ip6handler ipv6_fib_lookup failed");
			return XDP_PASS;
		}
	}
	else
	{
		return XDP_PASS;
	}
	__builtin_memcpy(eth->h_source, params.smac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, params.dmac, ETH_ALEN);
	return XDP_TX;
}

char __license[] SEC("license") = "Dual MIT/GPL";
