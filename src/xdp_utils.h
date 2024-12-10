#ifndef XDP_UTILS_H
#define XDP_UTILS_H
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "xdp_prog.h"
#include "xdp_map.h"

#ifdef XDP_TEST
// wrapper(test only mocking) of bpf_fib_lookup
static __always_inline bool ipv4_fib_lookup(struct xdp_md *xdp, struct bpf_fib_lookup *params,
                                            struct iphdr *iph, __u32 ifindex, __u32 flags)
{

    struct bpf_fib_lookup_mock map_key = {};

    // ignore tos, tot_len, sport, dport, l4 proto, ifindex
    map_key.family = AF_INET;
    map_key.ipv4_src_or_ipv6_src[0] = iph->saddr;
    map_key.ipv4_dst_or_ipv6_dst[0] = iph->daddr;
    map_key.ifindex = ifindex;

    DEBUG_PRINT("ipv4_fib_lookup (mock) called iph->saddr %x", iph->saddr);
    DEBUG_PRINT("ipv4_fib_lookup (mock) called iph->daddr %x", iph->daddr);
    DEBUG_PRINT("ipv4_fib_lookup (mock) called ifindex %d", ifindex);
    struct fib_lookup_mock_result *mockres = (struct fib_lookup_mock_result *)bpf_map_lookup_elem(&fib_lookup_mock_table, &map_key);
    if (!mockres)
    {
        DEBUG_PRINT("ipv4_fib_lookup (mock) failed, return false");
        return false;
    }
    if (mockres->status != BPF_FIB_LKUP_RET_SUCCESS)
    {
        DEBUG_PRINT("ipv4_fib_lookup (mock) success, but status is not success, return false");
        return false;
    }

    __builtin_memcpy(params, &mockres->params, sizeof(struct bpf_fib_lookup));
    DEBUG_PRINT("ipv4_fib_lookup (mock) success");
    return true;
}

static __always_inline bool ipv6_fib_lookup(struct xdp_md *xdp, struct bpf_fib_lookup *params,
                                            struct ip6_hdr *ip6h, __u32 ifindex, __u32 flags)
{
    struct bpf_fib_lookup_mock map_key = {};

    // ignore tos, tot_len, sport, dport, l4 proto, ifindex
    map_key.family = AF_INET6;
    __builtin_memcpy(map_key.ipv4_src_or_ipv6_src, ip6h->ip6_src.s6_addr, sizeof(ip6h->ip6_src.s6_addr));
    __builtin_memcpy(map_key.ipv4_dst_or_ipv6_dst, ip6h->ip6_dst.s6_addr, sizeof(ip6h->ip6_dst.s6_addr));
    map_key.ifindex = ifindex;

    DEBUG_PRINT("ipv6_fib_lookup (mock) called ifindex %d", ifindex);
    struct fib_lookup_mock_result *mockres = (struct fib_lookup_mock_result *)bpf_map_lookup_elem(&fib_lookup_mock_table, &map_key);
    if (!mockres)
    {
        DEBUG_PRINT("ipv6_fib_lookup (mock) failed, return false");
        return false;
    }
    if (mockres->status != BPF_FIB_LKUP_RET_SUCCESS)
    {
        DEBUG_PRINT("ipv6_fib_lookup (mock) success, but status is not success, return false");
        return false;
    }

    __builtin_memcpy(params, &mockres->params, sizeof(struct bpf_fib_lookup));
    DEBUG_PRINT("ipv6_fib_lookup (mock) success");
    return true;
}
#else
// wrapper of bpf_fib_lookup
// flags: BPF_FIB_LOOKUP_DIRECT, BPF_FIB_LOOKUP_OUTPUT
// https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h#L2611
static __always_inline bool ipv4_fib_lookup(struct xdp_md *xdp, struct bpf_fib_lookup *params,
                                            struct iphdr *iph, __u32 ifindex, __u32 flags)
{
    params->family = AF_INET;
    params->tos = iph->tos;
    params->l4_protocol = iph->protocol;
    params->sport = 0;
    params->dport = 0;
    params->tot_len = bpf_ntohs(iph->tot_len);
    params->ipv4_src = iph->saddr;
    params->ipv4_dst = iph->daddr;
    params->ifindex = ifindex;
    int rc = bpf_fib_lookup(xdp, params, sizeof(struct bpf_fib_lookup), flags);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
        return false;
    return true;
}

static __always_inline bool ipv6_fib_lookup(struct xdp_md *xdp, struct bpf_fib_lookup *params,
                                            struct ip6_hdr *ip6h, __u32 ifindex, __u32 flags)
{
    params->family = AF_INET6;
    params->tos = 0;
    params->l4_protocol = 0;
    params->sport = 0;
    params->dport = 0;
    params->tot_len = 0;
    __builtin_memcpy(params->ipv6_src, ip6h->ip6_src.s6_addr, sizeof(ip6h->ip6_src.s6_addr));
    __builtin_memcpy(params->ipv6_dst, ip6h->ip6_dst.s6_addr, sizeof(ip6h->ip6_dst.s6_addr));
    params->ifindex = ifindex;
    int rc = bpf_fib_lookup(xdp, params, sizeof(struct bpf_fib_lookup), flags);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
        return false;
    return true;
}
#endif // XDP_TEST

#endif // XDP_UTILS_H
