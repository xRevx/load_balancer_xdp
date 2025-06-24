#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_icmp_reply(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != 1)
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    struct icmphdr *icmp = (void *)ip + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type != ICMP_ECHO)
        return XDP_PASS;

    // Swap MAC addresses
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // Swap IPs
    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    // Modify ICMP
    __u8 tmp_type = ICMP_ECHOREPLY; 
    icmp->type = tmp_type;
    icmp->checksum = 0;

    // Calculate new checksum
    __u16 *start = (__u16 *)icmp;
    __u64 csum = 0;
    void *icmp_end = data_end;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if ((void *)(start + i + 1) > icmp_end)
            break;
        csum += *(__u16 *)(start + i);
    }

    while (csum >> 16)
        csum = (csum & 0xffff) + (csum >> 16);

    icmp->checksum = ~csum;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
