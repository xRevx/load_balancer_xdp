#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

#define NUMBER_OF_PORTS 4

#define htons(x) __builtin_bswap16(x)
#define ntohs(x) __builtin_bswap16(x)

// Ports to rewrite from (host byte order)
static const __u16 ports_to_rewrite[NUMBER_OF_PORTS] = {8001, 8002, 8003, 8004};
static const __u16 new_port_value = 8000;

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

SEC("tc")
int rewrite_sport(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    int ip_header_len = ip->ihl * 4;
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + ip_header_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u16 sport = ntohs(tcp->source);

#pragma unroll
    for (int i = 0; i < NUMBER_OF_PORTS; i++) {
        if (sport == ports_to_rewrite[i]) {
            __u16 old_port = tcp->source;
            __u16 new_port = htons(new_port_value);

            // Set new source port
            tcp->source = new_port;
            break;
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
