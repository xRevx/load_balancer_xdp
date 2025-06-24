#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>

#define XDP_SERVER_PORT 8000
#define SERVER_COUNT 4
#define PACKETS_PER_SERVER 15
#define START_PORT 8001  // First backend server

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2); // 0 = counter, 1 = server index
    __type(key, __u32);
    __type(value, __u32);
} rr_map SEC(".maps");

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    return ~((csum & 0xffff) + (csum >> 16));
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return XDP_DROP;

    if (tcph->dest != htons(XDP_SERVER_PORT))
        return XDP_PASS;

    __u32 key_counter = 0;
    __u32 key_index = 1;

    __u32 *counter = bpf_map_lookup_elem(&rr_map, &key_counter);
    __u32 *server_idx = bpf_map_lookup_elem(&rr_map, &key_index);

    if (!counter || !server_idx) {
        return XDP_PASS;
    }

    if (*counter >= PACKETS_PER_SERVER) {
        *counter = 0;
        *server_idx = (*server_idx + 1) % SERVER_COUNT;
    }

    __u16 new_port = htons(START_PORT + *server_idx);
    __u16 old_port = tcph->dest;

    tcph->dest = new_port;

    // Recalculate TCP checksum
    __u32 csum = bpf_csum_diff(&old_port, sizeof(old_port), &new_port, sizeof(new_port), ~tcph->check);
    tcph->check = csum_fold_helper(csum);

    bpf_printk("server_idx=%d, counter=%d\n", *server_idx, *counter);

    // Update counter
    (*counter)++;

    return XDP_PASS;
}