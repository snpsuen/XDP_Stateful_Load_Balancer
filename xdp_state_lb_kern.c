#include "xdp_state_lb_kern.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))

#define LB 2
#define BACKEND_A 3
#define BACKEND_B 4

struct five_tuple {
    __u8  protocol;
    __u32 ip_source;
    __u32 ip_destination;
    __u16 port_source;
    __u16 port_destination;
};

struct bpf_map_def SEC("maps") return_traffic = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u16),
    .value_size  = sizeof(__u32),
    .max_entries = 100000,
    .map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") forward_flow = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct five_tuple),
    .value_size  = sizeof(__u8),
    .max_entries = 100000,
    .map_flags   = BPF_F_NO_PREALLOC,
};

SEC("xdp_state_lb")
int xdp_state_load_balancer(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct five_tuple forward_key = {};
    __u8* forward_backend;
    __u16 return_key;
    __u32* return_addr;
    __u8 backend;
    __u16 srcport;
    __u32 srcaddr;
    struct bpf_fib_lookup fib_params = {};
    long rc;

    bpf_printk("got something");
    struct ethhdr* eth = data;
    if ((void*)eth + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr* iph = (void*)eth + sizeof(struct ethhdr);
    if ((void*)iph + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr* tcph = (void*)iph + sizeof(struct iphdr);
    if ((void*)tcph + sizeof(struct tcphdr) > data_end)
        return XDP_ABORTED;

    bpf_printk("Got TCP packet travelling from port %d to %d", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
    bpf_printk("Got TCP packet travelling from IP %x to %x", iph->saddr, iph->daddr);
    if ((iph->saddr == IP_ADDRESS(BACKEND_A)) || (iph->saddr == IP_ADDRESS(BACKEND_B))) {
        bpf_printk("Packet returning from the backend %x", iph->saddr);
        bpf_printk("Packet with tcp source port %d", bpf_ntohs(tcph->source));
        bpf_printk("Packet with tcp destination port %d", bpf_ntohs(tcph->dest));
        
        return_key = bpf_ntohs(tcph->dest);
        bpf_printk("Using return key %d to look up the return traffic table", return_key);
        return_addr = bpf_map_lookup_elem(&return_traffic, &return_key);
        bpf_printk("Trying to locate return_addr from the return traffic table ...");
        
        if (return_addr == NULL) {
            bpf_printk("Cannot locate a return path for the destination port %x", return_key);
            return XDP_DROP;
        }
        
        bpf_printk("Located client %x from an existing entry in the return traffic table", *return_addr);
        iph->daddr = *return_addr;
        iph->saddr = IP_ADDRESS(LB);
        
        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(iph->tot_len);
        fib_params.ipv4_src = iph->saddr;
        fib_params.ipv4_dst = iph->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;
        
        rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        bpf_printk("Looked up relevant information in the FIB table with rc %d", rc);
        
        switch(rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            bpf_printk("Found fib_params.dmac = %x:%x:%x", fib_params.dmac[3], fib_params.dmac[4], fib_params.dmac[5]);
            bpf_printk("Found fib_params.smac = %x:%x:%x", fib_params.smac[3], fib_params.smac[4], fib_params.smac[5]);
                
            /* ip_decrease_ttl(iph); */
            memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            iph->check = iph_csum(iph);
            
            /* bpf_printk("Calling fib_params_redirect ...");
            return bpf_redirect(fib_params.ifindex, 0); */
            
            bpf_printk("Before XDP_TX, iph->saddr = %x, iph->daddr = %x", iph->saddr, iph->daddr);
            bpf_printk("Before XDP_TX, eth->h_source[5] = %x, eth->h_dest[5] = %x", eth->h_source[5], eth->h_dest[5]);
            bpf_printk("Returning XDP_TX ...");
            return XDP_TX;
            
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            return XDP_DROP;
        
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
        default:
          return XDP_PASS;
        }  
    }
    else {
        bpf_printk("Packet sent from the client %x", iph->saddr);
        bpf_printk("Packet with tcp source port %d", bpf_ntohs(tcph->source));
        bpf_printk("Packet with tcp destination port %d", bpf_ntohs(tcph->dest));
        
        forward_key.protocol = iph->protocol;
        forward_key.ip_source = iph->saddr;
        forward_key.ip_destination = iph->daddr;
        forward_key.port_source = bpf_ntohs(tcph->source);
        forward_key.port_destination = bpf_ntohs(tcph->dest);
            
        forward_backend = bpf_map_lookup_elem(&forward_flow, &forward_key);
        if (forward_backend == NULL) {
            backend = BACKEND_A;
            if (bpf_get_prandom_u32() % 2)
                backend = BACKEND_B;
            
            bpf_printk("Add a new entry to the forward flow table for backend %x", IP_ADDRESS(backend));
            bpf_map_update_elem(&forward_flow, &forward_key, &backend, BPF_ANY);

            srcport = forward_key.port_source;
            srcaddr = forward_key.ip_source;
            bpf_printk("Add a new entry to the return traffic table to map client port %d to client address %x", srcport, srcaddr);
            bpf_map_update_elem(&return_traffic, &srcport, &srcaddr, BPF_ANY);      
        }
        else {
            bpf_printk("Located backend %x from an existing entry in the forward flow table ", IP_ADDRESS(*forward_backend));
            backend = *forward_backend;
        }
        
        bpf_printk("Packet to be forwrded to backend %x", IP_ADDRESS(backend));
        iph->daddr = IP_ADDRESS(backend);
        iph->saddr = IP_ADDRESS(LB);
        
        eth->h_dest[5] = backend;
        eth->h_source[5] = LB;
        iph->check = iph_csum(iph);
        
        bpf_printk("Before XDP_TX, iph->saddr = %x, iph->daddr = %x", iph->saddr, iph->daddr);
        bpf_printk("Before XDP_TX, eth->h_source[5] = %x, eth->h_dest[5] = %x", eth->h_source[5], eth->h_dest[5]);
        bpf_printk("Returning XDP_TX ...");
        return XDP_TX;
    }
}

char _license[] SEC("license") = "GPL";
