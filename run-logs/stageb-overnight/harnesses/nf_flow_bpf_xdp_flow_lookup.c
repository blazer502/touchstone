#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t s_addr;
} __attribute__((packed)) in_addr_t;

typedef struct {
    uint8_t s6_addr[16];
} __attribute__((packed)) in6_addr_t;

typedef struct {
    uint32_t ifindex;
    uint8_t family;
    uint8_t l4_protocol;
    uint16_t sport;
    uint16_t dport;
    in_addr_t ipv4_src;
    in_addr_t ipv4_dst;
    in6_addr_t ipv6_src;
    in6_addr_t ipv6_dst;
} __attribute__((packed)) bpf_fib_lookup;

typedef struct {
    uint32_t error;
} __attribute__((packed)) bpf_flowtable_opts;

typedef struct {
    void *dev;
} __attribute__((packed)) xdp_rxq_info;

typedef struct {
    xdp_rxq_info rxq;
} __attribute__((packed)) xdp_buff;

typedef struct flow_offload_tuple_rhash {
    uint8_t data[16];
} __attribute__((packed)) flow_offload_tuple_rhash;

struct bpf_xdp_flow_lookup_harness {
    xdp_md ctx;
    bpf_fib_lookup fib_tuple;
    bpf_flowtable_opts opts;
    u32 opts_len;
};

#ifdef CBMC_HARNESS
int main(void) {
    struct bpf_xdp_flow_lookup_harness harness;

    __CPROVER_assume(harness.opts_len == NF_BPF_FLOWTABLE_OPTS_SZ);
    __CPROVER_assume(harness.fib_tuple.family == AF_INET || harness.fib_tuple.family == AF_INET6);

    flow_offload_tuple_rhash *result = bpf_xdp_flow_lookup(&harness.ctx, &harness.fib_tuple, &harness.opts, harness.opts_len);

    return 0;
}
#endif

__bpf_kfunc struct flow_offload_tuple_rhash *
bpf_xdp_flow_lookup(struct xdp_md *ctx, struct bpf_fib_lookup *fib_tuple,
		    struct bpf_flowtable_opts *opts, u32 opts_len)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;
	struct flow_offload_tuple tuple = {
		.iifidx = fib_tuple->ifindex,
		.l3proto = fib_tuple->family,
		.l4proto = fib_tuple->l4_protocol,
		.src_port = fib_tuple->sport,
		.dst_port = fib_tuple->dport,
	};
	struct flow_offload_tuple_rhash *tuplehash;
	__be16 proto;

	if (opts_len != NF_BPF_FLOWTABLE_OPTS_SZ) {
		opts->error = -EINVAL;
		return NULL;
	}

	switch (fib_tuple->family) {
	case AF_INET:
		tuple.src_v4.s_addr = fib_tuple->ipv4_src;
		tuple.dst_v4.s_addr = fib_tuple->ipv4_dst;
		proto = htons(ETH_P_IP);
		break;
	case AF_INET6:
		tuple.src_v6 = *(struct in6_addr *)&fib_tuple->ipv6_src;
		tuple.dst_v6 = *(struct in6_addr *)&fib_tuple->ipv6_dst;
		proto = htons(ETH_P_IPV6);
		break;
	default:
		opts->error = -EAFNOSUPPORT;
		return NULL;
	}

	tuplehash = bpf_xdp_flow_tuple_lookup(xdp->rxq.dev, &tuple, proto);
	if (IS_ERR(tuplehash)) {
		opts->error = PTR_ERR(tuplehash);
		return NULL;
	}

	return tuplehash;
}
