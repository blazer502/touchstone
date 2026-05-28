#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) flow_offload_tuple_rhash;

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) nf_flowtable;

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) flow_offload;

struct net_device {
    uint8_t data[1];
};

static inline struct nf_flowtable *nf_flowtable_by_dev(struct net_device *dev) {
    return (struct nf_flowtable *)__CPROVER_nondet_pointer();
}

static inline struct flow_offload_tuple_rhash *
flow_offload_lookup(struct nf_flowtable *nf_flow_table, struct flow_offload_tuple *tuple) {
    return (struct flow_offload_tuple_rhash *)__CPROVER_nondet_pointer();
}

static inline void flow_offload_refresh(struct nf_flowtable *nf_flow_table, struct flow_offload *nf_flow, bool arg2) {
    // Minimal stub
}

static inline struct flow_offload *
container_of(const void *ptr, const void *type, const char *member) {
    return (struct flow_offload *)((char *)ptr - offsetof(type, member));
}

#ifdef CBMC_HARNESS
int main(void) {
    struct net_device dev;
    struct flow_offload_tuple tuple;
    __be16 proto = __CPROVER_nondet_uint16_t();

    __CPROVER_assume(tuple.dir < 2); // Assuming dir is an enum with at most two values

    struct flow_offload_tuple_rhash *result = bpf_xdp_flow_tuple_lookup(&dev, &tuple, proto);

    return 0;
}
#endif

/* @CONTRACTS */
struct flow_offload_tuple_rhash *
bpf_xdp_flow_tuple_lookup(struct net_device *dev,
			  struct flow_offload_tuple *tuple, __be16 proto)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct nf_flowtable *nf_flow_table;
	struct flow_offload *nf_flow;

	nf_flow_table = nf_flowtable_by_dev(dev);
	if (!nf_flow_table)
		return ERR_PTR(-ENOENT);

	tuplehash = flow_offload_lookup(nf_flow_table, tuple);
	if (!tuplehash)
		return ERR_PTR(-ENOENT);

	nf_flow = container_of(tuplehash, struct flow_offload,
			       tuplehash[tuplehash->tuple.dir]);
	flow_offload_refresh(nf_flow_table, nf_flow, false);

	return tuplehash;
}
