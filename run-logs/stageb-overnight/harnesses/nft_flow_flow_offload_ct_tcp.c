#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t flags;
} tcp_seen;

typedef struct {
    tcp_seen seen[2];
} proto_tcp;

typedef struct {
    proto_tcp proto;
    void *lock; // Opaque pointer, assume it's valid
} nf_conn;

#ifdef CBMC_HARNESS
int main(void) {
    __CPROVER_assume(ct != NULL);
    __CPROVER_assume(ct->lock != NULL);

    flow_offload_ct_tcp(ct);

    return 0;
}
#endif

static void flow_offload_ct_tcp(struct nf_conn *ct)
{
    /* conntrack will not see all packets, disable tcp window validation. */
    spin_lock_bh(&ct->lock);
    ct->proto.tcp.seen[0].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
    ct->proto.tcp.seen[1].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
    spin_unlock_bh(&ct->lock);
}
