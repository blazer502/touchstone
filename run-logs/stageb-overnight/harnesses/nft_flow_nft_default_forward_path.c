#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t ifindex;
} net_device;

typedef struct {
    net_device *dev;
} dst_entry;

typedef struct {
    void *in;
    void *dst;
    int xmit_type;
} nft_tuple;

typedef struct {
    nft_tuple tuple[2];
} nf_flow_route;

enum ip_conntrack_dir {
    IP_CT_DIR_ORIGINAL,
    IP_CT_DIR_REPLY
};

int nft_xmit_type(dst_entry *dst_cache) __CPROVER_pure;

#ifdef CBMC_HARNESS
int main(void) {
    nf_flow_route route;
    dst_entry dst_cache;
    net_device dev;
    dst_cache.dev = &dev;
    uint8_t dir = __CPROVER_nondet_uint8();
    __CPROVER_assume(dir == IP_CT_DIR_ORIGINAL || dir == IP_CT_DIR_REPLY);

    nft_default_forward_path(&route, &dst_cache, (enum ip_conntrack_dir)dir);

    return 0;
}
#endif

/* @CONTRACTS */
void nft_default_forward_path(nf_flow_route *route,
                              dst_entry *dst_cache,
                              enum ip_conntrack_dir dir)
{
    route->tuple[!dir].in.ifindex = dst_cache->dev->ifindex;
    route->tuple[dir].dst = dst_cache;
    route->tuple[dir].xmit_type = nft_xmit_type(dst_cache);
}
