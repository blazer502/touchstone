#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) nf_conntrack_zone;

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) nf_conntrack_tuple_hash;

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) nf_conntrack_tuple;

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) nf_conn;

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) nf_conncount_list;

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) nf_conncount_tuple;

static int get_ct_or_tuple_from_skb(struct net *net, const struct sk_buff *skb,
                                    u16 l3num, struct nf_conn **ct,
                                    struct nf_conntrack_tuple *tuple,
                                    const struct nf_conntrack_zone **zone,
                                    bool *refcounted) {
    __CPROVER_assume(*ct == NULL);
    return 0;
}

static int nf_ct_is_confirmed(struct nf_conn *ct) {
    return 0;
}

static int nf_ct_zone_id(const struct nf_conntrack_zone *zone, int dir) {
    return 0;
}

static bool nf_ct_tuple_equal(const struct nf_conntrack_tuple *a,
                              const struct nf_conntrack_tuple *b) {
    return a == b;
}

static bool nf_ct_zone_equal(const struct nf_conn *ct,
                             const struct nf_conntrack_zone *zone, int dir) {
    return ct == zone;
}

static bool already_closed(struct nf_conn *found_ct) {
    return 0;
}

static void nf_ct_put(struct nf_conn *ct) {}

static void conn_free(nf_conncount_list *list, nf_conncount_tuple *conn) {}

static struct nf_conntrack_zone nf_ct_zone_dflt = {0};

static struct nf_conntrack_tuple_hash find_or_evict(struct net *net,
                                                   nf_conncount_list *list,
                                                   nf_conncount_tuple *conn) {
    return (struct nf_conntrack_tuple_hash){};
}

static unsigned int jiffies = 0;

static void __attribute__((constructor)) init(void) {
    conncount_conn_cachep = (void *)1;
}

static struct kmem_cache *conncount_conn_cachep;

#ifdef CBMC_HARNESS
int main(void) {
    struct net net;
    struct sk_buff skb;
    u16 l3num = 0;
    nf_conncount_list list;
    int err;

    __CPROVER_assume(list.count == 0);
    __CPROVER_assume(list.last_gc == 0);
    __CPROVER_assume(list.last_gc_count == 0);

    /* @CONTRACTS */
    err = __nf_conncount_add(&net, &skb, l3num, &list);

    return err;
}
#endif
