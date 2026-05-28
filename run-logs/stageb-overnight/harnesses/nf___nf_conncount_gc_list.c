#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t data[1]; // Opaque array to represent any kernel type
} __attribute__((aligned(8))) nf_conntrack_tuple_hash, nf_conntrack_tuple, nf_conn;

typedef struct {
    uint32_t last_gc;
    unsigned int count;
    uint32_t last_gc_count;
    struct list_head head;
} nf_conncount_list;

struct list_head {
    struct list_head *next, *prev;
};

#define READ_ONCE(x) (x)
#define unlikely(x) (x)
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

static bool already_closed(nf_conn *ct) {
    return __CPROVER_nondet_bool();
}

static int find_or_evict(struct net *net, nf_conncount_list *list, nf_conntrack_tuple *conn) {
    if (__CPROVER_nondet_bool()) {
        return -ENOENT;
    }
    return 0;
}

static void nf_ct_put(nf_conn *ct) {
    // Minimal stub
}

static void conn_free(nf_conncount_list *list, nf_conntrack_tuple *conn) {
    // Minimal stub
}

#ifdef CBMC_HARNESS
int main(void) {
    struct net net;
    nf_conncount_list list = {0};
    list.head.next = &list.head;
    list.head.prev = &list.head;

    __CPROVER_assume(list.count <= 100); // Example constraint

    /* @CONTRACTS */
    return __nf_conncount_gc_list(&net, &list);
}
#endif
