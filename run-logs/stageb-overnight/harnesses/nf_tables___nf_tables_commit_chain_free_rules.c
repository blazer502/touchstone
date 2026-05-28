#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t size;
    uint8_t data[];
} __attribute__((aligned(16))) blob_t;

typedef struct {
    blob_t *blob;
} nft_rule_dp_last_t;

void kvfree(void *addr);

#ifdef CBMC_HARNESS
int main(void) {
    extern nft_rule_dp_last_t l;
    __CPROVER_assume(l.blob != NULL);
    __CPROVER_assume(l.blob->size > 0);

    /* @CONTRACTS */
    __nf_tables_commit_chain_free_rules(&l.h);

    return 0;
}
#endif

void __nf_tables_commit_chain_free_rules(struct rcu_head *h) {
    nft_rule_dp_last_t *l = container_of(h, nft_rule_dp_last_t, h);
    kvfree(l->blob);
}

void kvfree(void *addr) {
    // Minimal stub for kvfree
}
