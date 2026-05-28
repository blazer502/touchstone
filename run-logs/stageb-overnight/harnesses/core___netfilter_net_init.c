#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1]; // Opaque array to represent a generic structure
} nf_hook_entries;

#ifdef CBMC_HARNESS
int main(void) {
    __CPROVER_assume(max >= 0);
    nf_hook_entries **e = (__typeof__(e))malloc(sizeof(nf_hook_entries *) * max);
    int max = __CPROVER_nondet_int();

    /* @CONTRACTS */
    __netfilter_net_init(e, max);

    for (int h = 0; h < max; h++) {
        __CPROVER_assert(RCU_POINTER(e[h]) == NULL, "Pointer should be NULL");
    }

    free(e);
    return 0;
}
#endif

static void __net_init
__netfilter_net_init(struct nf_hook_entries __rcu **e, int max)
{
    int h;

    for (h = 0; h < max; h++)
        RCU_INIT_POINTER(e[h], NULL);
}

#define RCU_INIT_POINTER(p, v) (*(p) = (v))
#define RCU_POINTER(p) (*(p))
