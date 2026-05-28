#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) nf_lwtunnel_net_ops;

extern int register_pernet_subsys(const void *ops);

#ifdef CBMC_HARNESS
int main(void) {
    nf_lwtunnel_net_ops ops;
    __CPROVER_assume(__CPROVER_is_fresh(&ops, sizeof(ops)));

    /* @CONTRACTS */
    return register_pernet_subsys(&ops);
}
#endif
