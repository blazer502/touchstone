#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) nf_lwtunnel_net_ops;

extern void unregister_pernet_subsys(nf_lwtunnel_net_ops *ops);

#ifdef CBMC_HARNESS
int main(void) {
    /* @CONTRACTS */
    nf_lwtunnel_net_ops ops;
    __CPROVER_assume(__CPROVER_is_fresh(&ops, sizeof(ops)));

    unregister_pernet_subsys(&ops);

    return 0;
}
#endif
