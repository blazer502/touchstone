#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t hook_ref4;
} synproxy_net;

typedef struct {
    // Opaque type for net
} net;

void nf_unregister_net_hooks(net *net, void (*ops[])(void), size_t size) {
    // Minimal stub
}

extern synproxy_net snet;
extern net net;

/* @CONTRACTS */
int main(void) {
    __CPROVER_assume(snet.hook_ref4 >= 0);
    nf_synproxy_ipv4_fini(&snet, &net);
    return 0;
}
