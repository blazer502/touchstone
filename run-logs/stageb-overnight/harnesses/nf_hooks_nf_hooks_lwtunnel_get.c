#include <stdint.h>
#include <stddef.h>

#define static_branch_unlikely(x) __CPROVER_assume(!*(x))

extern uint8_t nf_hooks_lwtunnel_enabled[];

/* @CONTRACTS */
int main(void)
{
    return nf_hooks_lwtunnel_get();
}
