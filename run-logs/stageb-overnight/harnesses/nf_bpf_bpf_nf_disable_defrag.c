#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t data[1]; // Opaque array to represent any structure layout
} __attribute__((aligned(8))) bpf_nf_link;

typedef struct {
    void (*disable)(void *);
    void *owner;
} nf_defrag_hook;

typedef struct {
    nf_defrag_hook *defrag_hook;
    uint8_t net[1]; // Opaque array to represent any structure layout
} __attribute__((aligned(8))) bpf_nf_link;

#ifdef CBMC_HARNESS
int main(void) {
    bpf_nf_link link;
    nf_defrag_hook hook;

    __CPROVER_assume(link.defrag_hook == &hook);
    __CPROVER_assume(hook.disable != NULL);
    __CPROVER_assume(hook.owner != NULL);

    /* @CONTRACTS */
    bpf_nf_disable_defrag(&link);

    return 0;
}
#endif
