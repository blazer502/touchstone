#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t name[16];
} nft_chain_type;

typedef struct {
    uint32_t family;
    uint32_t type;
} nlattr;

#define NFT_CHAIN_T_MAX 10

nft_chain_type * __nft_chain_type_get(uint32_t family, uint32_t type) {
    // Minimal stub
    return (nft_chain_type *)__CPROVER_nondet_pointer();
}

int nla_strcmp(const nlattr *nla, const char *name) {
    // Minimal stub
    return 0;
}

#ifdef CBMC_HARNESS
int main(void) {
    __CPROVER_assume(family < NFT_CHAIN_T_MAX);

    nlattr nla;
    __CPROVER_assume(nla.family == family);
    __CPROVER_assume(nla.type < NFT_CHAIN_T_MAX);

    const struct nft_chain_type *type = __nf_tables_chain_type_lookup(&nla, family);

    /* @CONTRACTS */

    return 0;
}
#endif
