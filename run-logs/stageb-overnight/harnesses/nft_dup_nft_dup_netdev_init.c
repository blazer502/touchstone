#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1]; // Opaque array to represent a register
} __attribute__((aligned(4))) nft_register;

typedef struct {
    uint8_t data[1]; // Opaque array to represent a netdev
} __attribute__((aligned(4))) nft_netdev;

typedef struct {
    uint8_t data[1]; // Opaque array to represent an expression
} __attribute__((aligned(4))) nft_expr;

typedef struct {
    uint8_t data[1]; // Opaque array to represent a context
} __attribute__((aligned(4))) nft_ctx;

typedef struct {
    nft_register sreg_dev;
} __attribute__((aligned(4))) nft_dup_netdev;

#define NFTA_DUP_SREG_DEV 0

static int nft_parse_register_load(const nft_ctx *ctx, const void *data,
                                   nft_register *dest, size_t size)
{
    // Minimal stub for demonstration purposes
    return 0;
}

#ifdef CBMC_HARNESS
int main(void) {
    struct nft_dup_netdev priv;
    struct nft_expr expr;
    struct nlattr tb[1];

    __CPROVER_assume(tb[NFTA_DUP_SREG_DEV] != NULL);

    int result = nft_dup_netdev_init((const struct nft_ctx *)&ctx, (const struct nft_expr *)&expr, tb);
    /* @CONTRACTS */

    return 0;
}
#endif
