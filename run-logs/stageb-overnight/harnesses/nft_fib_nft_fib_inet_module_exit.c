#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t data[1]; // Opaque array to represent a kernel type
} nft_expr_type;

extern void nft_unregister_expr(nft_expr_type *type);

#ifdef CBMC_HARNESS
int main(void) {
    __CPROVER_assume(sizeof(nft_expr_type) > 0); // Ensure the struct is non-empty

    nft_expr_type nft_fib_inet_type;
    /* @CONTRACTS */
    nft_unregister_expr(&nft_fib_inet_type);

    return 0;
}
#endif
