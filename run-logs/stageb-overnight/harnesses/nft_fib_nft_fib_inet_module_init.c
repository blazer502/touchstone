#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t data[1]; // Opaque array to represent a kernel type
} nft_expr_type;

extern int nft_register_expr(nft_expr_type *type);

#ifdef CBMC_HARNESS
int main(void) {
    __CPROVER_assume(sizeof(nft_expr_type) > 0); // Ensure the struct is non-empty

    nft_expr_type nft_fib_inet_type;
    /* @CONTRACTS */
    return nft_register_expr(&nft_fib_inet_type);
}
#endif
