#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) nft_expr;

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) nft_regs;

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) nft_pktinfo;

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) nft_fib;

static void nft_fib4_eval(const struct nft_expr *expr, struct nft_regs *regs, const struct nft_pktinfo *pkt) {}
static void nft_fib6_eval(const struct nft_expr *expr, struct nft_regs *regs, const struct nft_pktinfo *pkt) {}
static void nft_fib4_eval_type(const struct nft_expr *expr, struct nft_regs *regs, const struct nft_pktinfo *pkt) {}
static void nft_fib6_eval_type(const struct nft_expr *expr, struct nft_regs *regs, const struct nft_pktinfo *pkt) {}

static uint32_t __CPROVER_nondet_uint32(void);
static uint8_t __CPROVER_nondet_byte(void);

static inline unsigned int nft_pf(const struct nft_pktinfo *pkt) {
    return __CPROVER_nondet_uint32();
}

static inline const void *nft_expr_priv(const struct nft_expr *expr) {
    return &expr->data;
}

#ifdef CBMC_HARNESS
int main(void) {
    struct nft_expr expr;
    struct nft_regs regs;
    struct nft_pktinfo pkt;

    __CPROVER_assume(nft_pf(&pkt) == NFPROTO_IPV4 || nft_pf(&pkt) == NFPROTO_IPV6);

    nft_fib_inet_eval(&expr, &regs, &pkt);
}
#endif

/* @CONTRACTS */
static void nft_fib_inet_eval(const struct nft_expr *expr,
			      struct nft_regs *regs,
			      const struct nft_pktinfo *pkt)
{
	const struct nft_fib *priv = nft_expr_priv(expr);

	switch (nft_pf(pkt)) {
	case NFPROTO_IPV4:
		switch (priv->result) {
		case NFT_FIB_RESULT_OIF:
		case NFT_FIB_RESULT_OIFNAME:
			return nft_fib4_eval(expr, regs, pkt);
		case NFT_FIB_RESULT_ADDRTYPE:
			return nft_fib4_eval_type(expr, regs, pkt);
		}
		break;
	case NFPROTO_IPV6:
		switch (priv->result) {
		case NFT_FIB_RESULT_OIF:
		case NFT_FIB_RESULT_OIFNAME:
			return nft_fib6_eval(expr, regs, pkt);
		case NFT_FIB_RESULT_ADDRTYPE:
			return nft_fib6_eval_type(expr, regs, pkt);
		}
		break;
	}

	regs->verdict.code = NF_DROP;
}
