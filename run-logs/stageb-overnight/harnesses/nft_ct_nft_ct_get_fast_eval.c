#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) nft_expr;

typedef struct {
    uint32_t *data;
    uint32_t dreg;
} nft_regs;

typedef struct {
    void *skb;
} nft_pktinfo;

typedef struct {
    uint32_t code;
} nft_verdict;

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) nf_conn;

#define NFT_CT_STATE 0
#define NFT_CT_DIRECTION 1
#define NFT_CT_STATUS 2
#ifdef CONFIG_NF_CONNTRACK_MARK
#define NFT_CT_MARK 3
#endif
#ifdef CONFIG_NF_CONNTRACK_SECMARK
#define NFT_CT_SECMARK 4
#endif

#define NF_CT_STATE_BIT(ctinfo) (ctinfo)
#define NF_CT_STATE_UNTRACKED_BIT 0x1
#define NF_CT_STATE_INVALID_BIT 0x2
#define IP_CT_UNTRACKED 0x1
#define CTINFO2DIR(ctinfo) ((ctinfo) & 0x3)

void nft_ct_get_fast_eval(const struct nft_expr *expr,
                          struct nft_regs *regs,
                          const struct nft_pktinfo *pkt)
{
    const struct nft_ct *priv = (const struct nft_ct *)expr;
    u32 *dest = &regs->data[priv->dreg];
    enum ip_conntrack_info ctinfo;
    const struct nf_conn *ct;
    unsigned int state;

    ct = (const struct nf_conn *)pkt->skb;

    switch (priv->key) {
    case NFT_CT_STATE:
        if (ct)
            state = NF_CT_STATE_BIT(ctinfo);
        else if (ctinfo == IP_CT_UNTRACKED)
            state = NF_CT_STATE_UNTRACKED_BIT;
        else
            state = NF_CT_STATE_INVALID_BIT;
        *dest = state;
        return;
    default:
        break;
    }

    if (!ct) {
        regs->verdict.code = NFT_BREAK;
        return;
    }

    switch (priv->key) {
    case NFT_CT_DIRECTION:
        nft_reg_store8(dest, CTINFO2DIR(ctinfo));
        return;
    case NFT_CT_STATUS:
        *dest = ct->status;
        return;
#ifdef CONFIG_NF_CONNTRACK_MARK
    case NFT_CT_MARK:
        *dest = ct->mark;
        return;
#endif
#ifdef CONFIG_NF_CONNTRACK_SECMARK
    case NFT_CT_SECMARK:
        *dest = ct->secmark;
        return;
#endif
    default:
        // WARN_ON_ONCE(1);
        regs->verdict.code = NFT_BREAK;
        break;
    }
}

/* @CONTRACTS */
int main(void)
{
    __CPROVER_assume(expr != NULL);
    __CPROVER_assume(regs != NULL);
    __CPROVER_assume(pkt != NULL);

    nft_ct_get_fast_eval(expr, regs, pkt);

    return 0;
}
