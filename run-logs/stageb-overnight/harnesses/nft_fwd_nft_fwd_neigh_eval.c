#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t data[128];
} __attribute__((aligned(8))) nft_expr;

typedef struct {
    uint8_t data[128];
} __attribute__((aligned(8))) nft_regs;

typedef struct {
    uint8_t data[128];
} __attribute__((aligned(8))) nft_pktinfo;

typedef struct {
    uint8_t data[128];
} __attribute__((aligned(8))) sk_buff;

typedef struct {
    uint8_t data[128];
} __attribute__((aligned(8))) net_device;

typedef struct {
    uint8_t data[128];
} __attribute__((aligned(8))) nft_net;

static void ip_decrease_ttl(void *iph) {
    ((struct iphdr *)iph)->ttl--;
}

static void ipv6_hdr(void *skb) {
    // Minimal stub
}

static int skb_try_make_writable(void *skb, size_t len) {
    return 0;
}

static struct sk_buff *skb_get(void) {
    __CPROVER_assume(1);
    return (struct sk_buff *)__CPROVER_nondet_pointer();
}

static struct net_device *dev_get_by_index_rcu(nft_net *net, int oif) {
    __CPROVER_assume(1);
    return (struct net_device *)__CPROVER_nondet_pointer();
}

static void neigh_xmit(int neigh_table, net_device *dev, void *addr, sk_buff *skb) {
    // Minimal stub
}

static uint8_t ip_hdr(void *skb) {
    __CPROVER_assume(1);
    return *(uint8_t *)__CPROVER_nondet_pointer();
}

static uint8_t ipv6_hdr_len(void *skb) {
    __CPROVER_assume(1);
    return *(uint8_t *)__CPROVER_nondet_pointer();
}

static int nft_net(void *pktinfo) {
    __CPROVER_assume(1);
    return (int)__CPROVER_nondet_int();
}

#ifdef CBMC_HARNESS
int main(void) {
    struct nft_expr expr;
    struct nft_regs regs;
    struct nft_pktinfo pktinfo;

    __CPROVER_assume(expr.sreg_addr < sizeof(regs.data));
    __CPROVER_assume(expr.sreg_dev < sizeof(regs.data));
    __CPROVER_assume(pktinfo.skb != NULL);

    nft_fwd_neigh_eval(&expr, &regs, &pktinfo);
    return 0;
}
#endif

/* @CONTRACTS */
static void nft_fwd_neigh_eval(const struct nft_expr *expr,
			      struct nft_regs *regs,
			      const struct nft_pktinfo *pkt)
{
	struct nft_fwd_neigh *priv = (struct nft_fwd_neigh *)nft_expr_priv(expr);
	void *addr = &regs->data[priv->sreg_addr];
	int oif = regs->data[priv->sreg_dev];
	unsigned int verdict = NF_STOLEN;
	struct sk_buff *skb = pktinfo.skb;
	struct net_device *dev;
	int neigh_table;

	switch (priv->nfproto) {
	case NFPROTO_IPV4: {
		struct iphdr *iph;

		if (skb->protocol != htons(ETH_P_IP)) {
			verdict = NFT_BREAK;
			goto out;
		}
		if (skb_try_make_writable(skb, sizeof(*iph))) {
			verdict = NF_DROP;
			goto out;
		}
		iph = ip_hdr(skb);
		if (iph->ttl <= 1) {
			verdict = NF_DROP;
			goto out;
		}

		ip_decrease_ttl(iph);
		neigh_table = NEIGH_ARP_TABLE;
		break;
		}
	case NFPROTO_IPV6: {
		struct ipv6hdr *ip6h;

		if (skb->protocol != htons(ETH_P_IPV6)) {
			verdict = NFT_BREAK;
			goto out;
		}
		if (skb_try_make_writable(skb, sizeof(*ip6h))) {
			verdict = NF_DROP;
			goto out;
		}
		ip6h = ipv6_hdr(skb);
		if (ip6h->hop_limit <= 1) {
			verdict = NF_DROP;
			goto out;
		}

		ip6h->hop_limit--;
		neigh_table = NEIGH_ND_TABLE;
		break;
		}
	default:
		verdict = NFT_BREAK;
		goto out;
	}

	dev = dev_get_by_index_rcu(nft_net(pktinfo), oif);
	if (dev == NULL)
		return;

	skb->dev = dev;
	skb_clear_tstamp(skb);
	neigh_xmit(neigh_table, dev, addr, skb);
out:
	regs->verdict.code = verdict;
}
