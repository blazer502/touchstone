#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) net_device;

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) sk_buff;

typedef struct {
    sk_buff *skb;
} nft_pktinfo;

extern net_device* dev_get_by_index_rcu(void*, int);
extern void kfree_skb(sk_buff*);
extern void nf_do_netdev_egress(sk_buff*, net_device*, int);

void nf_fwd_netdev_egress(const nft_pktinfo *pkt, int oif)
{
    struct net_device *dev;

    dev = dev_get_by_index_rcu(nft_net(pkt), oif);
    if (!dev) {
        kfree_skb(pkt->skb);
        return;
    }

    nf_do_netdev_egress(pkt->skb, dev, nft_hook(pkt));
}

#ifdef CBMC_HARNESS
int main(void)
{
    __CPROVER_assume(oif >= 0);

    nft_pktinfo pkt;
    pkt.skb = (sk_buff*)malloc(sizeof(sk_buff));
    __CPROVER_assume(pkt.skb != NULL);

    nf_fwd_netdev_egress(&pkt, oif);

    free(pkt.skb);
    return 0;
}
#endif
