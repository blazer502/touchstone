#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) sk_buff;

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(8))) net_device;

typedef struct {
    const sk_buff *skb;
} nft_pktinfo;

extern void __CPROVER_assume(int condition);
extern void __CPROVER_assert(int condition, const char *msg);

void nf_do_netdev_egress(sk_buff *skb, net_device *dev, int hook);

#ifdef CBMC_HARNESS
int main(void) {
    nft_pktinfo pkt;
    int oif;

    __CPROVER_assume(pkt.skb != NULL);
    __CPROVER_assume(oif >= 0);

    nf_dup_netdev_egress(&pkt, oif);

    return 0;
}
#endif

void nf_dup_netdev_egress(const nft_pktinfo *pkt, int oif) {
    struct net_device *dev;
    struct sk_buff *skb;

    dev = (struct net_device *)__CPROVER_nondet_pointer();
    if (dev == NULL)
        return;

    skb = (struct sk_buff *)__CPROVER_nondet_pointer();
    if (skb)
        nf_do_netdev_egress(skb, dev, 0);
}
