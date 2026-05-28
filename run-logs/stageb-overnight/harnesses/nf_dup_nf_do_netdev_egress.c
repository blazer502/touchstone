#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(1))) sk_buff;

typedef struct {
    uint8_t data[1];
} __attribute__((aligned(1))) net_device;

enum nf_dev_hooks {
    NF_NETDEV_INGRESS,
    NF_NETDEV_EGRESS
};

#define NF_RECURSION_LIMIT 10

extern unsigned int __this_cpu_read(unsigned int var);
extern void __this_cpu_inc(unsigned int *var);
extern void __this_cpu_dec(unsigned int *var);
extern void dev_queue_xmit(sk_buff *skb);
extern void kfree_skb(sk_buff *skb);

void nf_do_netdev_egress(sk_buff *skb, net_device *dev, enum nf_dev_hooks hook) {
    if (__this_cpu_read(nf_dup_skb_recursion) > NF_RECURSION_LIMIT)
        goto err;

    if (hook == NF_NETDEV_INGRESS && skb_mac_header_was_set(skb)) {
        if (skb_cow_head(skb, skb->mac_len))
            goto err;

        skb_push(skb, skb->mac_len);
    }

    skb->dev = dev;
    skb_clear_tstamp(skb);
    __this_cpu_inc(nf_dup_skb_recursion);
    dev_queue_xmit(skb);
    __this_cpu_dec(nf_dup_skb_recursion);
    return;
err:
    kfree_skb(skb);
}

#ifdef CBMC_HARNESS
int main(void) {
    sk_buff skb = {0};
    net_device dev = {0};

    __CPROVER_assume(skb.mac_len >= 0);
    __CPROVER_assume(skb.data != NULL);

    nf_do_netdev_egress(&skb, &dev, NF_NETDEV_EGRESS);

    return 0;
}
#endif
