#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1]; // Opaque array to represent a net_device
} struct_net_device;

typedef struct {
    uint64_t event;
    void *ptr;
} struct_netdev_notifier_info;

#define NETDEV_DOWN 0x1

static int flow_offload_netdev_event(struct notifier_block *this,
                                     unsigned long event, void *ptr)
{
    struct net_device *dev = (struct net_device *)netdev_notifier_info_to_dev(ptr);

    if (event != NETDEV_DOWN)
        return NOTIFY_DONE;

    nf_flow_table_cleanup(dev);

    return NOTIFY_DONE;
}

#ifdef CBMC_HARNESS
int main(void) {
    struct notifier_block this;
    unsigned long event;
    void *ptr;

    __CPROVER_assume(event == NETDEV_DOWN);
    ptr = (void *)&this;

    /* @CONTRACTS */
    flow_offload_netdev_event(&this, event, ptr);

    return 0;
}
#endif
