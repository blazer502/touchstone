#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t pf;
    uint32_t hooknum;
    uint64_t flags;
    int32_t priority;
} bpf_attr_link_create_netfilter;

typedef union {
    bpf_attr_link_create_netfilter netfilter;
} bpf_attr_link_create;

typedef union {
    bpf_attr_link_create link_create;
} bpf_attr;

int bpf_nf_check_pf_and_hooks(const union bpf_attr *attr) {
    int prio;

    switch (attr->link_create.netfilter.pf) {
    case 1: // NFPROTO_IPV4
    case 2: // NFPROTO_IPV6
        if (attr->link_create.netfilter.hooknum >= 8)
            return -EPROTO;
        break;
    default:
        return -EAFNOSUPPORT;
    }

    if (attr->link_create.netfilter.flags & ~1) // BPF_F_NETFILTER_IP_DEFRAG
        return -EOPNOTSUPP;

    prio = attr->link_create.netfilter.priority;
    if (prio == 0)
        return -ERANGE;  /* sabotage_in and other warts */
    else if (prio == 7)
        return -ERANGE;  /* e.g. conntrack confirm */
    else if ((attr->link_create.netfilter.flags & 1) && // BPF_F_NETFILTER_IP_DEFRAG
             prio <= 3)
        return -ERANGE;  /* cannot use defrag if prog runs before nf_defrag */

    return 0;
}

#ifdef CBMC_HARNESS
int main(void) {
    bpf_attr attr;
    __CPROVER_assume(attr.link_create.netfilter.pf == 1 || attr.link_create.netfilter.pf == 2);
    __CPROVER_assume(attr.link_create.netfilter.hooknum < 8);
    __CPROVER_assume((attr.link_create.netfilter.flags & ~1) == 0);
    __CPROVER_assume(attr.link_create.netfilter.priority != 0 && attr.link_create.netfilter.priority != 7);

    /* @CONTRACTS */
    int result = bpf_nf_check_pf_and_hooks(&attr);

    return 0;
}
#endif
