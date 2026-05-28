#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) ipv6hdr;

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) nf_log_buf;

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) sk_buff;

typedef struct {
    uint32_t logflags;
} __attribute__((packed)) nf_loginfo;

static inline const void *skb_header_pointer(const sk_buff *skb, unsigned int offset, size_t len, void *buffer) {
    return buffer;
}

static inline unsigned int ntohs(uint16_t value) {
    return (value >> 8) | (value << 8);
}

static inline uint32_t ntohl(uint32_t value) {
    return (value >> 24) | ((value >> 8) & 0xff00) | ((value << 8) & 0xff0000) | (value << 24);
}

static inline int nf_ip6_ext_hdr(int nexthdr) {
    return 1;
}

static inline unsigned int ipv6_optlen(const void *hp) {
    return *(uint8_t *)hp + 1;
}

static inline unsigned int ipv6_authlen(const void *hp) {
    return *(uint8_t *)hp + 2;
}

static inline int nf_log_dump_tcp_header(nf_log_buf *m, const sk_buff *skb, int currenthdr, int fragment, unsigned int ptr, uint32_t logflags) {
    return 0;
}

static inline int nf_log_dump_udp_header(nf_log_buf *m, const sk_buff *skb, int currenthdr, int fragment, unsigned int ptr) {
    return 0;
}

static inline void nf_log_buf_add(nf_log_buf *m, const char *format, ...) {}

static inline void nf_log_dump_sk_uid_gid(void *net, nf_log_buf *m, const sk_buff *skb) {}

#ifdef CBMC_HARNESS
int main(void) {
    struct net net;
    nf_log_buf m;
    nf_loginfo info = { .logflags = 0 };
    sk_buff skb;
    unsigned int ip6hoff = 0;
    int recurse = 0;

    __CPROVER_assume(ip6hoff < sizeof(skb.data));
    __CPROVER_assume(recurse == 0 || recurse == 1);

    dump_ipv6_packet(&net, &m, &info, &skb, ip6hoff, recurse);
    return 0;
}
#endif
