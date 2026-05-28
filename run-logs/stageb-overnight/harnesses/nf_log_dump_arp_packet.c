#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[1];
} __attribute__((packed)) byte_array;

typedef struct {
    uint8_t h_source[ETH_ALEN];
    uint8_t h_dest[ETH_ALEN];
    uint16_t h_proto;
} eth_hdr_struct;

typedef struct {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
    byte_array mac_src;
    byte_array ip_src;
    byte_array mac_dst;
    byte_array ip_dst;
} __attribute__((packed)) arppayload_struct;

typedef struct {
    uint16_t logflags;
} nf_loginfo_struct;

typedef struct {
    byte_array data;
} nf_log_buf_struct;

typedef struct {
    uint8_t h_proto;
} eth_hdr_struct;

static inline void *skb_header_pointer(const byte_array *skb, unsigned int nhoff, size_t len, byte_array *buf) {
    if (nhoff + len > skb->data_len)
        return NULL;
    memcpy(buf, skb->data + nhoff, len);
    return buf;
}

static inline const eth_hdr_struct *eth_hdr(const byte_array *skb) {
    return (const eth_hdr_struct *)skb_header_pointer(skb, 0, sizeof(eth_hdr_struct), (byte_array *)&_eth_hdr);
}

static inline void nf_log_buf_add(nf_log_buf_struct *m, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

void nf_log_buf_add(nf_log_buf_struct *m, const char *fmt, ...) {
    // Dummy implementation
}

static inline void nf_log_dump_vlan(nf_log_buf_struct *m, const byte_array *skb) {
    // Dummy implementation
}

#define NF_LOG_TYPE_LOG 1
#define NF_LOG_DEFAULT_MASK 0x000F

int main(void) {
    __CPROVER_assume(sizeof(byte_array) >= sizeof(eth_hdr_struct));
    __CPROVER_assume(sizeof(byte_array) >= sizeof(arppayload_struct));
    __CPROVER_assume(sizeof(byte_array) >= sizeof(nf_loginfo_struct));
    __CPROVER_assume(sizeof(byte_array) >= sizeof(nf_log_buf_struct));

    nf_log_buf_struct m;
    nf_loginfo_struct info = { .type = NF_LOG_TYPE_LOG, .u.log.logflags = NF_LOG_DEFAULT_MASK };
    byte_array skb_data[1024];
    nf_log_buf_struct *skb = (nf_log_buf_struct *)skb_data;

    dump_arp_packet(&m, &info, skb, 0);

    return 0;
}

/* @CONTRACTS */
void dump_arp_packet(nf_log_buf_struct *m, const nf_loginfo_struct *info, const byte_array *skb, unsigned int nhoff);
