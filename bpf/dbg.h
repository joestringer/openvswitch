#ifndef __BPF_DBG_H_
#define __BPF_DBG_H_

/* XXX: Mock these out from cilium */
enum debug_codes {
    DBG_GENERIC,
    DBG_L4_POLICY,
    DBG_ERROR_RET,
    DBG_PORT_MAP,
    DBG_CT_MATCH,
    DBG_CT_LOOKUP_REV,
    DBG_CT_LOOKUP,
    DBG_CT_LOOKUP4,
    DBG_CT_LOOKUP6,
    DBG_CT_VERDICT,
    DBG_CT_CREATED,
    DBG_CT_CREATED2,
};

static inline void cilium_trace(struct __sk_buff *skb OVS_UNUSED,
                                uint8_t code OVS_UNUSED,
                                uint32_t ctx OVS_UNUSED,
                                uint32_t ctx2 OVS_UNUSED)
{
}

static inline void cilium_trace3(struct __sk_buff *skb OVS_UNUSED,
                                uint8_t code OVS_UNUSED,
                                uint32_t ctx OVS_UNUSED,
                                uint32_t ctx2 OVS_UNUSED,
                                uint32_t ctx3 OVS_UNUSED)
{
}

#endif /* __BPF_DBG_H_ */
