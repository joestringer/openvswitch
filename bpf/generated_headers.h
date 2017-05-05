#ifndef P4_GENERATED_HEADERS
#define P4_GENERATED_HEADERS

#ifndef BPF_TYPES
#define BPF_TYPES
typedef signed char s8; 
typedef unsigned char u8; 
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;
#endif

struct ipv6_t {
    u8 version; /* 4 bits */
    u8 trafficClass; /* 8 bits */
    u32 flowLabel; /* 20 bits */
    u16 payloadLen; /* 16 bits */
    u8 nextHdr; /* 8 bits */
    u8 hopLimit; /* 8 bits */
    char srcAddr[16]; /* 128 bits */
    char dstAddr[16]; /* 128 bits */
    u8 valid; /* 1 bits */
};
struct pkt_metadata_t {
    u32 recirc_id; /* 32 bits */
    u32 dp_hash; /* 32 bits */
    u32 skb_priority; /* 32 bits */
    u32 pkt_mark; /* 32 bits */
    u16 ct_state; /* 16 bits */
    u16 ct_zone; /* 16 bits */
    u32 ct_mark; /* 32 bits */
    char ct_label[16]; /* 128 bits */
    u32 in_port; /* 32 bits */
};
struct udp_t {
    u16 srcPort; /* 16 bits */
    u16 dstPort; /* 16 bits */
    u16 length_; /* 16 bits */
    u16 checksum; /* 16 bits */
    u8 valid; /* 1 bits */
};
struct arp_rarp_t {
    u16 hwType; /* 16 bits */
    u16 protoType; /* 16 bits */
    u8 hwAddrLen; /* 8 bits */
    u8 protoAddrLen; /* 8 bits */
    u16 opcode; /* 16 bits */
    u8 valid; /* 1 bits */
};
struct icmp_t {
    u16 typeCode; /* 16 bits */
    u16 hdrChecksum; /* 16 bits */
    u8 valid; /* 1 bits */
};
struct ipv4_t {
    u8 version; /* 4 bits */
    u8 ihl; /* 4 bits */
    u8 diffserv; /* 8 bits */
    u16 totalLen; /* 16 bits */
    u16 identification; /* 16 bits */
    u8 flags; /* 3 bits */
    u16 fragOffset; /* 13 bits */
    u8 ttl; /* 8 bits */
    u8 protocol; /* 8 bits */
    u16 hdrChecksum; /* 16 bits */
    u32 srcAddr; /* 32 bits */
    u32 dstAddr; /* 32 bits */
    u8 valid; /* 1 bits */
};
struct flow_tnl_t {
    u32 ip_dst; /* 32 bits */
    char ipv6_dst[8]; /* 64 bits */
    u32 ip_src; /* 32 bits */
    char ipv6_src[8]; /* 64 bits */
    char tun_id[8]; /* 64 bits */
    u16 flags; /* 16 bits */
    u8 ip_tos; /* 8 bits */
    u8 ip_ttl; /* 8 bits */
    u16 tp_src; /* 16 bits */
    u16 tp_dst; /* 16 bits */
    u16 gbp_id; /* 16 bits */
    u8 gbp_flags; /* 8 bits */
    char pad1[5]; /* 40 bits */
};
struct tcp_t {
    u16 srcPort; /* 16 bits */
    u16 dstPort; /* 16 bits */
    u32 seqNo; /* 32 bits */
    u32 ackNo; /* 32 bits */
    u8 dataOffset; /* 4 bits */
    u8 res; /* 4 bits */
    u8 flags; /* 8 bits */
    u16 window; /* 16 bits */
    u16 checksum; /* 16 bits */
    u16 urgentPtr; /* 16 bits */
    u8 valid; /* 1 bits */
};
struct ethernet_t {
    char dstAddr[6]; /* 48 bits */
    char srcAddr[6]; /* 48 bits */
    u16 etherType; /* 16 bits */
    u8 valid; /* 1 bits */
};
struct standard_metadata_t {
    u16 ingress_port; /* 9 bits */
    u32 packet_length; /* 32 bits */
    u16 egress_spec; /* 9 bits */
    u16 egress_port; /* 9 bits */
    u32 egress_instance; /* 32 bits */
    u32 instance_type; /* 32 bits */
    u32 clone_spec; /* 32 bits */
    u8 _padding; /* 5 bits */
};
struct vlan_tag_t {
    u8 pcp; /* 3 bits */
    u8 cfi; /* 1 bits */
    u16 vid; /* 12 bits */
    u16 etherType; /* 16 bits */
    u8 valid; /* 1 bits */
};
struct ebpf_headers_t {
    struct ethernet_t ethernet;
    struct ipv4_t ipv4;
    struct ipv6_t ipv6;
    struct arp_rarp_t arp;
    struct tcp_t tcp;
    struct udp_t udp;
    struct icmp_t icmp;
    struct vlan_tag_t vlan;
};
struct ebpf_metadata_t {
    struct standard_metadata_t standard_metadata;
    struct pkt_metadata_t md;
    struct flow_tnl_t tnl_md;
};
#endif
