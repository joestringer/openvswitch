#ifndef __NET_DST_METADATA_WRAPPER_H
#define __NET_DST_METADATA_WRAPPER_H 1

#ifdef HAVE_METADATA_DST
#include_next <net/dst_metadata.h>
#else
#include <linux/skbuff.h>

#include <net/dsfield.h>
#include <net/dst.h>
#include <net/ipv6.h>
#include <net/ip_tunnels.h>

struct metadata_dst {
	unsigned long dst;
	union {
		struct ip_tunnel_info	tun_info;
	} u;
};

static inline struct metadata_dst *metadata_dst_alloc(u8 optslen, gfp_t flags)
{
	struct metadata_dst *md_dst;

	md_dst = kmalloc(sizeof(*md_dst) + optslen, flags);
	if (!md_dst)
		return NULL;

	return md_dst;
}

#define skb_tunnel_info ovs_skb_tunnel_info
#endif

static inline void ovs_ip_tun_rx_dst(struct ip_tunnel_info *tun_info,
				 struct sk_buff *skb, __be16 flags,
				 __be64 tunnel_id, int md_size)
{
	const struct iphdr *iph = ip_hdr(skb);

	ip_tunnel_key_init(&tun_info->key,
			   iph->saddr, iph->daddr, iph->tos, iph->ttl,
			   0, 0, tunnel_id, flags);
	tun_info->mode = 0;
}

static inline void ovs_ipv6_tun_rx_dst(struct ip_tunnel_info *info,
				       struct sk_buff *skb,
				       __be16 flags,
				       __be64 tunnel_id,
				       int md_size)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);

	info->mode = IP_TUNNEL_INFO_IPV6;
	info->key.tun_flags = flags;
	info->key.tun_id = tunnel_id;
	info->key.tp_src = 0;
	info->key.tp_dst = 0;

	info->key.u.ipv6.src = ip6h->saddr;
	info->key.u.ipv6.dst = ip6h->daddr;

	info->key.tos = ipv6_get_dsfield(ip6h);
	info->key.ttl = ip6h->hop_limit;
	info->key.label = ip6_flowlabel(ip6h);
}

void ovs_ip_tunnel_rcv(struct net_device *dev, struct sk_buff *skb,
		      struct metadata_dst *tun_dst);
#endif /* __NET_DST_METADATA_WRAPPER_H */
