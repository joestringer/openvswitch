#ifndef __NET_NETLINK_WRAPPER_H
#define __NET_NETLINK_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/netlink.h>

#ifndef HAVE_NLA_GET_BE16
/**
 * nla_get_be16 - return payload of __be16 attribute
 * @nla: __be16 netlink attribute
 */
static inline __be16 nla_get_be16(const struct nlattr *nla)
{
	return *(__be16 *) nla_data(nla);
}
#endif  /* !HAVE_NLA_GET_BE16 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
/* This function was introduced in 2.6.31, but initially it performed an
 * unaligned access, so we replace it up to 2.6.34 where it was fixed.  */
#define nla_get_be64 rpl_nla_get_be64
static inline __be64 nla_get_be64(const struct nlattr *nla)
{
	__be64 tmp;

	/* The additional cast is necessary because  */
	nla_memcpy(&tmp, (struct nlattr *) nla, sizeof(tmp));

	return tmp;
}
#endif

#ifndef HAVE_NLA_PUT_BE16
static inline int nla_put_be16(struct sk_buff *skb, int attrtype, __be16 value)
{
	return nla_put(skb, attrtype, sizeof(__be16), &value);
}
#endif

#ifndef HAVE_NLA_PUT_BE32
static inline int nla_put_be32(struct sk_buff *skb, int attrtype, __be32 value)
{
	return nla_put(skb, attrtype, sizeof(__be32), &value);
}
#endif

#ifndef HAVE_NLA_PUT_BE64
static inline int nla_put_be64(struct sk_buff *skb, int attrtype, __be64 value)
{
	return nla_put(skb, attrtype, sizeof(__be64), &value);
}
#endif

#ifndef nla_for_each_nested
#define nla_for_each_nested(pos, nla, rem) \
	nla_for_each_attr(pos, nla_data(nla), nla_len(nla), rem)
#endif

#ifndef HAVE_NLA_FIND_NESTED
static inline struct nlattr *nla_find_nested(struct nlattr *nla, int attrtype)
{
	return nla_find(nla_data(nla), nla_len(nla), attrtype);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
static inline bool nla_is_last(const struct nlattr *nla, int rem)
{
	return nla->nla_len == rem;
}
#endif

#ifndef HAVE_NLA_PARSE_STRICT

/*
 * Flags for nla_parse_strict() to apply additional policy constraints.
 */
#define NLA_PARSE_F_NOINIT	(1<<0)	/* Don't initialize the tb to zero. */
#define NLA_PARSE_F_UNKNOWN	(1<<1)	/* Disallow unknown attributes. */
#define NLA_PARSE_F_TRAILING	(1<<2)	/* Disallow trailing attributes. */
#define NLA_PARSE_F_DUPLICATE	(1<<3)	/* Disallow duplicate attributes. */
#define NLA_PARSE_F_EXACT_LEN	(1<<4)	/* Lengths specified in the policy
					   restrict both min and max length. */
#define NLA_PARSE_F_NONZERO	(1<<5)	/* Only store pointers for attributes
					   with nonzero values. Requires a
					   policy to be specified. */
#define NLA_PARSE_F_LOG_ERRORS	(1<<6)	/* Log errors as they are detected. */

int nla_parse_strict(const struct nlattr **tb, int maxtype,
		     const struct nlattr *head, int len,
		     const struct nla_policy *policy, u8 flags);
#endif

#endif /* net/netlink.h */
