#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/ratelimit.h>
#include <linux/types.h>
#include <net/netlink.h>

#ifndef HAVE_NLA_PARSE_STRICT

static const u16 nla_attr_minlen[NLA_TYPE_MAX+1] = {
	[NLA_U8]	= sizeof(u8),
	[NLA_U16]	= sizeof(u16),
	[NLA_U32]	= sizeof(u32),
	[NLA_U64]	= sizeof(u64),
	[NLA_MSECS]	= sizeof(u64),
	[NLA_NESTED]	= NLA_HDRLEN,
};

static int validate_nla(const struct nlattr *nla, int maxtype,
			const struct nla_policy *policy, bool strict, bool log)
{
	const struct nla_policy *pt;
	int minlen = 0, maxlen = 0, attrlen = nla_len(nla), type = nla_type(nla);

	if (type <= 0 || type > maxtype)
		return 0;

	pt = &policy[type];

	BUG_ON(pt->type > NLA_TYPE_MAX);

	switch (pt->type) {
	case NLA_FLAG:
		if (attrlen > 0)
			return -ERANGE;
		break;

	case NLA_NUL_STRING:
		if (pt->len)
			minlen = min_t(int, attrlen, pt->len + 1);
		else
			minlen = attrlen;

		if (!minlen || memchr(nla_data(nla), '\0', minlen) == NULL)
			return -EINVAL;
		/* fall through */

	case NLA_STRING:
		if (attrlen < 1)
			return -ERANGE;

		if (pt->len) {
			char *buf = nla_data(nla);

			if (buf[attrlen - 1] == '\0')
				attrlen--;

			if (attrlen > pt->len)
				return -ERANGE;
		}
		break;

	case NLA_BINARY:
		if (pt->len && attrlen > pt->len)
			return -ERANGE;
		break;

	case NLA_NESTED_COMPAT:
		if (attrlen < pt->len)
			return -ERANGE;
		if (attrlen < NLA_ALIGN(pt->len))
			break;
		if (attrlen < NLA_ALIGN(pt->len) + NLA_HDRLEN)
			return -ERANGE;
		nla = nla_data(nla) + NLA_ALIGN(pt->len);
		if (attrlen < NLA_ALIGN(pt->len) + NLA_HDRLEN + nla_len(nla))
			return -ERANGE;
		break;
	case NLA_NESTED:
		/* a nested attributes is allowed to be empty; if its not,
		 * it must have a size of at least NLA_HDRLEN.
		 */
		if (attrlen == 0)
			break;
	default:
		if (pt->len) {
			minlen = pt->len;
			if (strict)
				maxlen = pt->len;
		} else if (pt->type != NLA_UNSPEC) {
			minlen = nla_attr_minlen[pt->type];
		}

		if (attrlen < minlen || (maxlen && attrlen > maxlen)) {
			if (log)
				pr_warn_ratelimited("netlink: unexpected attribute "
					  "length in process `%s' (type=%d, length=%d,"
					  " expected length=%d).\n", current->comm,
					  type, nla_len(nla), minlen);
			return -ERANGE;
		}
	}

	return 0;
}

static bool is_all_zero(const u8 *fp, size_t size)
{
	int i;

	if (!fp)
		return false;

	for (i = 0; i < size; i++)
		if (fp[i])
			return false;

	return true;
}

/**
 * nla_parse_strict - Parse a stream of attributes into a tb buffer
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @policy: validation policy
 * @flags: mask of NLA_PARSE_F_*
 *
 * Parses a stream of attributes and stores a pointer to each attribute in the
 * tb array accessible via the attribute type. Attributes with a type
 * exceeding maxtype will be silently ignored for backwards compatibility
 * reasons. policy may be set to NULL if no validation is required. Passing
 * flags=0 provides the same behaviour as nla_parse().
 *
 * Returns 0 on success or a negative error code.
 */
int nla_parse_strict(const struct nlattr **tb, int maxtype,
		     const struct nlattr *head, int len,
		     const struct nla_policy *policy, u8 flags)
{
	const struct nlattr *nla;
	int rem, err;
	bool log = flags & NLA_PARSE_F_LOG_ERRORS ? true : false;

	BUG_ON(!policy && (flags & NLA_PARSE_F_NONZERO));
	if (!(flags & NLA_PARSE_F_NOINIT))
		memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

	nla_for_each_attr(nla, head, len, rem) {
		u16 type = nla_type(nla);

		if (type > 0 && type <= maxtype) {
			bool strict_len = flags & NLA_PARSE_F_EXACT_LEN;

			err = validate_nla(nla, maxtype, policy,
					   strict_len, log);
			if (err < 0)
				goto errout;

			if ((flags & NLA_PARSE_F_DUPLICATE) && tb[type]) {
				if (log)
					pr_warn_ratelimited("netlink: duplicate attribute "
						  "received in process `%s' (type=%d).\n",
						  current->comm, type);
				return -EINVAL;
			}

			if (!(flags & NLA_PARSE_F_NONZERO) ||
			    !is_all_zero(nla_data(nla), nla_len(nla)))
				tb[type] = nla;
		} else if (flags & NLA_PARSE_F_UNKNOWN) {
			if (log)
				pr_warn_ratelimited("netlink: unknown attribute received "
					  "in process `%s' (type=%d, max=%d).\n",
					  current->comm, type, maxtype);
			return -EINVAL;
		}
	}

	if (unlikely(rem > 0)) {
		pr_warn_ratelimited("netlink: %d bytes leftover after parsing "
			  "attributes in process `%s'.\n", rem, current->comm);
		if (flags & NLA_PARSE_F_TRAILING)
			return -EINVAL;
	}

	err = 0;
errout:
	return err;
}

#endif /* HAVE_NLA_PARSE_STRICT */
