
#include <config.h>

#include <errno.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/gen_stats.h>
#include "timeval.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "rtnetlink.h"
#include "openvswitch/vlog.h"
#include "tc.h"
#include "util.h"

#ifndef __LINUX_TC_VLAN_H
#define __LINUX_TC_VLAN_H

#include <linux/pkt_cls.h>

#define TCA_ACT_VLAN 12

#define TCA_VLAN_ACT_POP        1
#define TCA_VLAN_ACT_PUSH       2
#define TCA_VLAN_ACT_MODIFY     3

struct tc_vlan {
        tc_gen;
        int v_action;
};

enum {
        TCA_VLAN_UNSPEC,
        TCA_VLAN_TM,
        TCA_VLAN_PARMS,
        TCA_VLAN_PUSH_VLAN_ID,
        TCA_VLAN_PUSH_VLAN_PROTOCOL,
        TCA_VLAN_PAD,
        TCA_VLAN_PUSH_VLAN_PRIORITY,
        __TCA_VLAN_MAX,
};
#define TCA_VLAN_MAX (__TCA_VLAN_MAX - 1)

#endif


bool SKIP_HW = false;

VLOG_DEFINE_THIS_MODULE(tc);

/* Returns tc handle 'major':'minor'. */
static unsigned int
tc_make_handle(unsigned int major, unsigned int minor)
{
    return TC_H_MAKE(major << 16, minor);
}

static struct tcmsg *
hw_tc_make_request(int ifindex, int type, unsigned int flags,
                   struct ofpbuf *request)
{
    struct tcmsg *tcmsg;

    ofpbuf_init(request, 512);

    struct nlmsghdr *nlmsghdr;

    ovs_assert(request->size == 0);

    nl_msg_reserve(request, NLMSG_HDRLEN + sizeof *tcmsg);
    nlmsghdr = nl_msg_put_uninit(request, NLMSG_HDRLEN);
    nlmsghdr->nlmsg_len = 0;
    nlmsghdr->nlmsg_type = type;
    nlmsghdr->nlmsg_flags = NLM_F_REQUEST | flags;
    nlmsghdr->nlmsg_seq = 0;
    nlmsghdr->nlmsg_pid = 0;

    tcmsg = ofpbuf_put_zeros(request, sizeof *tcmsg);
    tcmsg->tcm_family = AF_UNSPEC;
    tcmsg->tcm_ifindex = ifindex;
    /* Caller should fill in tcmsg->tcm_handle. */
    /* Caller should fill in tcmsg->tcm_parent. */

    return tcmsg;
}

static int
tc_transact(struct ofpbuf *request, struct ofpbuf **replyp)
{
    int error = nl_transact(NETLINK_ROUTE, request, replyp);

    ofpbuf_uninit(request);
    return error;
}

static const struct nl_policy tca_policy[] = {
	[TCA_KIND] = {.type = NL_A_STRING,.optional = false},
	[TCA_OPTIONS] = {.type = NL_A_NESTED,.optional = false},
	[TCA_STATS] = {.type = NL_A_UNSPEC,.min_len =
		sizeof (struct tc_stats),.optional = true},
	[TCA_STATS2] = {.type = NL_A_NESTED,.optional = true},
};

static const struct nl_policy tca_flower_policy[TCA_FLOWER_MAX + 1] = {
    [TCA_FLOWER_CLASSID] = {.type = NL_A_U32,.optional = true},
    [TCA_FLOWER_INDEV] = {.type = NL_A_STRING,.max_len =
                          IFNAMSIZ,.optional = true},

    [TCA_FLOWER_KEY_ETH_DST] = {.type = NL_A_UNSPEC,.min_len =
                                ETH_ALEN,.optional = true},
    [TCA_FLOWER_KEY_ETH_DST_MASK] = {.type = NL_A_UNSPEC,.min_len =
                                     ETH_ALEN,.optional = true},
    [TCA_FLOWER_KEY_ETH_SRC] = {.type = NL_A_UNSPEC,.min_len =
                                ETH_ALEN,.optional = true},
    [TCA_FLOWER_KEY_ETH_SRC_MASK] = {.type = NL_A_UNSPEC,.min_len =
                                     ETH_ALEN,.optional = true},
    [TCA_FLOWER_KEY_ETH_TYPE] = {.type = NL_A_U16,.optional = false},

    [TCA_FLOWER_FLAGS] = {.type = NL_A_U32,.optional = false},
    [TCA_FLOWER_ACT] = {.type = NL_A_NESTED,.optional = false},

    [TCA_FLOWER_KEY_IP_PROTO] = {.type = NL_A_U8,.optional = true},

    [TCA_FLOWER_KEY_IPV4_SRC] = {.type = NL_A_U32,.optional = true},
    [TCA_FLOWER_KEY_IPV4_SRC_MASK] = {.type = NL_A_U32,.optional = true},
    [TCA_FLOWER_KEY_IPV4_DST] = {.type = NL_A_U32,.optional = true},
    [TCA_FLOWER_KEY_IPV4_DST_MASK] = {.type = NL_A_U32,.optional = true},

    [TCA_FLOWER_KEY_IPV6_SRC] = {.type = NL_A_UNSPEC,.min_len =
                                 sizeof (struct in6_addr),.optional =
                                 true},
    [TCA_FLOWER_KEY_IPV6_SRC_MASK] = {.type = NL_A_UNSPEC,.min_len =
                                      sizeof (struct in6_addr),.optional =
                                      true},
    [TCA_FLOWER_KEY_IPV6_DST] = {.type = NL_A_UNSPEC,.min_len =
                                 sizeof (struct in6_addr),.optional =
                                 true},
    [TCA_FLOWER_KEY_IPV6_DST_MASK] = {.type = NL_A_UNSPEC,.min_len =
                                      sizeof (struct in6_addr),.optional =
                                      true},

    [TCA_FLOWER_KEY_TCP_SRC] = {.type = NL_A_U16,.optional = true},
    [TCA_FLOWER_KEY_TCP_DST] = {.type = NL_A_U16,.optional = true},
    [TCA_FLOWER_KEY_TCP_SRC_MASK] = {.type = NL_A_U16,.optional = true},
    [TCA_FLOWER_KEY_TCP_DST_MASK] = {.type = NL_A_U16,.optional = true},

    [TCA_FLOWER_KEY_UDP_SRC] = {.type = NL_A_U16,.optional = true},
    [TCA_FLOWER_KEY_UDP_DST] = {.type = NL_A_U16,.optional = true},
    [TCA_FLOWER_KEY_UDP_SRC_MASK] = {.type = NL_A_U16,.optional = true},
    [TCA_FLOWER_KEY_UDP_DST_MASK] = {.type = NL_A_U16,.optional = true},

    [TCA_FLOWER_KEY_VLAN_ID] = {.type = NL_A_U16,.optional = true},
    [TCA_FLOWER_KEY_VLAN_PRIO] = {.type = NL_A_U8,.optional = true},
    [TCA_FLOWER_KEY_VLAN_ETH_TYPE] = {.type = NL_A_U16,.optional = true},
};

int
parse_tc_flow(struct ofpbuf *reply, struct tc_flow *tc_flow)
{
    struct tcmsg *tc;
    struct ofpbuf mask_d, *mask = &mask_d;

    memset(tc_flow, 0, sizeof (*tc_flow));
    ofpbuf_init(mask, 512);
    if (NLMSG_HDRLEN + (sizeof *tc) > reply->size) {
        return EPROTO;
    }

    tc = ofpbuf_at_assert(reply, NLMSG_HDRLEN, sizeof *tc);
    tc_flow->handle = tc->tcm_handle;
    tc_flow->eth_type = TC_H_MIN(tc->tcm_info);
    tc_flow->prio = TC_H_MAJ(tc->tcm_info) >> 16;
    VLOG_DBG("parse_tc_flow: handle: 0x%x, %d, eth_type: 0x%x, prio: %d",
             tc->tcm_handle, tc->tcm_handle, ntohs(tc_flow->eth_type), tc_flow->prio);

    if (!tc_flow->handle)
        return EAGAIN;

    struct nlattr *ta[ARRAY_SIZE(tca_policy)];

    if (!nl_policy_parse(reply, NLMSG_HDRLEN + sizeof (struct tcmsg),
                         tca_policy, ta, ARRAY_SIZE(ta))) {
        VLOG_ERR("failed to parse tca policy");
        return EPROTO;
    }

    const char *kind = nl_attr_get_string(ta[TCA_KIND]);

    if (strcmp(kind, "flower")) {
        VLOG_ERR("error, TCA_KIND not flower!");
        return EPROTO;
    }

    struct nlattr *nl_options = ta[TCA_OPTIONS];
    struct nlattr *attrs[ARRAY_SIZE(tca_flower_policy)];

    if (!nl_parse_nested(nl_options, tca_flower_policy,
                         attrs, ARRAY_SIZE(tca_flower_policy))) {
        VLOG_ERR("failed to parse flower classifier options");
        return EPROTO;
    }

    int flags = nl_attr_get_u32(attrs[TCA_FLOWER_FLAGS]);

    VLOG_DBG("flags: 0x%x, skip_sw: %d skip_hw: %d", flags,
             flags & TCA_CLS_FLAGS_SKIP_SW ? 1 : 0,
             flags & TCA_CLS_FLAGS_SKIP_HW ? 1 : 0);

    if (tc_flow->eth_type == htons(ETH_P_8021Q)) {
	tc_flow->encap_eth_type = nl_attr_get_u16(attrs[TCA_FLOWER_KEY_ETH_TYPE]);
	VLOG_DBG("flower encap eth_type: 0x%x", ntohs(tc_flow->encap_eth_type));

	if (attrs[TCA_FLOWER_KEY_VLAN_ETH_TYPE]) {
		VLOG_DBG("TCA_FLOWER_KEY_VLAN_ETH_TYPE: 0x%x\n", nl_attr_get_u16(attrs[TCA_FLOWER_KEY_VLAN_ETH_TYPE]));
	}
        if (attrs[TCA_FLOWER_KEY_VLAN_ID]) {
		tc_flow->vlan_id = nl_attr_get_u16(attrs[TCA_FLOWER_KEY_VLAN_ID]);
		VLOG_DBG("flower vlan id: %d", tc_flow->vlan_id);
	}
        if (attrs[TCA_FLOWER_KEY_VLAN_PRIO]) {
		tc_flow->vlan_prio = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_VLAN_PRIO]);
		VLOG_DBG("flower vlan prio %d", tc_flow->vlan_prio);
	}
    }


    const struct eth_addr *eth = 0;
    char eth_str[32] = "";

    if (attrs[TCA_FLOWER_KEY_ETH_SRC]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_SRC], ETH_ALEN);
        sprintf(eth_str, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ea[0],
                eth->ea[1], eth->ea[2], eth->ea[3], eth->ea[4], eth->ea[5]);
        VLOG_DBG("eth_src: %s", eth_str);
        memcpy(&tc_flow->src_mac, eth, sizeof (tc_flow->src_mac));

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_SRC_MASK], ETH_ALEN);
        sprintf(eth_str, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ea[0],
                eth->ea[1], eth->ea[2], eth->ea[3], eth->ea[4], eth->ea[5]);
        VLOG_DBG("eth_src_mask: %s", eth_str);
        memcpy(&tc_flow->src_mac_mask, eth, sizeof (tc_flow->src_mac_mask));
    }

    if (attrs[TCA_FLOWER_KEY_ETH_DST]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_DST], ETH_ALEN);
        sprintf(eth_str, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ea[0],
                eth->ea[1], eth->ea[2], eth->ea[3], eth->ea[4], eth->ea[5]);
        VLOG_DBG("eth_dst: %s", eth_str);
        memcpy(&tc_flow->dst_mac, eth, sizeof (tc_flow->dst_mac));

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_DST_MASK], ETH_ALEN);
        sprintf(eth_str, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ea[0],
                eth->ea[1], eth->ea[2], eth->ea[3], eth->ea[4], eth->ea[5]);
        VLOG_DBG("eth_dst_mask: %s", eth_str);
        memcpy(&tc_flow->dst_mac_mask, eth, sizeof (tc_flow->dst_mac_mask));
    }

    if (attrs[TCA_FLOWER_KEY_IP_PROTO]) {
        int proto = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_PROTO]);

        tc_flow->ip_proto = proto;

        if (attrs[TCA_FLOWER_KEY_IPV4_SRC])
            tc_flow->ipv4.ipv4_src =
                nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_SRC]);
        if (attrs[TCA_FLOWER_KEY_IPV4_SRC_MASK])
            tc_flow->ipv4.ipv4_src_mask =
                nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_SRC_MASK]);
        if (attrs[TCA_FLOWER_KEY_IPV4_DST])
            tc_flow->ipv4.ipv4_dst =
                nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_DST]);
        if (attrs[TCA_FLOWER_KEY_IPV4_DST_MASK])
            tc_flow->ipv4.ipv4_dst_mask =
                nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_DST_MASK]);

        if (attrs[TCA_FLOWER_KEY_IPV6_SRC])
            memcpy(tc_flow->ipv6.ipv6_src, nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_IPV6_SRC], sizeof(tc_flow->ipv6.ipv6_src)), sizeof(tc_flow->ipv6.ipv6_src));
        if (attrs[TCA_FLOWER_KEY_IPV6_SRC_MASK])
            memcpy(tc_flow->ipv6.ipv6_src_mask, nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_IPV6_SRC_MASK], sizeof(tc_flow->ipv6.ipv6_src_mask)), sizeof(tc_flow->ipv6.ipv6_src_mask));
        if (attrs[TCA_FLOWER_KEY_IPV6_DST])
            memcpy(tc_flow->ipv6.ipv6_dst, nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_IPV6_DST], sizeof(tc_flow->ipv6.ipv6_dst)), sizeof(tc_flow->ipv6.ipv6_dst));
        if (attrs[TCA_FLOWER_KEY_IPV6_DST_MASK])
            memcpy(tc_flow->ipv6.ipv6_dst_mask, nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_IPV6_DST_MASK], sizeof(tc_flow->ipv6.ipv6_dst_mask)), sizeof(tc_flow->ipv6.ipv6_dst_mask));

        if (proto == IPPROTO_TCP) {
            if (attrs[TCA_FLOWER_KEY_TCP_SRC])
                tc_flow->src_port =
                    nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_SRC]);
            if (attrs[TCA_FLOWER_KEY_TCP_SRC_MASK])
                tc_flow->src_port_mask =
                    nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_SRC_MASK]);
            else
                memset(&tc_flow->src_port_mask, 0xFF,
                       sizeof (tc_flow->src_port_mask));
            if (attrs[TCA_FLOWER_KEY_TCP_DST])
                tc_flow->dst_port =
                    nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_DST]);
            if (attrs[TCA_FLOWER_KEY_TCP_DST_MASK])
                tc_flow->dst_port_mask =
                    nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_DST_MASK]);
            else
                memset(&tc_flow->dst_port_mask, 0xFF,
                       sizeof (tc_flow->dst_port_mask));
        } else if (proto == IPPROTO_UDP) {
            if (attrs[TCA_FLOWER_KEY_UDP_SRC]) {
                tc_flow->src_port =
                    nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_SRC]);
            }
            if (attrs[TCA_FLOWER_KEY_UDP_SRC_MASK]) {
                tc_flow->src_port_mask =
                    nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_SRC_MASK]);
            } else
                memset(&tc_flow->src_port_mask, 0xFF,
                       sizeof (tc_flow->src_port_mask));
            if (attrs[TCA_FLOWER_KEY_UDP_DST]) {
                tc_flow->dst_port =
                    nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_DST]);
            }
            if (attrs[TCA_FLOWER_KEY_UDP_DST_MASK]) {
                tc_flow->dst_port_mask =
                    nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_DST_MASK]);
            } else
                memset(&tc_flow->dst_port_mask, 0xFF,
                       sizeof (tc_flow->dst_port_mask));
        }
    }

    if (attrs[TCA_FLOWER_ACT]) {
        struct nlattr *actions = attrs[TCA_FLOWER_ACT];
        int i = 0;

        static struct nl_policy actions_orders_policy[32 + 1] = { };
        struct nlattr *actions_orders[ARRAY_SIZE(actions_orders_policy)];

        for (i = 0; i < 33; i++) {
            actions_orders_policy[i].type = NL_A_NESTED;
            actions_orders_policy[i].optional = true;
        }

        if (!nl_parse_nested
            (actions, actions_orders_policy, actions_orders,
             ARRAY_SIZE(actions_orders_policy))) {
            VLOG_ERR("failed to parse action orders (TCA_FLOWER_ACT)");
            return EPROTO;
        }

        for (int i = 0; i < 32; i++) {
            if (actions_orders[i]) {
                struct nlattr *action = actions_orders[i];

                static const struct nl_policy act_policy[TCA_ACT_MAX + 1] = {
                    [TCA_ACT_KIND] = {.type = NL_A_STRING,.optional = false},
                    [TCA_ACT_OPTIONS] = {.type = NL_A_NESTED,.optional =
                                         false},
                    [TCA_ACT_STATS] = {.type = NL_A_NESTED,.optional = true},
                };
                struct nlattr *action_attrs[ARRAY_SIZE(act_policy)];

                if (!nl_parse_nested(action, act_policy,
                                     action_attrs, ARRAY_SIZE(act_policy))) {
                    VLOG_ERR("failed to parse single action options");
                    return EPROTO;
                }
                const char *act_kind =
                    nl_attr_get_string(action_attrs[TCA_ACT_KIND]);
                struct nlattr *act_options = action_attrs[TCA_ACT_OPTIONS];

                if (!strcmp(act_kind, "gact")) {
                    static const struct nl_policy gact_policy[TCA_GACT_MAX +
                                                              1] = {
                        [TCA_GACT_PARMS] = {.type = NL_A_UNSPEC,.min_len =
                                            sizeof (struct tc_gact),.optional =
                                            false},
                        [TCA_GACT_PROB] = {.type = NL_A_UNSPEC,.min_len =
                                           sizeof (struct tc_gact_p),.optional
                                           = true},
                        [TCA_GACT_TM] = {.type = NL_A_UNSPEC,.min_len =
                                         sizeof (struct tcf_t),.optional =
                                         false},
                    };

                    struct nlattr *gact_attrs[ARRAY_SIZE(gact_policy)];

                    if (!nl_parse_nested(act_options, gact_policy,
                                         gact_attrs,
                                         ARRAY_SIZE(gact_policy))) {
                        VLOG_ERR("failed to parse gact action options");
                        return EPROTO;
                    }

                    if (gact_attrs[TCA_GACT_PARMS]) {
                        const struct tc_gact *p =
                            nl_attr_get_unspec(gact_attrs[TCA_GACT_PARMS],
                                               sizeof (struct tc_gact));

                        if (p->action == TC_ACT_SHOT) {
                            VLOG_DBG("kind gact - dropping packet");
                        } else
                            VLOG_ERR("unkown actions: %d", p->action);
                    } else
                        VLOG_ERR("missing gact params!");

                    if (gact_attrs[TCA_GACT_TM]) {
                        const struct tcf_t *tm =
                            nl_attr_get_unspec(gact_attrs[TCA_GACT_TM],
                                               sizeof (struct tcf_t));
                        unsigned long long int lastuse = tm->lastuse * 10;
                        unsigned long long int now = time_msec();

                        tc_flow->lastused = now - lastuse;
                        VLOG_DBG
                            ("lastuse: %llu ms, now - lastuse:  %llu",
                             lastuse, now - lastuse);
                    } else
                        VLOG_ERR("missing gact tm!");
                } else if (!strcmp(act_kind, "mirred")) {
                    static const struct nl_policy mirred_policy[TCA_GACT_MAX +
                                                                1] = {
                        [TCA_MIRRED_PARMS] = {.type = NL_A_UNSPEC,.min_len =
                                              sizeof (struct
                                                      tc_mirred),.optional =
                                              false},
                        [TCA_MIRRED_TM] = {.type = NL_A_UNSPEC,.min_len =
                                           sizeof (struct tcf_t),.optional =
                                           false},
                    };

                    struct nlattr *mirred_attrs[ARRAY_SIZE(mirred_policy)];

                    if (!nl_parse_nested(act_options, mirred_policy,
                                         mirred_attrs,
                                         ARRAY_SIZE(mirred_policy))) {
                        VLOG_ERR("failed to parse mirred action options");
                        return EPROTO;
                    }

                    if (mirred_attrs[TCA_MIRRED_PARMS]) {
                        const struct tc_mirred *m =
                            nl_attr_get_unspec(mirred_attrs[TCA_MIRRED_PARMS],
                                               sizeof (struct tc_mirred));

                        if (m->action == TC_ACT_STOLEN
                            && m->eaction == TCA_EGRESS_REDIR && m->ifindex) {
                            VLOG_DBG("mirred - redirect to ifinex: %d",
                                     m->ifindex);
                            tc_flow->ifindex_out = m->ifindex;
                        } else
                            VLOG_ERR("unkown mirred actions: %d, %d, %d",
                                     m->action, m->eaction, m->ifindex);
                    } else
                        VLOG_ERR("missing mirred params!");

                    if (mirred_attrs[TCA_MIRRED_TM]) {
                        const struct tcf_t *tm =
                            nl_attr_get_unspec(mirred_attrs[TCA_MIRRED_TM],
                                               sizeof (struct tcf_t));
                        unsigned long long int lastuse = tm->lastuse * 10;
                        unsigned long long int now = time_msec();

                        VLOG_DBG("lastuse: %llu ms, now - lastuse: %llu",
                                 lastuse, now - lastuse);
                        tc_flow->lastused = now - lastuse;
                    } else
                        VLOG_ERR("missing mirred tm!");
                } else if (!strcmp(act_kind, "vlan")) {
                    static const struct nl_policy vlan_policy[TCA_VLAN_MAX +1] = {
                        [TCA_VLAN_PARMS] = {.type = NL_A_UNSPEC,
                                            .min_len = sizeof (struct tc_vlan),
                                            .optional = false},
                        [TCA_VLAN_PUSH_VLAN_ID] = {.type = NL_A_U16,.optional = true},
                        [TCA_VLAN_PUSH_VLAN_PROTOCOL] = {.type = NL_A_U16,.optional = true},
                        [TCA_VLAN_PUSH_VLAN_PRIORITY] = {.type = NL_A_U8,.optional = true },
                    };

                    struct nlattr *vlan_attrs[ARRAY_SIZE(vlan_policy)];

                    if (!nl_parse_nested(act_options, vlan_policy,
                                         vlan_attrs,
                                         ARRAY_SIZE(vlan_policy))) {
                        VLOG_ERR("failed to parse vlan action options");
                        return EPROTO;
                    }

                    if (vlan_attrs[TCA_VLAN_PARMS]) {
                        const struct tc_vlan *v =
                            nl_attr_get_unspec(vlan_attrs[TCA_VLAN_PARMS],
                                               sizeof (struct tc_vlan));

                        if (v->v_action == TCA_VLAN_ACT_PUSH) {
				tc_flow->vlan_push_id = nl_attr_get_u16(vlan_attrs[TCA_VLAN_PUSH_VLAN_ID]);
				tc_flow->vlan_push_prio = nl_attr_get_u8(vlan_attrs[TCA_VLAN_PUSH_VLAN_PRIORITY]);
			} else if (v->v_action == TCA_VLAN_ACT_POP) {
				tc_flow->vlan_pop = 1;
                        } else
                            VLOG_ERR("unkown vlan actions: %d, %d", v->action, v->v_action);
                    } else
                        VLOG_ERR("missing vlan params!");
		}
		  else 
                    VLOG_ERR("unkown TCA_ACT_KIND attribute: %s", act_kind);

                if (action_attrs[TCA_ACT_STATS]) {
                    struct nlattr *act_stats = action_attrs[TCA_ACT_STATS];

                    static const struct nl_policy stats_policy[TCA_STATS_MAX +
                                                               1] = {
                        [TCA_STATS_BASIC] = {.type = NL_A_UNSPEC,.min_len =
                                             sizeof (struct
                                                     gnet_stats_basic),.optional
                                             = true},
                    };

                    struct nlattr *stats_attrs[ARRAY_SIZE(stats_policy)];

                    if (!nl_parse_nested(act_stats, stats_policy,
                                         stats_attrs,
                                         ARRAY_SIZE(stats_policy))) {
                        VLOG_ERR
                            ("failed to parse action's TCA_ACT_STATS policy");
                        return EPROTO;
                    }
                    if (stats_attrs[TCA_STATS_BASIC]) {
                        const struct gnet_stats_basic *bs =
                            nl_attr_get_unspec(stats_attrs[TCA_STATS_BASIC],
                                               sizeof (struct
                                                       gnet_stats_basic));
                        VLOG_DBG
                            ("basic stats packets (gnet_stats_basic): %u, %llu",
                             bs->packets, bs->bytes);
                        struct ovs_flow_stats *stats = &tc_flow->stats;

                        stats->n_packets.lo = bs->packets;
                        stats->n_packets.hi = 0;

                        stats->n_bytes.hi = bs->bytes >> 32;
                        stats->n_bytes.lo = bs->bytes & 0x00000000FFFFFFFF;
                    } else
                        VLOG_ERR
                            ("missing tca action basic stats (TCA_STATS_BASIC)");
                } else
                    VLOG_ERR("missing action stats (TCA_ACT_STATS)");
            }
        }
    } else
        VLOG_ERR("missing flower action (TCA_FLOWER_ACT)");

    return 0;
}

int
tc_dump_flower_start(int ifindex, struct nl_dump *dump)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;

    tcmsg =
        hw_tc_make_request(ifindex, RTM_GETTFILTER,
                           0 | (NLM_F_REQUEST | NLM_F_DUMP), &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info = tc_make_handle(0, 0);
    tcmsg->tcm_handle = 0;

    nl_dump_start(dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    return 0;
}

int
tc_flush_flower(int ifindex)
{
    struct ofpbuf request;
    int error = 0;
    struct tcmsg *tcmsg;

    VLOG_DBG("flusing ifindex: %d", ifindex);

    tcmsg = hw_tc_make_request(ifindex, RTM_DELTFILTER, NLM_F_ACK, &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info = tc_make_handle(0, 0);

    error = tc_transact(&request, 0);
    if (error) {
        VLOG_ERR("tc error while requesting a flush: %d", error);
        return error;
    }
    return 0;
}

int
tc_del_flower(int ifindex, int handle, int prio)
{
    struct ofpbuf request;
    int error = 0;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;

    tcmsg = hw_tc_make_request(ifindex, RTM_DELTFILTER, NLM_F_ECHO, &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info = tc_make_handle(prio, 0);
    tcmsg->tcm_handle = handle;

    error = tc_transact(&request, &reply);
    if (error) {
        VLOG_ERR("tc error while deleting a rule: %d", error);
        return error;
    }
    return 0;
}

int
tc_get_flower(int ifindex, int handle, int prio, struct tc_flow *tc_flow)
{
    struct ofpbuf request;
    int error = 0;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;

    tcmsg = hw_tc_make_request(ifindex, RTM_GETTFILTER, NLM_F_ECHO, &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info = tc_make_handle(prio, 0);
    tcmsg->tcm_handle = handle;

    error = tc_transact(&request, &reply);
    if (error) {
        VLOG_ERR("tc error while querying a rule: %d", error);
        return error;
    }

    parse_tc_flow(reply, tc_flow);
    return error;
}

void
tc_set_skip_hw(bool set)
{
    VLOG_INFO("tc: using skip_hw flag?  %s", set ? "true" : "false");
    SKIP_HW = set;
}


int
tc_replace_flower(struct tc_flow *tc_flow, uint16_t prio)
{
    struct ofpbuf request;
    int error = 0;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;

    VLOG_DBG("%s %d %s: eth_type %x ip_proto %d (%x), ifindex fwd: %d -> %d",
             __FILE__, __LINE__, __func__, ntohs(tc_flow->eth_type),
             tc_flow->ip_proto, tc_flow->ip_proto, tc_flow->ifindex,
             tc_flow->ifindex_out);

    tcmsg =
        hw_tc_make_request(tc_flow->ifindex, RTM_NEWTFILTER,
                           NLM_F_CREATE | NLM_F_ECHO, &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info =
        tc_make_handle((OVS_FORCE uint16_t) prio,
                       (OVS_FORCE uint16_t) tc_flow->eth_type);
    if (tc_flow->handle) {
        VLOG_DBG
            ("requested handle: %d (%x) (replace?, handle will be replaced if exists, add NLM_F_EXCL to not touch existing)",
             tc_flow->handle, tc_flow->handle);
        tcmsg->tcm_handle = tc_flow->handle;
    }

    nl_msg_put_string(&request, TCA_KIND, "flower");
    size_t basic_offset = nl_msg_start_nested(&request, TCA_OPTIONS);

    {
        if (tc_flow->dst_mac.ea[0]) {
            VLOG_DBG("putting dst_mac/mask");
            nl_msg_put_unspec(&request, TCA_FLOWER_KEY_ETH_DST,
                              &tc_flow->dst_mac, ETH_ALEN);
            nl_msg_put_unspec(&request, TCA_FLOWER_KEY_ETH_DST_MASK,
                              &tc_flow->dst_mac_mask, ETH_ALEN);
        }
        if (tc_flow->src_mac.ea[0]) {
            VLOG_DBG("putting src_mac/mask");
            nl_msg_put_unspec(&request, TCA_FLOWER_KEY_ETH_SRC,
                              &tc_flow->src_mac, ETH_ALEN);
            nl_msg_put_unspec(&request, TCA_FLOWER_KEY_ETH_SRC_MASK,
                              &tc_flow->src_mac_mask, ETH_ALEN);
        }

        if (ntohs(tc_flow->eth_type) == ETH_P_IP
            || ntohs(tc_flow->eth_type) == ETH_P_IPV6) {
            VLOG_DBG("flower, protocol is ipv4/v6, proto: %d",
                     tc_flow->ip_proto);

            if (tc_flow->ip_proto) {
                VLOG_DBG("adding ip proto");
                nl_msg_put_u8(&request, TCA_FLOWER_KEY_IP_PROTO,
                              tc_flow->ip_proto);

                if (tc_flow->ip_proto == IPPROTO_UDP) {
                    VLOG_DBG("adding udp ports %d/%x, %d/%x",
                             ntohs(tc_flow->src_port),
                             ntohs(tc_flow->src_port_mask),
                             ntohs(tc_flow->dst_port),
                             ntohs(tc_flow->dst_port_mask));
                    if (tc_flow->src_port) {
                        VLOG_DBG("adding udp src port/msk");
                        nl_msg_put_be16(&request, TCA_FLOWER_KEY_UDP_SRC,
                                        tc_flow->src_port);
                        nl_msg_put_be16(&request, TCA_FLOWER_KEY_UDP_SRC_MASK,
                                        tc_flow->src_port_mask);
                    }
                    if (tc_flow->dst_port) {
                        VLOG_DBG("adding udp dst port/msk");
                        nl_msg_put_be16(&request, TCA_FLOWER_KEY_UDP_DST,
                                        tc_flow->dst_port);
                        nl_msg_put_be16(&request, TCA_FLOWER_KEY_UDP_DST_MASK,
                                        tc_flow->dst_port_mask);
                    }
                } else if (tc_flow->ip_proto == IPPROTO_TCP) {
                    VLOG_DBG("adding tcp ports %d/%x, %d/%x",
                             ntohs(tc_flow->src_port), tc_flow->src_port_mask,
                             ntohs(tc_flow->dst_port), tc_flow->dst_port_mask);

                    if (tc_flow->src_port) {
                        VLOG_DBG("adding tcp src port/msk");
                        nl_msg_put_be16(&request, TCA_FLOWER_KEY_TCP_SRC,
                                        tc_flow->src_port);
                        nl_msg_put_u16(&request, TCA_FLOWER_KEY_TCP_SRC_MASK,
                                       tc_flow->src_port_mask);
                    }
                    if (tc_flow->dst_port) {
                        VLOG_DBG("adding tcp dst port/msk");
                        nl_msg_put_be16(&request, TCA_FLOWER_KEY_TCP_DST,
                                        tc_flow->dst_port);
                        nl_msg_put_be16(&request, TCA_FLOWER_KEY_TCP_DST_MASK,
                                        tc_flow->dst_port_mask);
                    }
                } else if (tc_flow->ip_proto == IPPROTO_ICMP) {
                    VLOG_DBG("proto is icmp");
                }
            }
            if (ntohs(tc_flow->eth_type) == ETH_P_IP) {
                VLOG_DBG("ip_proto is ip, checking ips");
                if (tc_flow->ipv4.ipv4_src) {
                    VLOG_DBG("putting ipv4 src/msk, %d/%d",
                             tc_flow->ipv4.ipv4_src,
                             tc_flow->ipv4.ipv4_src_mask);
                    nl_msg_put_be32(&request, TCA_FLOWER_KEY_IPV4_SRC,
                                    tc_flow->ipv4.ipv4_src);
                    nl_msg_put_be32(&request, TCA_FLOWER_KEY_IPV4_SRC_MASK,
                                    tc_flow->ipv4.ipv4_src_mask);
                }
                if (tc_flow->ipv4.ipv4_dst) {
                    VLOG_DBG("putting ipv4 dst/msk %d/%d",
                             tc_flow->ipv4.ipv4_dst,
                             tc_flow->ipv4.ipv4_dst_mask);
                    nl_msg_put_be32(&request, TCA_FLOWER_KEY_IPV4_DST,
                                    tc_flow->ipv4.ipv4_dst);
                    nl_msg_put_be32(&request, TCA_FLOWER_KEY_IPV4_DST_MASK,
                                    tc_flow->ipv4.ipv4_dst_mask);
                }
            } else if (ntohs(tc_flow->eth_type) == ETH_P_IPV6) {
		if (!is_all_zeros(tc_flow->ipv6.ipv6_src_mask, sizeof(tc_flow->ipv6.ipv6_src_mask))) { 
                    nl_msg_put_unspec(&request, TCA_FLOWER_KEY_IPV6_SRC,
                                      tc_flow->ipv6.ipv6_src,
                                      sizeof (tc_flow->ipv6.ipv6_src));
                    nl_msg_put_unspec(&request, TCA_FLOWER_KEY_IPV6_SRC_MASK,
                                      tc_flow->ipv6.ipv6_src_mask,
                                      sizeof (tc_flow->ipv6.ipv6_src_mask));
		}
		if (!is_all_zeros(tc_flow->ipv6.ipv6_dst_mask, sizeof(tc_flow->ipv6.ipv6_dst_mask))) {
                    nl_msg_put_unspec(&request, TCA_FLOWER_KEY_IPV6_SRC,
                                      tc_flow->ipv6.ipv6_dst,
                                      sizeof (tc_flow->ipv6.ipv6_dst));
                    nl_msg_put_unspec(&request, TCA_FLOWER_KEY_IPV6_SRC_MASK,
                                      tc_flow->ipv6.ipv6_dst_mask,
                                      sizeof (tc_flow->ipv6.ipv6_dst_mask));
		}
            }
        }

        VLOG_DBG("putting eth_type: %x (nthos)", ntohs(tc_flow->eth_type));
        nl_msg_put_be16(&request, TCA_FLOWER_KEY_ETH_TYPE, tc_flow->eth_type);

	if (tc_flow->eth_type == htons(ETH_P_8021Q)) {
		VLOG_DBG("eth type is VLAN (ETH_P_8021Q)\n");
		if (tc_flow->vlan_id || tc_flow->vlan_prio) {
			VLOG_DBG("VLAN id to match: %d", tc_flow->vlan_id);
			nl_msg_put_u16(&request, TCA_FLOWER_KEY_VLAN_ID, tc_flow->vlan_id);
			VLOG_DBG("VLAN prio: %d to match", tc_flow->vlan_prio);
			nl_msg_put_u8(&request, TCA_FLOWER_KEY_VLAN_PRIO, tc_flow->vlan_prio);
		}
		if (tc_flow->encap_eth_type) {
			VLOG_DBG("VLAN encapsulated eth_type: 0x%x", ntohs(tc_flow->encap_eth_type));
			nl_msg_put_be16(&request, TCA_FLOWER_KEY_VLAN_ETH_TYPE, tc_flow->encap_eth_type);
		}
		/* TODO: support for encap ipv4/ipv6 here */
	}

        if (SKIP_HW) {
            VLOG_DBG
                ("putting SKIP_HW to avoid using counters, firmware bugs");
            nl_msg_put_u32(&request, TCA_FLOWER_FLAGS, TCA_CLS_FLAGS_SKIP_HW);
        } else
            nl_msg_put_u32(&request, TCA_FLOWER_FLAGS, TCA_CLS_FLAGS_SKIP_SW);

        size_t offset2 = nl_msg_start_nested(&request, TCA_FLOWER_ACT);

        {
	    size_t index = 1;
	    int again = 1;
	    while (again) {
		    again = 0;
		    size_t offset3 = nl_msg_start_nested(&request, index++);

		    {
			if (tc_flow->vlan_push_id) {
			    VLOG_DBG("flower action: pusing vlan id: %d, prio: %d", tc_flow->vlan_push_id, tc_flow->vlan_push_prio);
			    nl_msg_put_string(&request, TCA_ACT_KIND, "vlan");
			    size_t offset4 =
				nl_msg_start_nested(&request, TCA_ACT_OPTIONS);
			    {
				struct tc_vlan parm = { 0 };
				parm.action = TC_ACT_PIPE;
				parm.v_action = TCA_VLAN_ACT_PUSH;
				nl_msg_put_unspec(&request, TCA_VLAN_PARMS, &parm, sizeof (parm));
				nl_msg_put_u16(&request, TCA_VLAN_PUSH_VLAN_ID, tc_flow->vlan_push_id);
				nl_msg_put_u8(&request, TCA_VLAN_PUSH_VLAN_PRIORITY, tc_flow->vlan_push_prio);
			    }
			    nl_msg_end_nested(&request, offset4);
			    tc_flow->vlan_push_id = 0; again = 1;
			}
			else if (tc_flow->vlan_pop) {
			    VLOG_DBG("flower action: poping vlan");
			    nl_msg_put_string(&request, TCA_ACT_KIND, "vlan");
			    size_t offset4 =
				nl_msg_start_nested(&request, TCA_ACT_OPTIONS);
			    {
				struct tc_vlan parm = { 0 };
				parm.action = TC_ACT_PIPE;
				parm.v_action = TCA_VLAN_ACT_POP;
				nl_msg_put_unspec(&request, TCA_VLAN_PARMS, &parm, sizeof (parm));
			    }
			    nl_msg_end_nested(&request, offset4);
			    tc_flow->vlan_pop = 0; again = 1;
			}
			else if (!tc_flow->ifindex_out) {
			    VLOG_DBG("flower: dropping");
			    nl_msg_put_string(&request, TCA_ACT_KIND, "gact");
			    size_t offset4 =
				nl_msg_start_nested(&request, TCA_ACT_OPTIONS);
			    {
				struct tc_gact p;

				memset(&p, 0, sizeof (p));

				p.action = TC_ACT_SHOT;
				nl_msg_put_unspec(&request, TCA_GACT_PARMS, &p,
						  sizeof (p));
			    }
			    nl_msg_end_nested(&request, offset4);
			} else {
			    VLOG_DBG("flower: reidrecting");
			    nl_msg_put_string(&request, TCA_ACT_KIND, "mirred");
			    size_t offset4 =
				nl_msg_start_nested(&request, TCA_ACT_OPTIONS);
			    {
				struct tc_mirred m;

				memset(&m, 0, sizeof (m));

				m.eaction = TCA_EGRESS_REDIR;
				m.action = TC_ACT_STOLEN;
				m.ifindex = tc_flow->ifindex_out;

				nl_msg_put_unspec(&request, TCA_MIRRED_PARMS, &m,
						  sizeof (m));
			    }
			    nl_msg_end_nested(&request, offset4);
			}
		    }
		    nl_msg_end_nested(&request, offset3);
	    }
        }
        nl_msg_end_nested(&request, offset2);
    }
    nl_msg_end_nested(&request, basic_offset);

    error = tc_transact(&request, &reply);
    if (error) {
        VLOG_ERR("%s %d: tc error: %d", __func__, __LINE__, error);
        return error;
    } else {
        VLOG_DBG("REPLY SIZE: %d", reply->size);
        if (reply->size) {
            struct tcmsg *tc =
                ofpbuf_at_assert(reply, NLMSG_HDRLEN, sizeof *tc);
            tc_flow->prio = TC_H_MAJ(tc->tcm_info) >> 16;
            tc_flow->handle = tc->tcm_handle;
            VLOG_DBG("SUCCESS, handle: %x, prio: %d", tc_flow->handle, tc_flow->prio);
        }
    }
    return 0;
}
