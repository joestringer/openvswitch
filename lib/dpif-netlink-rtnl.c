/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "dpif-netlink-rtnl.h"

#include <net/if.h>
#include <linux/ip.h>
#include <linux/rtnetlink.h>

#include "dpif-netlink.h"
#include "netdev-vport.h"
#include "netlink-socket.h"

/* On some older systems, these enums are not defined. */
#ifndef IFLA_VXLAN_MAX
#define IFLA_VXLAN_MAX 0
#endif
#if IFLA_VXLAN_MAX < 25
#define IFLA_VXLAN_LEARNING 7
#define IFLA_VXLAN_PORT 15
#define IFLA_VXLAN_UDP_ZERO_CSUM6_RX 20
#define IFLA_VXLAN_GBP 23
#define IFLA_VXLAN_COLLECT_METADATA 25
#endif

#ifndef IFLA_GRE_MAX
#define IFLA_GRE_MAX 0
#endif
#if IFLA_GRE_MAX < 18
#define IFLA_GRE_COLLECT_METADATA 18
#endif

#ifndef IFLA_GENEVE_MAX
#define IFLA_GENEVE_MAX 0
#endif
#if IFLA_GENEVE_MAX < 10
#define IFLA_GENEVE_PORT 5
#define IFLA_GENEVE_COLLECT_METADATA 6
#define IFLA_GENEVE_UDP_ZERO_CSUM6_RX 10
#endif

static int
rtnl_transact(uint32_t type, uint32_t flags, const char *name,
              struct ofpbuf **reply)
{
    struct ofpbuf request;
    int err;

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, type, flags);
    ofpbuf_put_zeros(&request, sizeof(struct ifinfomsg));
    nl_msg_put_string(&request, IFLA_IFNAME, name);

    err = nl_transact(NETLINK_ROUTE, &request, reply);
    ofpbuf_uninit(&request);

    return err;
}

static int
dpif_netlink_rtnl_destroy(const char *name)
{
    return rtnl_transact(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, name, NULL);
}

static int
dpif_netlink_rtnl_getlink(const char *name, struct ofpbuf **reply)
{
    return rtnl_transact(RTM_GETLINK, NLM_F_REQUEST, name, reply);
}

static const struct nl_policy rtlink_policy[] = {
    [IFLA_LINKINFO] = { .type = NL_A_NESTED },
};
static const struct nl_policy linkinfo_policy[] = {
    [IFLA_INFO_KIND] = { .type = NL_A_STRING },
    [IFLA_INFO_DATA] = { .type = NL_A_NESTED },
};
static const struct nl_policy geneve_policy[] = {
    [IFLA_GENEVE_COLLECT_METADATA] = { .type = NL_A_FLAG },
    [IFLA_GENEVE_UDP_ZERO_CSUM6_RX] = { .type = NL_A_U8 },
    [IFLA_GENEVE_PORT] = { .type = NL_A_U16 },
};
static const struct nl_policy vxlan_policy[] = {
    [IFLA_VXLAN_COLLECT_METADATA] = { .type = NL_A_U8 },
    [IFLA_VXLAN_LEARNING] = { .type = NL_A_U8 },
    [IFLA_VXLAN_UDP_ZERO_CSUM6_RX] = { .type = NL_A_U8 },
    [IFLA_VXLAN_PORT] = { .type = NL_A_U16 },
};
static const struct nl_policy gre_policy[] = {
    [IFLA_GRE_COLLECT_METADATA] = { .type = NL_A_FLAG },
};

static bool
rtnl_policy_parse(struct ofpbuf *reply, const char *kind,
                  const struct nl_policy *tunnel_policy,
                  struct nlattr *tunnel[], int policy_size)
{
    struct nlattr *linkinfo[ARRAY_SIZE(linkinfo_policy)];
    struct nlattr *rtlink[ARRAY_SIZE(rtlink_policy)];
    struct ifinfomsg *ifmsg;

    ifmsg = ofpbuf_at(reply, NLMSG_HDRLEN, sizeof *ifmsg);
    return (nl_policy_parse(reply, NLMSG_HDRLEN + sizeof *ifmsg,
                            rtlink_policy, rtlink, ARRAY_SIZE(rtlink_policy))
            && nl_parse_nested(rtlink[IFLA_LINKINFO], linkinfo_policy,
                               linkinfo, ARRAY_SIZE(linkinfo_policy))
            && !strcmp(nl_attr_get_string(linkinfo[IFLA_INFO_KIND]), kind)
            && nl_parse_nested(linkinfo[IFLA_INFO_DATA], tunnel_policy,
                               tunnel, policy_size));
}

static int
dpif_netlink_rtnl_vxlan_verify(const char *name, const char *kind,
                               const struct netdev_tunnel_config *tnl_cfg)
{
    struct ofpbuf *reply;
    int err;

    err = dpif_netlink_rtnl_getlink(name, &reply);

    if (!err) {
        struct nlattr *vxlan[ARRAY_SIZE(vxlan_policy)];

        if (!rtnl_policy_parse(reply, kind, vxlan_policy, vxlan,
                               ARRAY_SIZE(vxlan_policy))) {
            err = EINVAL;
        }
        if (!err) {
            if (0 != nl_attr_get_u8(vxlan[IFLA_VXLAN_LEARNING])
                || 1 != nl_attr_get_u8(vxlan[IFLA_VXLAN_COLLECT_METADATA])
                || 1 != nl_attr_get_u8(vxlan[IFLA_VXLAN_UDP_ZERO_CSUM6_RX])
                || (tnl_cfg->dst_port
                    != nl_attr_get_be16(vxlan[IFLA_VXLAN_PORT]))) {
                err = EINVAL;
            }
        }
        if (!err) {
            if (tnl_cfg->exts & (1 << OVS_VXLAN_EXT_GBP)
                && !nl_attr_get_flag(vxlan[IFLA_VXLAN_GBP])) {
                err = EINVAL;
            }
        }
        ofpbuf_delete(reply);
    }

    return err;
}

static int
dpif_netlink_rtnl_vxlan_create_kind(struct netdev *netdev, const char *kind)
{
    const struct netdev_tunnel_config *tnl_cfg;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    size_t linkinfo_off, infodata_off;
    struct ifinfomsg *ifinfo;
    struct ofpbuf request;
    const char *name;
    int err;

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (!tnl_cfg) {
        return EINVAL;
    }

    name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_NEWLINK,
                        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
    ifinfo = ofpbuf_put_zeros(&request, sizeof(struct ifinfomsg));
    ifinfo->ifi_change = ifinfo->ifi_flags = IFF_UP;
    nl_msg_put_string(&request, IFLA_IFNAME, name);
    nl_msg_put_u32(&request, IFLA_MTU, UINT16_MAX);
    linkinfo_off = nl_msg_start_nested(&request, IFLA_LINKINFO);
    nl_msg_put_string(&request, IFLA_INFO_KIND, kind);
    infodata_off = nl_msg_start_nested(&request, IFLA_INFO_DATA);

    nl_msg_put_u8(&request, IFLA_VXLAN_LEARNING, 0);
    nl_msg_put_u8(&request, IFLA_VXLAN_COLLECT_METADATA, 1);
    nl_msg_put_u8(&request, IFLA_VXLAN_UDP_ZERO_CSUM6_RX, 1);
    if (tnl_cfg->exts & (1 << OVS_VXLAN_EXT_GBP)) {
        nl_msg_put_flag(&request, IFLA_VXLAN_GBP);
    }
    nl_msg_put_be16(&request, IFLA_VXLAN_PORT, tnl_cfg->dst_port);

    nl_msg_end_nested(&request, infodata_off);
    nl_msg_end_nested(&request, linkinfo_off);

    err = nl_transact(NETLINK_ROUTE, &request, NULL);
    ofpbuf_uninit(&request);

    if (err) {
        return err;
    }

    err = dpif_netlink_rtnl_vxlan_verify(name, kind, tnl_cfg);
    if (err) {
        dpif_netlink_rtnl_destroy(name);
    }

    return err;
}

static int
dpif_netlink_rtnl_vxlan_create(struct netdev *netdev)
{
    return dpif_netlink_rtnl_vxlan_create_kind(netdev, "vxlan");
}

static int
dpif_netlink_rtnl_gre_verify(const char *name, const char *kind)
{
    struct ofpbuf *reply;
    int err;

    err = dpif_netlink_rtnl_getlink(name, &reply);

    if (!err) {
        struct nlattr *gre[ARRAY_SIZE(gre_policy)];

        if (!rtnl_policy_parse(reply, kind, gre_policy, gre,
                               ARRAY_SIZE(gre_policy))) {
            err = EINVAL;
        }
        if (!err) {
            if (!nl_attr_get_flag(gre[IFLA_GRE_COLLECT_METADATA])) {
                err = EINVAL;
            }
        }
        ofpbuf_delete(reply);
    }

    return err;
}

static int
dpif_netlink_rtnl_gre_create_kind(struct netdev *netdev, const char *kind)
{
    const struct netdev_tunnel_config *tnl_cfg;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    size_t linkinfo_off, infodata_off;
    struct ifinfomsg *ifinfo;
    struct ofpbuf request;
    const char *name;
    int err;

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (!tnl_cfg) {
        return EINVAL;
    }

    name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_NEWLINK,
                        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
    ifinfo = ofpbuf_put_zeros(&request, sizeof(struct ifinfomsg));
    ifinfo->ifi_change = ifinfo->ifi_flags = IFF_UP;
    nl_msg_put_string(&request, IFLA_IFNAME, name);
    nl_msg_put_u32(&request, IFLA_MTU, UINT16_MAX);
    linkinfo_off = nl_msg_start_nested(&request, IFLA_LINKINFO);
    nl_msg_put_string(&request, IFLA_INFO_KIND, kind);
    infodata_off = nl_msg_start_nested(&request, IFLA_INFO_DATA);

    nl_msg_put_flag(&request, IFLA_GRE_COLLECT_METADATA);

    nl_msg_end_nested(&request, infodata_off);
    nl_msg_end_nested(&request, linkinfo_off);

    err = nl_transact(NETLINK_ROUTE, &request, NULL);
    ofpbuf_uninit(&request);

    if (err) {
        return err;
    }

    err = dpif_netlink_rtnl_gre_verify(name, kind);
    if (err) {
        dpif_netlink_rtnl_destroy(name);
    }

    return err;
}

static int
dpif_netlink_rtnl_gre_create(struct netdev *netdev)
{
    return dpif_netlink_rtnl_gre_create_kind(netdev, "gretap");
}

static int
dpif_netlink_rtnl_geneve_verify(const char *name, const char *kind,
                                const struct netdev_tunnel_config *tnl_cfg)
{
    struct ofpbuf *reply;
    int err;

    err = dpif_netlink_rtnl_getlink(name, &reply);

    if (!err) {
        struct nlattr *geneve[ARRAY_SIZE(geneve_policy)];

        if (!rtnl_policy_parse(reply, kind, geneve_policy, geneve,
                               ARRAY_SIZE(geneve_policy))) {
            err = EINVAL;
        }
        if (!err) {
            if (!nl_attr_get_flag(geneve[IFLA_GENEVE_COLLECT_METADATA])
                || 1 != nl_attr_get_u8(geneve[IFLA_GENEVE_UDP_ZERO_CSUM6_RX])
                || (tnl_cfg->dst_port
                    != nl_attr_get_be16(geneve[IFLA_GENEVE_PORT]))) {
                err = EINVAL;
            }
        }
        ofpbuf_delete(reply);
    }

    return err;
}

static int
dpif_netlink_rtnl_geneve_create_kind(struct netdev *netdev, const char *kind)
{
    const struct netdev_tunnel_config *tnl_cfg;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    size_t linkinfo_off, infodata_off;
    struct ifinfomsg *ifinfo;
    struct ofpbuf request;
    const char *name;
    int err;

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (!tnl_cfg) {
        return EINVAL;
    }

    name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_NEWLINK,
                        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
    ifinfo = ofpbuf_put_zeros(&request, sizeof(struct ifinfomsg));
    ifinfo->ifi_change = ifinfo->ifi_flags = IFF_UP;
    nl_msg_put_string(&request, IFLA_IFNAME, name);
    nl_msg_put_u32(&request, IFLA_MTU, UINT16_MAX);
    linkinfo_off = nl_msg_start_nested(&request, IFLA_LINKINFO);
    nl_msg_put_string(&request, IFLA_INFO_KIND, kind);
    infodata_off = nl_msg_start_nested(&request, IFLA_INFO_DATA);

    nl_msg_put_flag(&request, IFLA_GENEVE_COLLECT_METADATA);
    nl_msg_put_u8(&request, IFLA_GENEVE_UDP_ZERO_CSUM6_RX, 1);
    nl_msg_put_be16(&request, IFLA_GENEVE_PORT, tnl_cfg->dst_port);

    nl_msg_end_nested(&request, infodata_off);
    nl_msg_end_nested(&request, linkinfo_off);

    err = nl_transact(NETLINK_ROUTE, &request, NULL);
    ofpbuf_uninit(&request);

    if (err) {
        return err;
    }

    err = dpif_netlink_rtnl_geneve_verify(name, kind, tnl_cfg);
    if (err) {
        dpif_netlink_rtnl_destroy(name);
    }

    return err;
}

static int
dpif_netlink_rtnl_geneve_create(struct netdev *netdev)
{
    return dpif_netlink_rtnl_geneve_create_kind(netdev, "geneve");
}

int
dpif_netlink_rtnl_port_create(struct netdev *netdev)
{
    switch (netdev_to_ovs_vport_type(netdev_get_type(netdev))) {
    case OVS_VPORT_TYPE_VXLAN:
        return dpif_netlink_rtnl_vxlan_create(netdev);
    case OVS_VPORT_TYPE_GRE:
        return dpif_netlink_rtnl_gre_create(netdev);
    case OVS_VPORT_TYPE_GENEVE:
        return dpif_netlink_rtnl_geneve_create(netdev);
    case OVS_VPORT_TYPE_NETDEV:
    case OVS_VPORT_TYPE_INTERNAL:
    case OVS_VPORT_TYPE_LISP:
    case OVS_VPORT_TYPE_STT:
    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
    default:
        return EOPNOTSUPP;
    }
    return 0;
}

int
dpif_netlink_rtnl_port_destroy(const char *name, const char *type)
{
    switch (netdev_to_ovs_vport_type(type)) {
    case OVS_VPORT_TYPE_VXLAN:
    case OVS_VPORT_TYPE_GRE:
    case OVS_VPORT_TYPE_GENEVE:
        return dpif_netlink_rtnl_destroy(name);
    case OVS_VPORT_TYPE_NETDEV:
    case OVS_VPORT_TYPE_INTERNAL:
    case OVS_VPORT_TYPE_LISP:
    case OVS_VPORT_TYPE_STT:
    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
    default:
        return EOPNOTSUPP;
    }
    return 0;
}

/**
 * Probe for whether the modules are out-of-tree (openvswitch) or in-tree
 * (upstream kernel).
 *
 * We probe for "ovs_geneve" via rtnetlink. As long as this returns something
 * other than EOPNOTSUPP we know that the module in use is the out-of-tree one.
 * This will be used to determine which netlink interface to use when creating
 * ports; rtnetlink or compat/genetlink.
 *
 * See ovs_tunnels_out_of_tree
 */
bool
dpif_netlink_rtnl_probe_oot_tunnels(void)
{
    struct netdev *netdev = NULL;
    bool out_of_tree = false;
    int error;

    error = netdev_open("ovs-system-probe", "geneve", &netdev);
    if (!error) {
        error = dpif_netlink_rtnl_geneve_create_kind(netdev, "ovs_geneve");
        if (error != EOPNOTSUPP) {
            if (!error) {
                char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
                const char *dp_port;

                dp_port = netdev_vport_get_dpif_port(netdev, namebuf,
                                                     sizeof namebuf);
                dpif_netlink_rtnl_destroy(dp_port);
            }
            out_of_tree = true;
        }
        netdev_close(netdev);
    }

    return out_of_tree;
}
