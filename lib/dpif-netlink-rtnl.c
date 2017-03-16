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
#include "dpif-netlink.h"


int
dpif_netlink_rtnl_port_create(struct netdev *netdev)
{
    switch (netdev_to_ovs_vport_type(netdev_get_type(netdev))) {
    case OVS_VPORT_TYPE_VXLAN:
    case OVS_VPORT_TYPE_GRE:
    case OVS_VPORT_TYPE_GENEVE:
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
dpif_netlink_rtnl_port_destroy(const char *name OVS_UNUSED, const char *type)
{
    switch (netdev_to_ovs_vport_type(type)) {
    case OVS_VPORT_TYPE_VXLAN:
    case OVS_VPORT_TYPE_GRE:
    case OVS_VPORT_TYPE_GENEVE:
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
