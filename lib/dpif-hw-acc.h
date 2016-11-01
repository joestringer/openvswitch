#ifndef DPIF_HW_NETLINK_H
#define DPIF_HW_NETLINK_H 1

#include "ovs-thread.h"
#include "dpif-provider.h"

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_hw_acc {
    struct dpif dpif;
    struct dpif *lp_dpif_netlink;
    const char *const name;
};

#endif
