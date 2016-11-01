#ifndef DPIF_HW_NETLINK_H
#define DPIF_HW_NETLINK_H 1

#include "ovs-thread.h"
#include "hmap.h"
#include "dpif-provider.h"

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_hw_acc {
    struct dpif dpif;
    struct dpif *lp_dpif_netlink;
    const char *const name;
    struct ovs_mutex hash_mutex;
    struct hmap port_to_netdev;
    struct hmap ufid_to_handle;
    struct hmap handle_to_ufid;
    struct hmap mask_to_prio;
    
    uint16_t last_prio;
    uint64_t n_last_hits;
    uint64_t n_last_flows;
};

struct mask_prio_data {
    struct hmap_node node;
    char data[128];
    size_t len;
    uint16_t prio;
};

struct port_netdev_hash_data {
    struct hmap_node node;
    struct netdev *netdev;
    odp_port_t port;
};

struct ufid_handle_hash_data {
    struct hmap_node node_ufid;
    struct hmap_node node_handle;
    ovs_u128 ovs_ufid;
    int handle;
    int prio;
    struct netdev *netdev;
    odp_port_t port;
};
#endif
