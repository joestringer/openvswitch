
#ifndef HW_OFFLOAD_POLICY_H
#define HW_OFFLOAD_POLICY_H 1

#include "dpif-hw-acc.h"

enum dpif_hw_offload_policy {
    DPIF_HW_NO_OFFLAOAD = 1,    /* no offload - SW only */
    DPIF_HW_OFFLOAD_ONLY,       /* if fails fall back to SW */
    DPIF_HW_OFFLOAD_SPLIT,
};

enum dpif_hw_offload_policy HW_offload_test_put(struct dpif_hw_acc *dpif,
                                                struct dpif_flow_put *put);
enum dpif_hw_offload_policy HW_offload_test_del(struct dpif *dpif,
                                                struct dpif_flow_del *del);
enum dpif_hw_offload_policy HW_offload_test_get(struct dpif *dpif,
                                                struct dpif_flow_get *get);

#endif
