#include <config.h>
#include "dpif.h"
#include "openvswitch/types.h"
#include "hw-offload-policy.h"
#include "dpif-hw-acc.h"

enum dpif_hw_offload_policy
HW_offload_test_put(struct dpif_hw_acc *dpif, struct dpif_flow_put *put)
{
    return DPIF_HW_OFFLOAD_ONLY;
}

enum dpif_hw_offload_policy
HW_offload_test_del(struct dpif *dpif, struct dpif_flow_del *del)
{
    return DPIF_HW_OFFLOAD_ONLY;
}

enum dpif_hw_offload_policy
HW_offload_test_get(struct dpif *dpif, struct dpif_flow_get *get)
{
    return DPIF_HW_OFFLOAD_ONLY;
}
