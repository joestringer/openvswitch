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

#ifndef DPIF_RTNETLINK_H
#define DPIF_RTNETLINK_H 1

#include <errno.h>

#include "netdev.h"

int dpif_rtnetlink_port_create(struct netdev *netdev);
int dpif_rtnetlink_port_destroy(const char *name, const char *type);

#ifndef __linux__
/* Dummy implementations for non Linux builds.
 *
 * NOTE: declaration above are for all platforms to keep sparse happy.
 */

static inline int dpif_rtnetlink_port_create(struct netdev *netdev OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static inline int dpif_rtnetlink_port_destroy(const char *name OVS_UNUSED,
                                              const char *type OVS_UNUSED)
{
    return EOPNOTSUPP;
}

#endif

#endif /* DPIF_RTNETLINK_H */
