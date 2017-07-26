#!/bin/bash

OVS_PATH=${PWD}
OVS_DEV=${OVS_PATH}/utilities/ovs-dev.py
LINUX_TOOLS=/home/vagrant/net-next/tools
OVS_BPF_PATH=/sys/fs/bpf/ovs
BRIDGE=br0

# $1 = netns name
# $2 = IP
setup_topology()
{
    netns="$1"
    ip="$2"

    ip netns add ${netns}
    ip link add dev veth-${netns} type veth peer name veth0 netns ${netns}
    ip link set dev veth-${netns} up
    ip netns exec ${netns} ip link set dev veth0 up
    ip netns exec ${netns} ip addr add dev veth0 ${ip}
    ovs-vsctl add-port ${BRIDGE} veth-${netns}
}

# $1 = netns name
cleanup_topology()
{
    netns="$1"

    ovs-vsctl del-port veth-${netns}
    ip link set dev veth-${netns} down
    ip link del dev veth-${netns}
    ip netns del ${netns}
}

cleanup()
{
    for netns in foo bar; do
        cleanup_topology ${netns}
    done
    ovs-vsctl del-br ${BRIDGE}
    ${OVS_DEV} kill
    rm -rf ${OVS_BPF_PATH}
    ip li del dev ovs-system
}

run()
{
    export LD_LIBRARY_PATH=${LINUX_TOOLS}/lib/bpf:${LD_LIBRARY_PATH}
    export OVS_PKGDATADIR=${OVS_PATH}/_build-gcc
    trap cleanup SIGINT SIGTERM

    `${OVS_DEV} env`
    echo "Run OVS now"
    #read -n 1
    ${OVS_DEV} run
    ovs-vsctl add-br ${BRIDGE} -- \
        set bridge ${BRIDGE} datapath_type=bpf
    setup_topology foo "172.31.0.1/24"
    setup_topology bar "172.31.0.2/24"

    echo "Ready."
    read -n 1
    ip netns exec foo ping 172.31.0.2
    cleanup
}

run
