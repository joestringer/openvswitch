/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef BPF_OPENVSWITCH_DEPARSER_H
#define BPF_OPENVSWITCH_DEPARSER_H

#include <openvswitch/compiler.h>
#include "api.h"
#include "ovs-p4.h"
#include "maps.h"

//__section_tail(DEPARSER_CALL)
static inline int ovs_deparser(struct __sk_buff* ebpf_packet) {

    int err = -1;
    //uint32_t ebpf_packetOffsetInBits = 0;
    struct ebpf_headers_t *ebpf_headers;
    struct ebpf_metadata_t *ebpf_mds;

    if (!ebpf_packet)
        return err;

    ebpf_headers = bpf_get_headers();
    if (!ebpf_headers) {
        printt("no header\n");
        return err;
    }

    ebpf_mds = bpf_get_mds();
    if (!ebpf_mds) {
        printt("no md\n");
        return err;
    }

    printt("deparser\n");
    /* Deparser */

    //if (ebpf_headers->ethernet.valid) {
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->ethernet.dstAddr[0]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 1, 0, 8, ebpf_headers->ethernet.dstAddr[1]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 2, 0, 8, ebpf_headers->ethernet.dstAddr[2]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 3, 0, 8, ebpf_headers->ethernet.dstAddr[3]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 4, 0, 8, ebpf_headers->ethernet.dstAddr[4]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 5, 0, 8, ebpf_headers->ethernet.dstAddr[5]);
    //    ebpf_packetOffsetInBits += 48;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->ethernet.srcAddr[0]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 1, 0, 8, ebpf_headers->ethernet.srcAddr[1]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 2, 0, 8, ebpf_headers->ethernet.srcAddr[2]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 3, 0, 8, ebpf_headers->ethernet.srcAddr[3]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 4, 0, 8, ebpf_headers->ethernet.srcAddr[4]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 5, 0, 8, ebpf_headers->ethernet.srcAddr[5]);
    //    ebpf_packetOffsetInBits += 48;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->ethernet.etherType);
    //    ebpf_packetOffsetInBits += 16;
    //}
    //if (ebpf_headers->vlan.valid) {
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 3, ebpf_headers->vlan.pcp);
    //    ebpf_packetOffsetInBits += 3;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 3, 1, ebpf_headers->vlan.cfi);
    //    ebpf_packetOffsetInBits += 1;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 4, 12, ebpf_headers->vlan.vid);
    //    ebpf_packetOffsetInBits += 12;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->vlan.etherType);
    //    ebpf_packetOffsetInBits += 16;
    //}
    //if (ebpf_headers->ipv4.valid) {
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 4, ebpf_headers->ipv4.version);
    //    ebpf_packetOffsetInBits += 4;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 4, 4, ebpf_headers->ipv4.ihl);
    //    ebpf_packetOffsetInBits += 4;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->ipv4.diffserv);
    //    ebpf_packetOffsetInBits += 8;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->ipv4.totalLen);
    //    ebpf_packetOffsetInBits += 16;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->ipv4.identification);
    //    ebpf_packetOffsetInBits += 16;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 3, ebpf_headers->ipv4.flags);
    //    ebpf_packetOffsetInBits += 3;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 3, 13, ebpf_headers->ipv4.fragOffset);
    //    ebpf_packetOffsetInBits += 13;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->ipv4.ttl);
    //    ebpf_packetOffsetInBits += 8;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->ipv4.protocol);
    //    ebpf_packetOffsetInBits += 8;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->ipv4.hdrChecksum);
    //    ebpf_packetOffsetInBits += 16;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 32, ebpf_headers->ipv4.srcAddr);
    //    ebpf_packetOffsetInBits += 32;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 32, ebpf_headers->ipv4.dstAddr);
    //    ebpf_packetOffsetInBits += 32;
    //}
    //if (ebpf_headers->arp.valid) {
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->arp.hwType);
    //    ebpf_packetOffsetInBits += 16;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->arp.protoType);
    //    ebpf_packetOffsetInBits += 16;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->arp.hwAddrLen);
    //    ebpf_packetOffsetInBits += 8;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->arp.protoAddrLen);
    //    ebpf_packetOffsetInBits += 8;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->arp.opcode);
    //    ebpf_packetOffsetInBits += 16;
    //}
    //if (ebpf_headers->ipv6.valid) {
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 4, ebpf_headers->ipv6.version);
    //    ebpf_packetOffsetInBits += 4;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 4, 8, ebpf_headers->ipv6.trafficClass);
    //    ebpf_packetOffsetInBits += 8;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 4, 20, ebpf_headers->ipv6.flowLabel);
    //    ebpf_packetOffsetInBits += 20;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->ipv6.payloadLen);
    //    ebpf_packetOffsetInBits += 16;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->ipv6.nextHdr);
    //    ebpf_packetOffsetInBits += 8;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->ipv6.hopLimit);
    //    ebpf_packetOffsetInBits += 8;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->ipv6.srcAddr[0]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 1, 0, 8, ebpf_headers->ipv6.srcAddr[1]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 2, 0, 8, ebpf_headers->ipv6.srcAddr[2]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 3, 0, 8, ebpf_headers->ipv6.srcAddr[3]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 4, 0, 8, ebpf_headers->ipv6.srcAddr[4]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 5, 0, 8, ebpf_headers->ipv6.srcAddr[5]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 6, 0, 8, ebpf_headers->ipv6.srcAddr[6]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 7, 0, 8, ebpf_headers->ipv6.srcAddr[7]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 8, 0, 8, ebpf_headers->ipv6.srcAddr[8]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 9, 0, 8, ebpf_headers->ipv6.srcAddr[9]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 10, 0, 8, ebpf_headers->ipv6.srcAddr[10]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 11, 0, 8, ebpf_headers->ipv6.srcAddr[11]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 12, 0, 8, ebpf_headers->ipv6.srcAddr[12]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 13, 0, 8, ebpf_headers->ipv6.srcAddr[13]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 14, 0, 8, ebpf_headers->ipv6.srcAddr[14]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 15, 0, 8, ebpf_headers->ipv6.srcAddr[15]);
    //    ebpf_packetOffsetInBits += 128;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->ipv6.dstAddr[0]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 1, 0, 8, ebpf_headers->ipv6.dstAddr[1]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 2, 0, 8, ebpf_headers->ipv6.dstAddr[2]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 3, 0, 8, ebpf_headers->ipv6.dstAddr[3]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 4, 0, 8, ebpf_headers->ipv6.dstAddr[4]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 5, 0, 8, ebpf_headers->ipv6.dstAddr[5]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 6, 0, 8, ebpf_headers->ipv6.dstAddr[6]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 7, 0, 8, ebpf_headers->ipv6.dstAddr[7]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 8, 0, 8, ebpf_headers->ipv6.dstAddr[8]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 9, 0, 8, ebpf_headers->ipv6.dstAddr[9]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 10, 0, 8, ebpf_headers->ipv6.dstAddr[10]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 11, 0, 8, ebpf_headers->ipv6.dstAddr[11]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 12, 0, 8, ebpf_headers->ipv6.dstAddr[12]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 13, 0, 8, ebpf_headers->ipv6.dstAddr[13]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 14, 0, 8, ebpf_headers->ipv6.dstAddr[14]);
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 15, 0, 8, ebpf_headers->ipv6.dstAddr[15]);
    //    ebpf_packetOffsetInBits += 128;
    //}
    //if (ebpf_headers->icmp.valid) {
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->icmp.typeCode);
    //    ebpf_packetOffsetInBits += 16;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->icmp.hdrChecksum);
    //    ebpf_packetOffsetInBits += 16;
    //}
    //if (ebpf_headers->udp.valid) {
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->udp.srcPort);
    //    ebpf_packetOffsetInBits += 16;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->udp.dstPort);
    //    ebpf_packetOffsetInBits += 16;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->udp.length_);
    //    ebpf_packetOffsetInBits += 16;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->udp.checksum);
    //    ebpf_packetOffsetInBits += 16;
    //}
    //if (ebpf_headers->tcp.valid) {
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->tcp.srcPort);
    //    ebpf_packetOffsetInBits += 16;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->tcp.dstPort);
    //    ebpf_packetOffsetInBits += 16;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 32, ebpf_headers->tcp.seqNo);
    //    ebpf_packetOffsetInBits += 32;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 32, ebpf_headers->tcp.ackNo);
    //    ebpf_packetOffsetInBits += 32;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 4, ebpf_headers->tcp.dataOffset);
    //    ebpf_packetOffsetInBits += 4;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 4, 4, ebpf_headers->tcp.res);
    //    ebpf_packetOffsetInBits += 4;
    //    bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers->tcp.flags);
    //    ebpf_packetOffsetInBits += 8;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->tcp.window);
    //    ebpf_packetOffsetInBits += 16;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->tcp.checksum);
    //    ebpf_packetOffsetInBits += 16;
    //    //bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers->tcp.urgentPtr);
    //    ebpf_packetOffsetInBits += 16;
    //}

    return 0 /* drop packet; clone is forwarded */;
}
#endif
