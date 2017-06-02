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

/* Protocol parser generated from P4 1.0
 *
 * TODO:
 * - move to P4 2016
 * - use union for protocol header to save space
 */
#include "ovs-p4.h"
#include "api.h"
#include "helpers.h"
#include "maps.h"

/* first function called after tc ingress */
__section_tail(PARSER_CALL)
static int ovs_parser(struct __sk_buff* ebpf_packet) {
    struct ebpf_headers_t ebpf_headers = {};
    struct ebpf_metadata_t ebpf_metadata = {};
    unsigned ebpf_packetOffsetInBits = 0;
    enum ErrorCode ebpf_error = p4_pe_no_error;
    u32 ebpf_zero = 0;

    goto start;
    start: {
        goto parse_ethernet;
    }
    parse_ethernet: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 48)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ethernet.dstAddr[0] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 0) >> 0));
        ebpf_headers.ethernet.dstAddr[1] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 1) >> 0));
        ebpf_headers.ethernet.dstAddr[2] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 2) >> 0));
        ebpf_headers.ethernet.dstAddr[3] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 3) >> 0));
        ebpf_headers.ethernet.dstAddr[4] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 4) >> 0));
        ebpf_headers.ethernet.dstAddr[5] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 5) >> 0));
        ebpf_packetOffsetInBits += 48;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 48)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ethernet.srcAddr[0] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 0) >> 0));
        ebpf_headers.ethernet.srcAddr[1] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 1) >> 0));
        ebpf_headers.ethernet.srcAddr[2] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 2) >> 0));
        ebpf_headers.ethernet.srcAddr[3] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 3) >> 0));
        ebpf_headers.ethernet.srcAddr[4] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 4) >> 0));
        ebpf_headers.ethernet.srcAddr[5] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 5) >> 0));
        ebpf_packetOffsetInBits += 48;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ethernet.etherType = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        ebpf_headers.ethernet.valid = 1;
        u32 tmp_3 = ebpf_headers.ethernet.etherType;
        if (tmp_3 == 33024)
            goto parse_vlan;
        if (tmp_3 == 34984)
            goto parse_vlan;
        if (tmp_3 == 2054)
            goto parse_arp;
        if (tmp_3 == 2048)
            goto parse_ipv4;
        if (tmp_3 == 34525)
            goto parse_ipv6;
        else
            goto ovs_tbl_4;
    }
    parse_vlan: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 3)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.vlan.pcp = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (5)) & EBPF_MASK(u8, 3);
        ebpf_packetOffsetInBits += 3;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 1)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.vlan.cfi = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (4)) & EBPF_MASK(u8, 1);
        ebpf_packetOffsetInBits += 1;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 12)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.vlan.vid = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0)) & EBPF_MASK(u16, 12);
        ebpf_packetOffsetInBits += 12;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.vlan.etherType = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        ebpf_headers.vlan.valid = 1;
        u32 tmp_5 = ebpf_headers.vlan.etherType;
        if (tmp_5 == 2054)
            goto parse_arp;
        if (tmp_5 == 2048)
            goto parse_ipv4;
        if (tmp_5 == 34525)
            goto parse_ipv6;
        else
            goto ovs_tbl_4;
    }
    parse_arp: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.arp.hwType = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.arp.protoType = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.arp.hwAddrLen = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.arp.protoAddrLen = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.arp.opcode = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        ebpf_headers.arp.valid = 1;
        goto ovs_tbl_4;
    }
    parse_ipv4: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv4.version = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (4)) & EBPF_MASK(u8, 4);
        ebpf_headers.ipv4.version = 0;
        ebpf_packetOffsetInBits += 4;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv4.ihl = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0)) & EBPF_MASK(u8, 4);
        ebpf_headers.ipv4.ihl = 0;
        ebpf_packetOffsetInBits += 4;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv4.diffserv = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.ipv4.diffserv = 0;
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv4.totalLen = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.ipv4.totalLen = 0;
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }

        // Remove from key
    //    ebpf_headers.ipv4.identification = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.ipv4.identification = 0;
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 3)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv4.flags = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (5)) & EBPF_MASK(u8, 3);
        ebpf_headers.ipv4.flags = 0;
        ebpf_packetOffsetInBits += 3;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 13)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv4.fragOffset = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0)) & EBPF_MASK(u16, 13);
        ebpf_headers.ipv4.fragOffset = 0;
        ebpf_packetOffsetInBits += 13;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.ttl = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.protocol = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        // Remove from key
        //ebpf_headers.ipv4.hdrChecksum = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.ipv4.hdrChecksum = 0;
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.srcAddr = ((load_word(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 32;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.dstAddr = ((load_word(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 32;
        ebpf_headers.ipv4.valid = 1;
        u32 tmp_6 = ebpf_headers.ipv4.protocol;
        if (tmp_6 == 6)
            goto parse_tcp;
        if (tmp_6 == 17)
            goto parse_udp;
        if (tmp_6 == 1)
            goto parse_icmp;
        else
            goto ovs_tbl_4;
    }
    parse_ipv6: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv6.version = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (4)) & EBPF_MASK(u8, 4);
        ebpf_packetOffsetInBits += 4;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv6.trafficClass = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (4)) & EBPF_MASK(u16, 8);
        ebpf_headers.ipv6.trafficClass = 0;
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 20)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv6.flowLabel = ((load_word(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (8)) & EBPF_MASK(u32, 20);
        ebpf_packetOffsetInBits += 20;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv6.payloadLen = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.ipv6.payloadLen = 0;
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv6.nextHdr = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv6.hopLimit = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.ipv6.hopLimit = 0;
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 128)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv6.srcAddr[0] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 0) >> 0));
        ebpf_headers.ipv6.srcAddr[1] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 1) >> 0));
        ebpf_headers.ipv6.srcAddr[2] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 2) >> 0));
        ebpf_headers.ipv6.srcAddr[3] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 3) >> 0));
        ebpf_headers.ipv6.srcAddr[4] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 4) >> 0));
        ebpf_headers.ipv6.srcAddr[5] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 5) >> 0));
        ebpf_headers.ipv6.srcAddr[6] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 6) >> 0));
        ebpf_headers.ipv6.srcAddr[7] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 7) >> 0));
        ebpf_headers.ipv6.srcAddr[8] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 8) >> 0));
        ebpf_headers.ipv6.srcAddr[9] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 9) >> 0));
        ebpf_headers.ipv6.srcAddr[10] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 10) >> 0));
        ebpf_headers.ipv6.srcAddr[11] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 11) >> 0));
        ebpf_headers.ipv6.srcAddr[12] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 12) >> 0));
        ebpf_headers.ipv6.srcAddr[13] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 13) >> 0));
        ebpf_headers.ipv6.srcAddr[14] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 14) >> 0));
        ebpf_headers.ipv6.srcAddr[15] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 15) >> 0));
        ebpf_packetOffsetInBits += 128;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 128)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv6.dstAddr[0] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 0) >> 0));
        ebpf_headers.ipv6.dstAddr[1] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 1) >> 0));
        ebpf_headers.ipv6.dstAddr[2] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 2) >> 0));
        ebpf_headers.ipv6.dstAddr[3] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 3) >> 0));
        ebpf_headers.ipv6.dstAddr[4] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 4) >> 0));
        ebpf_headers.ipv6.dstAddr[5] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 5) >> 0));
        ebpf_headers.ipv6.dstAddr[6] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 6) >> 0));
        ebpf_headers.ipv6.dstAddr[7] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 7) >> 0));
        ebpf_headers.ipv6.dstAddr[8] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 8) >> 0));
        ebpf_headers.ipv6.dstAddr[9] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 9) >> 0));
        ebpf_headers.ipv6.dstAddr[10] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 10) >> 0));
        ebpf_headers.ipv6.dstAddr[11] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 11) >> 0));
        ebpf_headers.ipv6.dstAddr[12] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 12) >> 0));
        ebpf_headers.ipv6.dstAddr[13] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 13) >> 0));
        ebpf_headers.ipv6.dstAddr[14] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 14) >> 0));
        ebpf_headers.ipv6.dstAddr[15] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 15) >> 0));
        ebpf_packetOffsetInBits += 128;
        ebpf_headers.ipv6.valid = 1;
        u32 tmp_7 = ebpf_headers.ipv6.nextHdr;
        if (tmp_7 == 6)
            goto parse_tcp;
        if (tmp_7 == 17)
            goto parse_udp;
        if (tmp_7 == 1)
            goto parse_icmp;
        else
            goto ovs_tbl_4;
    }
    parse_tcp: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.tcp.srcPort = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.tcp.dstPort = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.tcp.seqNo = ((load_word(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.tcp.seqNo = 0;
        ebpf_packetOffsetInBits += 32;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.tcp.ackNo = ((load_word(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.tcp.ackNo = 0;
        ebpf_packetOffsetInBits += 32;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.tcp.dataOffset = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (4)) & EBPF_MASK(u8, 4);
        ebpf_headers.tcp.dataOffset = 0;
        ebpf_packetOffsetInBits += 4;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.tcp.res = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0)) & EBPF_MASK(u8, 4);
        ebpf_headers.tcp.res = 0;
        ebpf_packetOffsetInBits += 4;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.tcp.flags = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.tcp.window = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.tcp.window = 0;
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        // Remove from key
        //ebpf_headers.tcp.checksum = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.tcp.checksum = 0;

        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.tcp.urgentPtr = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.tcp.urgentPtr = 0;
        ebpf_packetOffsetInBits += 16;
        ebpf_headers.tcp.valid = 1;
        goto ovs_tbl_4;
    }
    parse_udp: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.udp.srcPort = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.udp.dstPort = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.udp.length_ = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.udp.length_ = 0;
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        // Remove from key
        // ebpf_headers.udp.checksum = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.udp.checksum = 0;
        ebpf_packetOffsetInBits += 16;
        ebpf_headers.udp.valid = 1;
        goto ovs_tbl_4;
    }
    parse_icmp: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.icmp.typeCode = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        // Remove from key
        // ebpf_headers.icmp.hdrChecksum = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.icmp.hdrChecksum = 0;
        ebpf_packetOffsetInBits += 16;
        ebpf_headers.icmp.valid = 1;
        goto ovs_tbl_4;
    }

    /* Most of the code are generated by P4C-EBPF
       Manual code starts here */
    ovs_tbl_4:
    {
        int ret;
        struct bpf_tunnel_key key;

        ebpf_metadata.md.skb_priority = ebpf_packet->priority;
        /* Don't use ovs_cb_get_ifindex(), that gets optimized into something
         * that can't be verified. >:( */
        if (ebpf_packet->cb[OVS_CB_INGRESS]) {
            ebpf_metadata.md.in_port = ebpf_packet->ingress_ifindex;
        }
        if (!ebpf_packet->cb[OVS_CB_INGRESS]) {
            ebpf_metadata.md.in_port = ebpf_packet->ifindex;
        }
        ebpf_metadata.md.pkt_mark = ebpf_packet->mark;

        ret = bpf_skb_get_tunnel_key(ebpf_packet, &key, sizeof(key), 0);
        if (!ret) {
            memcpy(&ebpf_metadata.tnl_md.tun_id, &key.tunnel_id, sizeof(key.tunnel_id));
            ebpf_metadata.tnl_md.ip_dst = key.remote_ipv4;
            ebpf_metadata.tnl_md.ip_tos = key.tunnel_tos;
            ebpf_metadata.tnl_md.ip_ttl = key.tunnel_ttl;
            /* TODO: bpf_skb_get_tunnel_opt */
        }
    }

end:
    /* write flow key and md to key map */
    printt("Parser: updating flow key\n");
    bpf_map_update_elem(&percpu_headers,
                        &ebpf_zero, &ebpf_headers, BPF_ANY);

    if (ebpf_headers.icmp.valid)
        printt("receive icmp packet\n");

    if (ovs_cb_is_initial_parse(ebpf_packet)) {
        bpf_map_update_elem(&percpu_metadata,
                            &ebpf_zero, &ebpf_metadata, BPF_ANY);
    }
    ebpf_packet->cb[OVS_CB_ACT_IDX] = 0;

    /* tail call next stage */
    printt("tail call match+lookup stage\n");
    bpf_tail_call(ebpf_packet, &tailcalls, MATCH_ACTION_CALL);

    printt("[ERROR] missing tail call\n");
    return TC_ACT_OK;
}
