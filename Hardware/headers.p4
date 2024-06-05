#ifndef _HEADERS_
#define _HEADERS_

#include "types.p4"

//@controller_header("packet_out")
header packet_out_header_t{
    bit<16> egress_port;
}

//@controller_header("packet_in")
header packet_in_header_t{
    bit<16> ingress_port;
}

header srcRoute_t {
    bit<7>    bos;
    bit<9>   port;
}
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
header measure_t {
    bit<16> proto_id;
    bit<8> tag;  //4 mode header, 0->pedning, 1->targeted, 2->targeted/untargeted , 3-> Feature Measured
}
struct flow_t{
   bit<1> flowid;
   bit<8> proto;
   bit<32> src;
   bit<32> dst;
   bit<16> srcp;
   bit<16> dstp;
   bit<32> hval;
   bit<1> evic;
   bit<1> mf;
   bit<32> hash;
   bit<32> count;
   bit<32> bcount;
   bit<32> f_idx;
}
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}
//Bridge metadata
@flexible
header pkt_info_t{
    bit<16> sport;
    bit<16> dport;
    bit<32> flow_offset;
    bit<8> y;
    bit<1> add;
}

@flexible
struct metadata {
    bit<1> flowid;
    bit<1> mf;
    bit<1> evic;
    bit<32> Mhindex;
    bit<32> Hhindex;
    bit<32> hval;
    bit<32> hval_c_;
    bit<32> hval_reg;
    bit<8> mcnt;
    bit<8> mcnt_;
    bit<32> cnt;
    bit<32> bcnt;
    bit<8> path_l;
    bit<1> next_stage;
    bit<1> edge;
    bit<32> prev_flow_offset;
    bit<32> flow_index;
    pkt_info_t md;
    bit<32> idx;
    bit<1> truncation_flag;
    bit<32> binIndex_preTruncation;
    bit<32> binIndex_posTruncation;
    bit<1> src_route;
}
struct headers {
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t   ethernet;
    srcRoute_t[MAX_HOPS]  srcRoute;
    measure_t    measure;
    ipv4_t       ipv4;
    srcRoute_t[MAX_HOPS]  srcRoute_info;
    tcp_t 	 tcp;
    udp_t 	 udp;
}

#endif
