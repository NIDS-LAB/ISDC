/* -*- P4_16 -*- */

#define CPU_PORT 64
#define MAX_HOPS 13
#define PKT_INGRESS 1

const bit<32> MAX = (1<<32) - 1;
const bit<16> PKT_INFO = 0x8888;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MEASURE = 0x1FB6;
const bit<16> TYPE_SRCROUTING = 0x1FBB;

const bit<2> TYPE_ACK = 3;
const bit<2> TYPE_RPT = 2;
const bit<8> TYPE_SRCINFO = 0x88;


const bit<8> REST = 15;
const bit<32> LIST_SIZE=9287; 
const bit<32> MLIST_SIZE=1024; 

const bit<32> QUEUE_SIZE=1024;

/* In our running example, we will use QL=4 */
const bit<8> BIN_WIDTH_SHIFT = 4 ; 

//const bit<32> FLOW_BINS = 1500 >> BIN_WIDTH_SHIFT; //94 flow counters for QL=4 && BinWidth=16
const bit<32> FLOW_BINS = 94; // QL=4 + top-10 most relavent bin
/* Number of flows in each partition */
const bit<32> FLOWS_PER_PARTITION = (LIST_SIZE + QUEUE_SIZE);

const bit<32> PARTITION_SIZE = FLOWS_PER_PARTITION*FLOW_BINS;

/* Number of packet sizes considered for truncation */
const bit<32> NUM_PKT_SIZES = 1500;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<8>  path_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

@controller_header("packet_out")
header packet_out_header_t{
    bit<16> egress_port;
}

@controller_header("packet_in")
header packet_in_header_t{
    bit<16> ingress_port;
}

header srcRoute_t {
    bit<2>    bos;
    bit<14>   port;
}
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
header measure_t {
    bit<16> proto_id;
    bit<8> tag;  
    bit<16> len;
    bit<16> st_len;
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
   bit<32> h_idx;
   bit<32> nf_idx;
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

header flow_info_t{
   bit<8> type_;
   bit<8> proto;
   bit<32> src;
   bit<32> dst;
   bit<16> srcp;
   bit<16> dstp;
   bit<32> hval;
   bit<4> evic;
   bit<4> mf;
   bit<32> hash;
   bit<32> count;
   bit<32> bcount;
   bit<32> f_idx;
   bit<32> h_idx;
   bit<32> nf_idx;
}

struct metadata {
    @field_list(1)
    bit<1> mf;
    @field_list(1, 2)
    bit<1> evic;
    @field_list(1, 2, 3)
    bit<32> hval;
    @field_list(1, 2, 3, 4)
    bit<32> hval_c_;
    @field_list(1, 2, 3, 4, 5)
    bit<32> Hhindex;
    @field_list(1, 2, 3, 4, 5, 6)
    bit<32> cnt;
    @field_list(1, 2, 3, 4, 5, 6, 7)
    bit<32> bcnt;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8)
    bit<32> prev_flow_offset;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9)
    bit<32> flow_offset;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
    bit<8> path_reg;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
    bit<16> sport;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
    bit<16> dport;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
    bit<14> port;


    bit<1> flowid;
    bit<32> Mhindex;
    bit<16> length_;
    bit<32> hval_reg;
    bit<8> mcnt;
    bit<16> mbcnt;
    bit<32> cnt_;
    bit<32> bcnt_;
    bit<8> path_l;
    bit<8> y;
    bit<1> next_stage;
    bit<1> edge;
    bit<1> clone;
    bit<32> flow_index;
    bit<32> idx;
    bit<1> truncation_flag;
    bit<32> binIndex_preTruncation;
    bit<32> binIndex_posTruncation;
    bit<1> heavy;
    bit<2> pkt_type;
}
struct headers {
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t   ethernet;
    flow_info_t c_info;
    measure_t    measure;
    srcRoute_t[MAX_HOPS]  srcRoute;
    srcRoute_t[MAX_HOPS]  srcRoute_info;
    ipv4_t       ipv4;
    tcp_t 	 tcp;
    udp_t 	 udp;
}
