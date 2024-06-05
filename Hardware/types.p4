#ifndef _TYPES_
#define _TYPES_

#define CPU_PORT 192
#define MAX_HOPS 14

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MEASURE = 0x1FB6;
const bit<16> TYPE_SRCROUTING = 0x1FBB;
const bit<8> TYPE_REPORT = 251;
const bit<8> TYPE_ACK = 252;

const bit<32> QUEUE_SIZE=256;
const bit<32> LIST_SIZE=2059; //ratio 1
const bit<32> MLIST_SIZE=3511; //ratio 1

/* In our running example, we will use QL=4 */
const bit<8> BIN_WIDTH_SHIFT = 4 ; 

//const bit<32> FLOW_BINS = 1500 >> BIN_WIDTH_SHIFT; //94 flow counters for QL=4 && BinWidth=16
const bit<32> FLOW_BINS = 10; // QL=4 + top-10 most relavent bin
/* Number of flows in each partition */
const bit<32> FLOWS_PER_PARTITION = (LIST_SIZE + QUEUE_SIZE);

const bit<32> PARTITION_SIZE = FLOWS_PER_PARTITION*FLOW_BINS;

/* Number of packet sizes considered for truncation */
const bit<32> NUM_PKT_SIZES = 1500;

typedef bit<9>  egressSpec_t;
typedef bit<8>  path_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

struct ins_pair_t{
	bit<32> cnt;
	bit<32> key;
}
struct feature_pair_t{
	bit<32> key;
	bit<8> path;
}
#endif
