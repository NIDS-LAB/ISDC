
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "headers.p4"


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.pkt_type=0;
        transition select(standard_metadata.ingress_port){
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }
    
    state parse_packet_out{
        packet.extract(hdr.packet_out);
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : ipv4_accept;
            TYPE_SRCROUTING: parse_srcRouting;
            default: accept;
        }
    }
    
    state ipv4_accept{
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
    	    TYPE_MEASURE: parse_measure;
            TYPE_SRCROUTING: parse_srcRouting;
            default : accept;
        }
    }

    state parse_measure{
	packet.extract(hdr.measure);
        transition select(hdr.measure.proto_id) {
	    TYPE_IPV4: parse_ipv4;
        TYPE_SRCROUTING: parse_srcRouting;
        default : accept;
	  }
    }

    state parse_srcRouting {
        packet.extract(hdr.srcRoute.next);
        meta.pkt_type=hdr.srcRoute.last.bos;
        transition select(hdr.srcRoute.last.bos){
                1: parse_ipv4;
                TYPE_RPT: check_type_rpt; //RPT
                TYPE_ACK: accept;  //ACK
                default: parse_srcRouting;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
	        17: parse_udp;
            default: accept;
        }
    }

    state check_type_rpt{
        transition select(standard_metadata.ingress_port){
            CPU_PORT: accept;
            default: parse_srcRouting_info;
        }
    }

    state parse_srcRouting_info {
        packet.extract(hdr.srcRoute_info.next);
        transition select(hdr.srcRoute_info.last.bos){
                TYPE_ACK: accept;
                default: parse_srcRouting_info;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
   register<bit<8>>(MLIST_SIZE) Mpacket_cnt;
   register<bit<16>>(MLIST_SIZE) Mpacket_bcnt;
   register<bit<32>>(MLIST_SIZE) Mhash_check_register;
   register<bit<8>>(MLIST_SIZE)  Mpacket_cnt_;

   register<bit<32>>(LIST_SIZE) packet_cnt;
   register<bit<32>>(LIST_SIZE) packet_bcnt;
   register<bit<32>>(LIST_SIZE) hash_check_register;
   register<bit<8>>(LIST_SIZE) path_reg;

   register<bit<32>>(LIST_SIZE)  Hflow_off;
   register<bit<32>>(1) reg_cur_grid;
   register<bit<32>>(QUEUE_SIZE) reg_queue;
   register<bit<16>>(PARTITION_SIZE) reg_grid;

   bit<32> cnt;
   bit<32> bcnt;

  action add_header(){
   	  hdr.measure.setValid();
	    hdr.measure.proto_id=hdr.ethernet.etherType;
	    hdr.ethernet.etherType=TYPE_MEASURE;
	    hdr.measure.tag=0;
      hdr.measure.len=hdr.ipv4.identification;
      hdr.measure.st_len=0;
      hdr.ipv4.ttl = 255;
	    meta.edge=1;
	    meta.y=1;
   }
   action get_tcp_hash(){
	    hash(meta.hval, HashAlgorithm.crc32_custom,
        (bit<1>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort},
	      (bit<33>)((1<<32) - 1));

	    meta.length_=hdr.ipv4.totalLen;
  	  meta.sport=hdr.tcp.srcPort;
	    meta.dport=hdr.tcp.dstPort;
   }
   action get_udp_hash(){
	    hash(meta.hval, HashAlgorithm.crc32_custom,
      (bit<1>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.udp.srcPort, hdr.udp.dstPort},
	    (bit<33>)((1<<32) - 1));

	    meta.length_=hdr.ipv4.totalLen;
	    meta.sport=hdr.udp.srcPort;
	    meta.dport=hdr.udp.dstPort;
   }
   action count_it(){
	    Mpacket_cnt.write((bit<32>)meta.Mhindex, meta.mcnt +  1);
	    Mpacket_bcnt.write((bit<32>)meta.Mhindex, meta.mbcnt + (bit<16>)meta.length_);
   }
   action count1_it(){
	    packet_bcnt.read(bcnt, (bit<32>)meta.Hhindex);
	    packet_cnt.write((bit<32>)meta.Hhindex, meta.cnt_ + meta.cnt + 1);
	    packet_bcnt.write((bit<32>)meta.Hhindex, bcnt + meta.bcnt + (bit<32>)meta.length_);
   }
   action drop() {
      mark_to_drop(standard_metadata);
   }
   action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
      standard_metadata.egress_spec = port;
      hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
      hdr.ethernet.dstAddr = dstAddr;
      meta.path_l=hdr.ipv4.ttl;
      hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	    meta.y=1;
   }
    action remove_header(macAddr_t dstAddr, egressSpec_t port){
	    standard_metadata.egress_spec = port;
      hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
      hdr.ethernet.dstAddr = dstAddr;
	    hdr.ethernet.etherType = TYPE_IPV4;
      meta.path_l=hdr.ipv4.ttl;
      hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	    meta.y=0;
   }
    action Mfirst_count(){
      Mhash_check_register.write((bit<32>)meta.Mhindex, meta.hval);
      Mpacket_bcnt.write((bit<32>)meta.Mhindex,  (bit<16>)meta.length_);
      Mpacket_cnt.write((bit<32>)meta.Mhindex,  (bit<8>) 1);
      Mpacket_cnt_.write((bit<32>)meta.Mhindex,  (bit<8>)0);
   }
    action first_count(){
	    hash_check_register.write((bit<32>)meta.Hhindex, meta.hval);
	    path_reg.write((bit<32>)meta.Hhindex, (bit<8>)meta.path_l);
    	packet_cnt.write((bit<32>)meta.Hhindex, (meta.cnt + (bit<32>)1));
    	packet_bcnt.write((bit<32>)meta.Hhindex, meta.bcnt + (bit<32>)meta.length_);
   }
   action get_flow_offset(){
	    reg_cur_grid.read(meta.idx, (bit<32>)0);
	    reg_queue.read(meta.flow_offset, (bit<32>)meta.idx);
	    reg_queue.write((bit<32>)meta.idx, MAX);
	    meta.idx=(bit<32>)((bit<10>)(meta.idx+1));
	    reg_cur_grid.write((bit<32>)0, meta.idx);
   }
   action truncate_binIndex(bit<32> new_index, bit<1> flag) {
      meta.binIndex_posTruncation = new_index;
      meta.truncation_flag = flag;
   }
   action reg_grid_action(){
	    bit<16> value;  
      reg_grid.read(value, meta.flow_index);
      value = value+1;
      reg_grid.write(meta.flow_index, value);
   }
   action srcRoute_nhop(){
      standard_metadata.egress_spec = (bit<9>)hdr.srcRoute[0].port;
      hdr.srcRoute.pop_front(1);
  }

  table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
	          remove_header;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
   }
  table truncation_tbl {
        key = {
            meta.binIndex_preTruncation: exact;
        }
        actions = {
            truncate_binIndex();
            NoAction();
        }
        default_action = truncate_binIndex(0, 0);
		size = NUM_PKT_SIZES;
  }

  apply {

    meta.edge=0;
    if (hdr.ipv4.isValid() && !hdr.measure.isValid() && (hdr.tcp.isValid() || hdr.udp.isValid()) && 
            standard_metadata.ingress_port != CPU_PORT && meta.pkt_type != TYPE_RPT && meta.pkt_type !=TYPE_ACK) {
           add_header();
    }

	  if(hdr.measure.isValid()){
	     ipv4_lpm.apply();
	  }
    else if(hdr.srcRoute[0].isValid()){   
        if(hdr.srcRoute[0].bos!=0){
            hdr.ethernet.etherType=(bit<16>)meta.pkt_type + 0x8000;
            hdr.packet_in.setValid();
        }
        srcRoute_nhop();
    }

    
    if(meta.pkt_type==TYPE_RPT){
        hdr.srcRoute_info.push_front(1);
        hdr.srcRoute_info[0].setValid();
        hdr.srcRoute_info[0]={(bit<2>)0, (bit<14>)standard_metadata.ingress_port};
        if(standard_metadata.ingress_port == CPU_PORT){
            hdr.packet_out.setInvalid();
            hdr.srcRoute_info[0].bos=(bit<2>)3; //rpt
        }
      //  else if(meta.y==0){
      //      standard_metadata.egress_spec = CPU_PORT;
      //      hdr.packet_in.setValid();
      //  }
    }
    else if(hdr.measure.isValid()){
        meta.heavy=0;
        if ((hdr.tcp.isValid() || hdr.udp.isValid())){
            if((hdr.measure.tag==1) || (meta.edge==1)){
                if(hdr.tcp.isValid()){
                  get_tcp_hash();
                }
                else if(hdr.udp.isValid()){	
                  get_udp_hash();
                }
            meta.next_stage=1;
            meta.cnt=0;
            meta.bcnt=0;
            meta.clone=0;


            meta.flowid=0;
            meta.mf=0;
            meta.evic=0;                    

            if(meta.edge==1){
                if(hdr.tcp.isValid()){
                    hash(meta.Mhindex, HashAlgorithm.crc32_custom,
                      (bit<1>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort},
                      (bit<33>)MLIST_SIZE);
                }
                else if(hdr.udp.isValid()){	
                    hash(meta.Mhindex, HashAlgorithm.crc32_custom,
                      (bit<1>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.udp.srcPort, hdr.udp.dstPort},
                      (bit<33>)MLIST_SIZE);
                }
            Mpacket_cnt.read(meta.mcnt, (bit<32>)meta.Mhindex);
            Mhash_check_register.read(meta.hval_reg, (bit<32>)meta.Mhindex);

            if(meta.mcnt==0){
                Mhash_check_register.write((bit<32>)meta.Mhindex, meta.hval);
                Mpacket_bcnt.write((bit<32>)meta.Mhindex,  (bit<16>)meta.length_);
                Mpacket_cnt.write((bit<32>)meta.Mhindex,  (bit<8>)1);
                hdr.measure.tag=0; //First flow in mouse table (measured)
                meta.next_stage=0;
            }
            else if(meta.hval == meta.hval_reg){
                    Mpacket_bcnt.read(meta.mbcnt, (bit<32>)meta.Mhindex);
                    if(meta.mcnt<REST){
                        hdr.measure.tag=1;
                        count_it(); 
                    }
                    else{
                        Mpacket_cnt.write((bit<32>)meta.Mhindex,  (bit<8>)1);
                        Mpacket_cnt_.write((bit<32>)meta.Mhindex,  (bit<8>)0);
                        hdr.measure.tag=1;
                    }
            }
            else{
                    meta.cnt_=(bit<32>)meta.mcnt;
                    Mpacket_cnt_.read(meta.mcnt, (bit<32>)meta.Mhindex);
                    if(((bit<10>)meta.mcnt<=(bit<10>)(meta.cnt_*2)) && (meta.mcnt<REST)){
                        Mpacket_cnt_.write((bit<32>)meta.Mhindex, meta.mcnt + 1);
                        meta.cnt=0;
                        meta.bcnt=0;
                        hdr.measure.tag=2;
                        meta.next_stage=0;
                    }
                    else{
                        Mpacket_bcnt.read(meta.mbcnt, (bit<32>)meta.Mhindex);
                        meta.bcnt=(bit<32>)meta.mbcnt;
                        meta.cnt=meta.cnt_;
                        Mfirst_count();
                        meta.hval_c_=meta.hval_reg;
                        hdr.measure.tag=0; //First packet in mouse table
                        meta.next_stage=0;

                    }
              }
           }

            if(hdr.measure.tag==1){
                hdr.srcRoute.push_front(1);
                hdr.srcRoute[0].setValid();
                if(meta.edge==1){
                    hdr.srcRoute[0]={(bit<2>)1, (bit<14>)CPU_PORT};
                    hdr.measure.proto_id=TYPE_SRCROUTING;
                    hdr.measure.st_len=1;
                }
                else{
                    hdr.srcRoute[0]={(bit<2>)0, (bit<14>)standard_metadata.ingress_port};
                    meta.port = (bit<14>)standard_metadata.ingress_port;
                    hdr.measure.st_len=hdr.measure.st_len + 1;
                }
            }

            if(meta.next_stage==1){
                hash(meta.Hhindex, HashAlgorithm.crc32_custom, (bit<1>)0, {meta.hval},(bit<33>)LIST_SIZE);
                packet_cnt.read(meta.cnt_, (bit<32>)meta.Hhindex);

                hash_check_register.read(meta.hval_reg, (bit<32>)meta.Hhindex);
                if(meta.cnt_==0 && (hdr.measure.tag==1)){
                first_count();
                tf.count(0);
                meta.flowid=1;
                meta.mf=1;

                Hflow_off.read(meta.flow_offset, (bit<32>)meta.Hhindex);
                hdr.measure.tag=3;
                meta.heavy=1;
            }
            else if(meta.hval == meta.hval_reg){
                        count1_it(); 
                        tf.count(1);
                        hdr.measure.tag=3;
                        meta.heavy=1;
                        Hflow_off.read(meta.flow_offset, (bit<32>)meta.Hhindex);
                    hdr.srcRoute.pop_front(13);
	                hdr.measure.st_len=0;
            }
            if(hdr.measure.tag==1){
                path_reg.read(meta.path_reg, (bit<32>)meta.Hhindex);
                    if(meta.path_reg!=255){
                        if(meta.path_l == 255 || (meta.path_l < meta.path_reg)){
                            packet_bcnt.read(meta.bcnt_, (bit<32>)meta.Hhindex);
                            meta.flowid=1;
                            meta.mf=1;
                            meta.evic=1;                    

                            first_count();
                            meta.hval_c_=meta.hval_reg;
                            meta.cnt=meta.cnt_;
                            meta.bcnt=meta.bcnt_;
                            hdr.measure.tag=3;
                            meta.heavy=1;
                            Hflow_off.read(meta.prev_flow_offset, (bit<32>)meta.Hhindex);
                            get_flow_offset();
                            Hflow_off.write((bit<32>)meta.Hhindex,  meta.flow_offset);
                            }
                    }
                }

                if(meta.flowid==1){
                    meta.path_reg= (bit<8>)255 - hdr.ipv4.ttl;
                    if(meta.edge==0){
                        meta.clone=1;
                        clone_preserving_field_list(CloneType.I2E, 200, 1);
                    }
                    //hdr.srcRoute.pop_front(meta.path_reg);
                    hdr.srcRoute.pop_front(13);
	                hdr.measure.proto_id=TYPE_IPV4;
	                hdr.measure.st_len=0;
                }
            }

            if(hdr.measure.tag==3 && meta.heavy==1 && (meta.flow_offset != MAX)){
                // Do FlowLens  
                meta.binIndex_preTruncation =  (bit<32>) (meta.length_ >> BIN_WIDTH_SHIFT);
                meta.truncation_flag = 0;
                //truncation_tbl.apply();
                meta.binIndex_posTruncation = meta.binIndex_preTruncation;
                meta.truncation_flag = 1;
                if(meta.truncation_flag==1){
                    meta.flow_index=(bit<32>)(meta.flow_offset*FLOW_BINS) + meta.binIndex_posTruncation;
                    reg_grid_action();
                }	
            }
        }
            if(meta.clone==0 && (meta.evic==1 || meta.flowid==1)){
                digest<flow_t>((bit<32>)1024, {meta.flowid, hdr.ipv4.protocol, hdr.ipv4.srcAddr,
                     hdr.ipv4.dstAddr, meta.sport, meta.dport, meta.hval, meta.evic, meta.mf,
                     meta.hval_c_, meta.cnt, meta.bcnt, meta.prev_flow_offset, meta.Hhindex, meta.flow_offset});
               }
            if(meta.y==0){
                hdr.measure.setInvalid();
            }

          }

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { 
            if(standard_metadata.instance_type == PKT_INGRESS){
                    hdr.c_info.setValid();
                    hdr.c_info = {TYPE_SRCINFO, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, meta.sport, meta.dport, 
                                    meta.hval, (bit<4>)meta.evic, (bit<4>)meta.mf, meta.hval_c_, meta.cnt, meta.bcnt, 
                                    meta.prev_flow_offset, meta.Hhindex, meta.flow_offset};
                    hdr.packet_in.setValid();
                    hdr.measure.setInvalid();
                    hdr.ipv4.setInvalid();
                    hdr.srcRoute.push_front(1);
                    hdr.srcRoute[0].setValid();
                    hdr.srcRoute[0]={(bit<2>)0, meta.port};
                    hdr.ethernet.etherType=PKT_INFO;
                    meta.path_reg = meta.path_reg*2 + 57; 
                    truncate((bit<32>)meta.path_reg+2);
                }
          }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
	    packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.c_info);
    	packet.emit(hdr.measure);
        packet.emit(hdr.srcRoute);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.srcRoute_info);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;


