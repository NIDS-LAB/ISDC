/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "types.p4"
#include "headers.p4"
#include "parsers.p4"

#include "Inspect.p4"
#include "Meter.p4"

control Ingress(    
    inout headers                        hdr,
    inout  metadata                       meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md){
    
    INspect() inspect; 
    MEter() meter;

    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_func_5tuple;
 
    action add_header(){
   	hdr.measure.setValid();
	hdr.measure.proto_id=hdr.ethernet.etherType;
	hdr.ethernet.etherType=TYPE_MEASURE;
	hdr.measure.tag=0;
    	hdr.ipv4.ttl = 255;
	meta.edge=1;
	meta.md.y=1;	
    }
    action get_hash(){
   	meta.hval = hash_func_5tuple.get({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, meta.md.sport, meta.md.dport});
    }
    action drop(){
       ig_dprsr_md.drop_ctl = 1;
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, path_t plength) {
        ig_tm_md.ucast_egress_port = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        meta.path_l=hdr.ipv4.ttl;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	    meta.md.y=1;
    }
    action remove_header(macAddr_t dstAddr, egressSpec_t port){
	ig_tm_md.ucast_egress_port = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
	    hdr.ethernet.etherType = TYPE_IPV4;
        meta.path_l=hdr.ipv4.ttl;
	    meta.md.y=0;
    }
    action srcRoute_nhop(){
        ig_tm_md.ucast_egress_port = (bit<9>)hdr.srcRoute[0].port;
        hdr.srcRoute.pop_front(1);
   }
   action idx_calc0(){ 
	meta.Mhindex=(bit<32>)meta.hval[18:0]; // & MLIST_SIZE;
	meta.Hhindex=(bit<32>)meta.hval[16:0]; // & LIST_SIZE;
   }
   action tcp(){
	meta.md.sport=hdr.tcp.srcPort;
	meta.md.dport=hdr.tcp.dstPort;		         
   }
   action udp(){
	meta.md.sport=hdr.udp.srcPort;
	meta.md.dport=hdr.udp.dstPort;		         
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
   table l4_type {
        key = {
            hdr.ipv4.protocol: exact;
        }
        actions = {
            tcp;
	    udp;
            @defaultonly NoAction;
        }
	size = 2;
	const entries={
	(8w6) : tcp();
	(8w17) : udp();
	}
        default_action = NoAction;
   }
    
   apply{

    meta.edge=0;
    if (l4_type.apply().hit){  
    	if(!hdr.measure.isValid()){
           add_header();
        }
    }
    
    //IP OR Src Routing 
    if(hdr.srcRoute[0].isValid()){   //Rpt ack use src routing
	ig_tm_md.bypass_egress = 1;
        if(hdr.srcRoute[0].bos==1){
            hdr.ethernet.etherType=TYPE_IPV4;
            //hdr.packet_in.setValid();
        }
        srcRoute_nhop();
    }
    else{ 
           ipv4_lpm.apply();
    }
    
    //Handling Rpt packet
    if(hdr.ipv4.protocol==TYPE_REPORT && meta.src_route==0){
	    ig_tm_md.bypass_egress = 1;
            hdr.srcRoute_info.push_front(1);
            hdr.srcRoute_info[0].setValid();
            hdr.srcRoute_info[0]={(bit<7>)0, (bit<9>)ig_intr_md.ingress_port};
            hdr.ipv4.totalLen=hdr.ipv4.totalLen + (bit<16>)8;
        if(ig_intr_md.ingress_port == CPU_PORT){
            //hdr.packet_out.setInvalid();
            hdr.srcRoute_info[0].bos=(bit<7>)1;
        }
        else if(meta.md.y==0){
            ig_tm_md.ucast_egress_port = CPU_PORT;
            //hdr.packet_in.setValid();
        }
    }
    else if(meta.src_route==0 && hdr.measure.isValid() && ((hdr.measure.tag==1) || (hdr.measure.tag==2) || (meta.edge==1))){
		    get_hash();
  		  ig_dprsr_md.digest_type=0;
		    meta.next_stage=1;
		    meta.cnt=0;
		    meta.bcnt=0;

		    meta.flowid=0;
		    meta.mf=0;
		    meta.evic=0;                    
		    
        //FlowIndentifier
        if(meta.edge==1){
          idx_calc0(); 
          inspect.apply(hdr, meta.hval, meta.Mhindex, meta, ig_dprsr_md);
        }	    
        //Feature Meter
        if(meta.next_stage==1){
            meta.md.add=0;
            meter.apply(hdr, meta.hval, meta.Hhindex, meta, ig_dprsr_md);
        }
    	}        
    }           
}
control Egress(
    /* User */
    inout headers                          hdr,
    inout metadata                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    
    Register<bit<32>, bit<32>>(1) dummy1;

    MathUnit<bit<32>>(MathOp_t.MUL, FLOW_BINS) mul;
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(dummy1) mul_calc = {
        void apply (inout bit<32> value, out bit<32> result) {            
          value = mul.execute(meta.md.flow_offset);
          result = value;
        }
    };

    Register<bit<16>, bit<32>>(PARTITION_SIZE) reg_grid;
    RegisterAction<bit<16>, bit<32>, bit<32>>(reg_grid) reg_grid_increase = {
        void apply (inout bit<16> value) {            
          value = value + 16w1;
        }
    };

   action drop(){
        eg_dprsr_md.drop_ctl = 1;
    }
    action truncate_binIndex(bit<32> new_index, bit<1> flag) {
        meta.binIndex_posTruncation = new_index;
        meta.truncation_flag = flag;
   }

  action idx_calc2(){
        meta.flow_index=mul_calc.execute(0) + meta.binIndex_posTruncation;
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
  table ipv4_drop {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            meta.md.sport : exact;
            meta.md.dport : exact;
            hdr.ipv4.protocol : exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    apply {
          if(meta.md.add==1){
                meta.binIndex_preTruncation =  (bit<32>) (hdr.ipv4.totalLen >> BIN_WIDTH_SHIFT);
                meta.truncation_flag = 0;
                truncation_tbl.apply();
                if(meta.truncation_flag==1){
                    //meta.flow_index=(bit<32>)(meta.flow_offset*FLOW_BINS) + meta.binIndex_posTruncation;
                    idx_calc2();
                    reg_grid_increase.execute(meta.flow_index);
              }	
		      } 
        	if(meta.md.y==0){
                	hdr.measure.setInvalid();
            }
         
         //   if(ipv4_drop.apply().hit){
		//	    hdr.ipv4.setInvalid();
		//	drop();
	    //    }
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;

