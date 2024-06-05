//#idndef _PARSERS_
#define _PARSERS_

#include "types.p4"
#include "headers.p4"

parser IngressParser(packet_in packet,
                out headers hdr,
                out metadata meta,
                out ingress_intrinsic_metadata_t  ig_intr_md) {

    state start {
	packet.extract(ig_intr_md);
	packet.advance(PORT_METADATA_SIZE);
        meta.src_route=0;
        transition select(ig_intr_md.ingress_port){
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }
    
    state parse_packet_out{
        //packet.extract(hdr.packet_out);
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : ipv4_accept;
            TYPE_SRCROUTING: parse_srcRouting;
            default: reject;
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
    
    state parse_srcRouting {
        meta.src_route=1;
        packet.extract(hdr.srcRoute.next);
        transition select(hdr.srcRoute.last.bos){
                1: parse_ipv4;
                default: parse_srcRouting;
        }
    }

    state parse_measure{
	packet.extract(hdr.measure);
        transition select(hdr.measure.proto_id) {
	    TYPE_IPV4: parse_ipv4;
            default : accept;
	  }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
	    17: parse_udp;
            TYPE_REPORT: parse_srcRouting_info;
            default: accept;
        }
    }

    state parse_srcRouting_info {
        packet.extract(hdr.srcRoute_info.next);
        transition select(hdr.srcRoute_info.last.bos){
                1: accept;
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

control IngressDeparser(packet_out packet,
    /* User */
    inout headers                      		     hdr,
    in    metadata                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    // Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;
    Digest<flow_t>() digest_a;
    
    apply {        
    if(ig_dprsr_md.digest_type==1){
                digest_a.pack({meta.flowid, hdr.ipv4.protocol, hdr.ipv4.srcAddr,
                     hdr.ipv4.dstAddr, meta.md.sport, meta.md.dport, meta.hval, meta.evic, meta.mf,
                          meta.hval_c_, meta.cnt, meta.bcnt, meta.prev_flow_offset});
               }

          packet.emit(meta.md);
	  packet.emit(hdr);
    }
    
}

parser EgressParser(packet_in      packet,
    /* User */
    out headers          hdr,
    out metadata         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        packet.extract(eg_intr_md);
        packet.extract(meta.md);
        transition parse_ether;
    }
    state parse_ether {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
    	    TYPE_MEASURE: parse_measure;
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }
    state parse_measure{
	packet.extract(hdr.measure);
        transition select(hdr.measure.proto_id) {
	    TYPE_IPV4: parse_ipv4;
            default : accept;
	  }
    }
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition accept;
    }
    
}

control EgressDeparser(packet_out packet,
    /* User */
    inout headers                       hdr,
    in    metadata                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        packet.emit(hdr);
    }
}
//#endif
