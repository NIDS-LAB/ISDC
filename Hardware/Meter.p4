#include "types.p4"
#include "headers.p4"

control MEter(inout headers hdr, in bit<32> hval, in bit<32> idx, 
		inout metadata meta, inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md ){

    Register<bit<32>, bit<32>>(LIST_SIZE) packet_cnt;
    Register<bit<32>, bit<32>>(LIST_SIZE) packet_bcnt;
    Register<bit<32>, bit<32>>(LIST_SIZE) hash_check_register;
    Register<bit<8>, bit<32>>(LIST_SIZE)  path_reg;

    Register<bit<32>, bit<32>>(LIST_SIZE) Hflow_off;
    Register<bit<32>, bit<1>>(1) reg_cur_grid;
    Register<bit<32>, bit<32>>(QUEUE_SIZE) reg_queue;

    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_cur_grid) get_cur_off = {
        void apply (inout bit<32> value, out bit<32> result) {
        	result = value;
        	value = value + 32w1;                      	
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(Hflow_off) Flow_offset = {
        void apply (inout bit<32> value, out bit<32> result) {            
          result = value; 
          if(meta.flowid==1){
            value = meta.md.flow_offset;
          }
      }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_queue) reg_queue_read = {
        void apply (inout bit<32> value, out bit<32> result) { 
                   result = value;            	
        }
    };
    RegisterAction<bit<8>, bit<32>, bit<16>>(path_reg) Feature_col_path = {
        void apply (inout bit<8> value, out bit<16> result) {            
          result = (bit<16>)meta.path_l - (bit<16>)value;
          if(meta.path_l == 8w255){
            value = meta.path_l; 
          }
          else{
            if(meta.path_l < value){  //#ToDo and check
              value = meta.path_l; 
            }
          }    
	      }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(hash_check_register) Feature_col_hash = {
        void apply (inout bit<32> value, out bit<32> result) {            
          result = value;
          if(meta.evic==1){
            value = hval;
          }
	      }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(packet_cnt) pkt_cnt_increase = {
        void apply (inout bit<32> value, out bit<32> result) {  
          result = value;
          if(meta.evic==0){
            value = value + 32w1;
          }
          else{
            value = 32w1;
          }        	                     
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(packet_bcnt) pkt_bcnt_increase = {
        void apply (inout bit<32> value, out bit<32> result) {            
          result = value;
          if(meta.evic==0){
                  value = value + 32w1;
          }
          else{
                  value = (bit<32>)hdr.ipv4.totalLen;
                } 
        }
    }; 

	apply{
		bit<16> dif = Feature_col_path.execute(idx);                    	

		if((dif[15:15]==1 || meta.path_l=8w255) && hdr.measure.tag==1){
			ig_dprsr_md.digest_type=1;
			meta.flowid=1; meta.mf=1; meta.evic=1;
			meta.md.add=1;  hdr.measure.tag=3; 
		}

		bit<32> key = Feature_col_hash.execute(idx);                    	
		meta.hval_c_=key;

		if(key==0 &&  hdr.measure.tag==1){
			ig_dprsr_md.digest_type=1;
			meta.flowid=1; hdr.measure.tag=3; meta.evic=0; meta.mf=0;
			meta.md.add=1; meta.md.flow_offset=meta.Hhindex;
		}
		else if(key == hval){
			hdr.measure.tag=3; meta.md.add=1;        		
			@stage(11){
				meta.md.flow_offset = Flow_offset.execute(idx);							
			}
		}
		else if(meta.evic==1){
			meta.idx = get_cur_off.execute(0);
			meta.md.flow_offset = reg_queue_read.execute(meta.idx);
			meta.prev_flow_offset = Flow_offset.execute(idx);							
		}

		if(meta.md.add==1){
			meta.cnt = pkt_cnt_increase.execute(idx);
			meta.bcnt = pkt_bcnt_increase.execute(idx);  
		}
	}

}
