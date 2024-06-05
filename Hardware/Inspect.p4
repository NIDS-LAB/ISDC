#include "types.p4"
#include "headers.p4"


control INspect(inout headers hdr, in bit<32> hval, in bit<32> idx, 
		inout metadata meta, inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md){

    Register<ins_pair_t, bit<32>>(MLIST_SIZE) Mhash_register;
    Register<bit<8>, bit<32>>(MLIST_SIZE)  Mpacket_cnt_;

    MathUnit<bit<32>>(MathOp_t.MUL, 4, 3) div;

    RegisterAction<bit<8>, bit<32>, bit<8>>(Mpacket_cnt_) GR_tot_increase = {
        void apply (inout bit<8> value, out bit<8> result) {            
            if(value == 8w255){
            	value = 8w1;
            }
            else{
            	value = value + 8w1;                        	
            }
            result = value;
        }
    };

    RegisterAction<ins_pair_t, bit<32>, bit<32>>(Mhash_register) Inspect_reset = {
        void apply (inout ins_pair_t value, out bit<32> result) {           
	    result = value.key;
	    value.cnt = 32w1;
	    value.key = hval;

	}
   };

    RegisterAction<ins_pair_t, bit<32>, bit<32>>(Mhash_register) Inspect = {
        void apply (inout ins_pair_t value, out bit<32> result) {           
	    result = value.key;
	    if(meta.cnt == value.cnt){
		value.key = hval;
		value.cnt = div.execute(meta.cnt); 
	    }
	    else{
		if(value.key == hval){
	    		value.cnt = value.cnt + 32w1;
		}
		else{
			result = 32w0; // new flow
		}
	    }
  }
  };

  action reset_ins(){
        meta.hval_c_ = Inspect_reset.execute(idx);            
  }
  action ins(){
	meta.cnt=((bit<32>)meta.mcnt>>2); 
        meta.hval_reg = Inspect.execute(idx);            
  }
   table FlowInspect {
        key = {
            meta.mcnt: exact;
        }
        actions = {
            reset_ins;
	    ins;
            @defaultonly NoAction;
        }
	size = 2;
	const entries={
	(8w1) : reset_ins();
	(_) : ins();
	}
        default_action = NoAction;
    }

	apply{
		meta.hval_reg = 32w1;
            	meta.mcnt = GR_tot_increase.execute(idx);

		FlowInspect.apply();

		if(hval == meta.hval_reg){
			hdr.measure.tag = 1; 
		}
		else if(meta.hval_reg == 0){
			hdr.measure.tag = 2; 
		}
		else{
			hdr.measure.tag = 0; 
			meta.next_stage = 0;
			ig_dprsr_md.digest_type=1;
			meta.flowid = 1;                
		}
	}

}
