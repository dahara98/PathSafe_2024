#define SIP_PORT 5555
const bit<64> const_0 = 0x736f6d6570736575;
const bit<64> const_1 = 0x646f72616e646f6d;
const bit<64> const_2 = 0x6c7967656e657261;
const bit<64> const_3 = 0x7465646279746573;

#define ROUND_TYPE_COMPRESSION 0
#define ROUND_TYPE_FINALIZATION 1
#define ROUND_TYPE_END 2

#include <core.p4>
#include <v1model.p4>

typedef bit<9> egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header sip_inout_h {
    bit<8> session_id;
    bit<64> hash;
    bit<16> egress_port;
    bit<8> ttl;
}

header notification_h {
    bit<8> session_id;
}

header sip_meta_h {
    bit<64> m_0;
    bit<64> m_1;
    bit<64> m_2;
    bit<64> m_3;
    bit<64> v_0;
    bit<64> v_1;
    bit<64> v_2;
    bit<64> v_3;
    bit<16> dest_port;
    bit<8> curr_round;
}

struct header_t {
    ethernet_h ethernet;
    sip_inout_h probe;
    sip_meta_h sip_meta;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    notification_h notification;
}

header sip_tmp_h {
    bit<64> a_0;
    bit<64> a_1;
    bit<64> a_2;
    bit<64> a_3;
    bit<64> i_0;
    bit<64> hval;
    bit<8> round_type;
}

struct ig_metadata_t {

    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;
    bool recirc;
    bit<16> rnd_port_for_recirc;
    bit<1> rnd_bit;
    sip_tmp_h sip_tmp;
    @field_list(1)
    bit<16> in_port;
}

parser MyParser(
        packet_in pkt,
        out header_t hdr,
        inout ig_metadata_t ig_md,
        inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_sip {
        pkt.extract(hdr.probe);
        transition accept;
    }

    state parse_notif {
        pkt.extract(hdr.notification);
        transition accept;
    }

    state parse_sip_and_meta {
        pkt.extract(hdr.probe);
        pkt.extract(hdr.sip_meta);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            SIP_PORT: parse_sip;
            SIP_PORT+1: parse_sip_and_meta;
            SIP_PORT+2: parse_notif;
            default: accept;
        }
    }
}


control MyDeparser(
        packet_out pkt,
        in header_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.probe);
        pkt.emit(hdr.sip_meta);
    }
}


control MyIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        inout standard_metadata_t standard_metadata) {

				action drop() {
		        mark_to_drop(standard_metadata);
		    }

        action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
              hash(ig_md.ecmp_hash,
            HashAlgorithm.crc16,
            (bit<1>)0,
            { hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.ipv4.protocol},
            num_nhops);

            ig_md.ecmp_group_id = ecmp_group_id;
          }

        action set_nhop(mac_addr_t dst_addr, egress_spec_t port) {

              hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
              hdr.ethernet.dst_addr = dst_addr;
              standard_metadata.egress_spec = port;
              hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
          }

        table ecmp_group_to_nhop {
              key = {
                  ig_md.ecmp_group_id:    exact;
                  ig_md.ecmp_hash: exact;
              }
              actions = {
                  drop;
                  set_nhop;
              }
              size = 1024;
          }

        table ipv4_lpm {
              key = {
                  hdr.ipv4.dst_addr: lpm;
              }
              actions = {
                  set_nhop;
                  ecmp_group;
                  drop;
              }
              size = 1024;
              default_action = drop;
          }

        register<bit<1>>(1) notification_register;

		    apply {
            if (standard_metadata.instance_type == 0) {
              switch (ipv4_lpm.apply().action_run){
                ecmp_group: {
                  ecmp_group_to_nhop.apply();
                }
              }
            }


            if (hdr.ipv4.ttl > 0) {

              if (hdr.probe.isValid() && !hdr.sip_meta.isValid()) {

                ig_md.in_port = (bit<16>) standard_metadata.ingress_port;

                if (hdr.probe.ttl == 0) {
                  hdr.probe.ttl = hdr.ipv4.ttl+1;
                }

                bit<1> tmp;
                notification_register.read(tmp,0);
                if (tmp == 0){
                  standard_metadata.mcast_grp = ig_md.in_port;
                }

              } else {

                if (hdr.sip_meta.curr_round == 11) {

                  standard_metadata.egress_spec = (bit<9>) hdr.probe.egress_port;

                }
              }

            } else {
              if (hdr.notification.isValid()) {
                notification_register.write(0,1);
              }
            }


		    }
}

control MyEgress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        inout standard_metadata_t standard_metadata) {

        register<bit<64>>(2) sip_key;
        bit<64> sip_key_0;
        bit<64> sip_key_1;

        action drop() {
		        mark_to_drop(standard_metadata);
		    }
        action nop() {
		    }

        action write_msgvar_m_0() {
            ig_md.sip_tmp.i_0 = hdr.sip_meta.m_0;
        }
        action write_msgvar_m_1() {
            ig_md.sip_tmp.i_0 = hdr.sip_meta.m_1;
        }
        action write_msgvar_m_2() {
            ig_md.sip_tmp.i_0 = hdr.sip_meta.m_2;
        }
        action write_msgvar_m_3() {
            ig_md.sip_tmp.i_0 = hdr.sip_meta.m_3;
        }

		    action get_rnd_bit() {
		        ig_md.rnd_bit = (bit<1>) (standard_metadata.ingress_port % 2); // simple pseudo-random
		    }


		    action do_not_recirc() {

		        hdr.udp.dst_port = SIP_PORT;
		        hdr.sip_meta.m_0 = 0;
		        hdr.sip_meta.m_1 = 0;
		        hdr.sip_meta.m_2 = 0;
		        hdr.sip_meta.m_3 = 0;

		        ig_md.sip_tmp.round_type = ROUND_TYPE_END;
		        hdr.probe.hash = ig_md.sip_tmp.hval;
		        hdr.sip_meta.setInvalid();
            clone(CloneType.E2E,100);
		    }

        action start_m0_compression(){
            ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;
		        write_msgvar_m_0();
        }
        action start_m1_compression(){
            ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;
            write_msgvar_m_1();
        }
        action start_m2_compression(){
            ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;
            write_msgvar_m_2();
        }
        action start_m3_compression(){
            ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;
            write_msgvar_m_3();
        }

        action sip_init() {

            sip_key.read(sip_key_0,0);
            sip_key.read(sip_key_1,1);
            log_msg("key0 {}",{sip_key_0});
            log_msg("key1 {}",{sip_key_1});
		        hdr.sip_meta.v_0 = const_0 ^ sip_key_0;
		        hdr.sip_meta.v_1 = const_1 ^ sip_key_1;
		        hdr.sip_meta.v_2 = const_2 ^ sip_key_0;
		        hdr.sip_meta.v_3 = const_3 ^ sip_key_1;

		    }

        action sip_preround_1(){
        		hdr.sip_meta.v_3[63:32] = hdr.sip_meta.v_3[63:32] ^ ig_md.sip_tmp.i_0[63:32];

      	}
      	action sip_preround_2(){
      		  hdr.sip_meta.v_3[31:0] = hdr.sip_meta.v_3[31:0] ^ ig_md.sip_tmp.i_0[31:0];
      	}

      	action sip_1_a1(){
      		//a_0 = i_0 + i_1
      		ig_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
      		//a_2 = i_2 + i_3
      		ig_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
      		//a_1 = i_1 << 13
      		ig_md.sip_tmp.a_1[63:32] = hdr.sip_meta.v_1[50:19];
      	}
      	action sip_1_a2(){
      	  ig_md.sip_tmp.a_1[31:0] = hdr.sip_meta.v_1[18:0] ++ hdr.sip_meta.v_1[63:51];
      	}
      	action sip_1_b1(){

      		//a_3 = i_3 << 16
      		ig_md.sip_tmp.a_3 = hdr.sip_meta.v_3[47:0] ++ hdr.sip_meta.v_3[63:48];
      		ig_md.sip_tmp.a_3[63:32]=hdr.sip_meta.v_3[47:16];
      	}
      	action sip_1_b2(){
      		ig_md.sip_tmp.a_3[31: 0]=hdr.sip_meta.v_3[15:0] ++ hdr.sip_meta.v_3[63:48];
      	}

      	action sip_2_a1(){
      		hdr.sip_meta.v_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_0;
      		hdr.sip_meta.v_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_2;
      		hdr.sip_meta.v_0[63:32] = ig_md.sip_tmp.a_0[31:0];
      		hdr.sip_meta.v_2 = ig_md.sip_tmp.a_2;
      	}
      	action sip_2_a2(){
      		hdr.sip_meta.v_0[31:0] = ig_md.sip_tmp.a_0[63:32];
      	}

      	action sip_3_a1(){
      		//c_2 = b_2 + b_1
      		ig_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_1;
      		//c_0 = b_0 + b_3
      		ig_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_3;
      		//c_1 = b_1 << 17
      		ig_md.sip_tmp.a_1[63:32] = hdr.sip_meta.v_1[46:15];
      	}
      	action sip_3_a2(){
      		ig_md.sip_tmp.a_1[31:0] = hdr.sip_meta.v_1[14:0] ++ hdr.sip_meta.v_1[63:47];
      	}

      	action sip_3_b1(){
      		//c_3 = b_3 << 21
      		ig_md.sip_tmp.a_3[63:32] = hdr.sip_meta.v_3[42:11];
      	}
      	action sip_3_b2(){
      		ig_md.sip_tmp.a_3[31:0] = hdr.sip_meta.v_3[10:0] ++ hdr.sip_meta.v_3[63:43];
      	}


      	action sip_4_a1(){
      		//d_1 = c_1 ^ c_2
      		hdr.sip_meta.v_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_2;
      		//d_3 = c_3 ^ c_0 i
      		hdr.sip_meta.v_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_0;
      		//d_2 = c_2 << 32
      		hdr.sip_meta.v_2[63:32]=ig_md.sip_tmp.a_2[31:0];
      	}
      	action sip_4_a2(){
      		hdr.sip_meta.v_2[31:0]=ig_md.sip_tmp.a_2[63:32];
      	}

      	action sip_postround_1(){
      		hdr.sip_meta.v_0[63:32] = ig_md.sip_tmp.a_0[63:32] ^ ig_md.sip_tmp.i_0[63:32];
      	}
      	action sip_postround_2(){
      		hdr.sip_meta.v_0[31:0] = ig_md.sip_tmp.a_0[31:0] ^ ig_md.sip_tmp.i_0[31:0];
      	}

      	action sip_speculate_end_1(){
      			ig_md.sip_tmp.hval[63:32] = hdr.sip_meta.v_0[63:32] ^  hdr.sip_meta.v_1[63:32]^  hdr.sip_meta.v_2[63:32]^  hdr.sip_meta.v_3[63:32];
      	}
      	action sip_speculate_end_2(){
      			ig_md.sip_tmp.hval[31:0] = hdr.sip_meta.v_0[31:0] ^ hdr.sip_meta.v_1[31:0] ^ hdr.sip_meta.v_2[31:0] ^ hdr.sip_meta.v_3[31:0];
      	}


        action start_nop(){
      		ig_md.sip_tmp.i_0=0;
      	}

      	//round 2*NUM_WORDS (first finalization round)

      	action start_finalization_first(){
      		ig_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
      		ig_md.sip_tmp.i_0 = 0;
      		// also xor v2 with FF at beginning of the first finalization pass
      		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 64w0xff;
      	}

      	//round 2*NUM_WORDS +1 ~ +3 (last 3 finalization rounds)
      	action start_finalization_else(){
      		ig_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
      		ig_md.sip_tmp.i_0 = 0;
      	}

        action pre_end_nop(){
            ig_md.sip_tmp.i_0 = 0;
        }
        action pre_end_m_0_compression(){
            ig_md.sip_tmp.i_0 = hdr.sip_meta.m_0;
        }

        action pre_end_m_1_compression(){
            ig_md.sip_tmp.i_0 = hdr.sip_meta.m_1;
        }

        action pre_end_m_2_compression(){
            ig_md.sip_tmp.i_0 = hdr.sip_meta.m_2;
        }

        action pre_end_m_3_compression(){
            ig_md.sip_tmp.i_0 = hdr.sip_meta.m_3;
        }

        table tb_hashing_init {
		        key = {
		            hdr.udp.dst_port: exact;
		        }
		        actions = {
		            sip_init;
		            nop;
		        }
		        default_action = nop;
		        const entries = {
		            SIP_PORT: sip_init();
		        }

		    }



				apply {

          if (standard_metadata.instance_type != 2){ // no cloned yet
              if (!hdr.probe.isValid() || hdr.ipv4.ttl < 1) {

                  drop();
                  exit;

              }

              hdr.sip_meta.setValid();
              hdr.probe.egress_port = (bit<16>) standard_metadata.egress_port;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.curr_round = 0;
              tb_hashing_init.apply();
              start_m0_compression();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

              pre_end_nop();

              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8> )1;

              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_nop();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

              pre_end_m_0_compression();

              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8>) 2;

              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_m1_compression();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

              pre_end_nop();

              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8>) 3;
              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_nop();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();


        		  pre_end_m_1_compression();

              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8> )4;
              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_m2_compression();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

        			pre_end_nop();

              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8>) 5;
              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_nop();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();


        			pre_end_m_2_compression();


              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8>) 6;
              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_m3_compression();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

              pre_end_nop();

              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8>) 7;
              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_nop();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

              pre_end_m_3_compression();

              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8>) 8;
              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});

              start_finalization_first();


              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

              pre_end_nop();

              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8>) 9;
              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_finalization_else();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

              pre_end_nop();

              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8>) 10;
              // transition
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_finalization_else();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

              pre_end_nop();
              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();
              //tb_recirc_decision.apply();
              hdr.sip_meta.curr_round = (bit<8>) 11;

              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;
              hdr.sip_meta.m_0 = (bit<64>) (hdr.ipv4.ttl+1 ++ hdr.probe.egress_port ++ hdr.probe.session_id);
              hdr.sip_meta.m_1 = hdr.probe.hash;
              log_msg("m0 {}",{hdr.sip_meta.m_0});
              start_finalization_else();

              sip_preround_1();
              sip_preround_2();

              sip_1_a1();
              sip_1_a2();
              sip_1_b1();
              sip_1_b2();
              sip_2_a1();
              sip_2_a2();

              sip_3_a1();
              sip_3_a2();
              sip_3_b1();
              sip_3_b2();

              sip_4_a1();
              sip_4_a2();

              pre_end_nop();
              sip_postround_1();
              sip_postround_2();

              sip_speculate_end_1();
              sip_speculate_end_2();

              hdr.udp.dst_port = SIP_PORT;
              hdr.sip_meta.m_0 = 0;
              hdr.sip_meta.m_1 = 0;
              hdr.sip_meta.m_2 = 0;
              hdr.sip_meta.m_3 = 0;

              ig_md.sip_tmp.round_type = ROUND_TYPE_END;
              hdr.probe.hash = ig_md.sip_tmp.hval;
              hdr.sip_meta.setInvalid();
              clone(CloneType.E2E,100);

              //if (hdr.udp.dst_port == SIP_PORT + 1){
              //  recirculate_preserving_field_list(1);
              //}
          }

				}

}

control MyVerifyChecksum(inout header_t hdr, inout ig_metadata_t meta) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout header_t hdr, inout ig_metadata_t meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr },
              hdr.ipv4.hdr_checksum,
              HashAlgorithm.csum16);
    }
}

V1Switch(
				MyParser(),
				MyVerifyChecksum(),
				MyIngress(),
				MyEgress(),
				MyComputeChecksum(),
				MyDeparser()
) main;
