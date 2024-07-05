from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import os,time,json
import numpy as np
from scapy.all import sniff, sendp, get_if_list, get_if_hwaddr, bind_layers, send
from scapy.all import Packet, Ether, IP, UDP
from scapy.all import BitField
from Crypto.Random import get_random_bytes

CONST_0 = 0x736f6d6570736575
CONST_1 = 0x646f72616e646f6d
CONST_2 = 0x6c7967656e657261
CONST_3 = 0x7465646279746573
MASK32 = 0x00000000FFFFFFFF
class ProbePacket(Packet):
    name = "ProbePacket"
    fields_desc = [BitField("session_id",0,8), BitField("hash",0,64),BitField("egress_port",0,16),BitField("ttl",0,8)]

bind_layers(UDP,ProbePacket,dport=5555)

class NotificationPacket(Packet):
    name = "NotificationPacket"
    fields_desc = [BitField("session_id",0,8)]

bind_layers(UDP,ProbePacket,dport=5557)

class SipHash:

    def __init__(self):
        self.ig_md = {
            'sip_tmp': {
                'a_0': 0,
                'a_1': 0,
                'a_2': 0,
                'a_3': 0,
                'i_0': 0,
                'hval': 0
            }
        }
        self.hdr = {
            'sip_meta': {
                'v_0': 0,
                'v_1': 0,
                'v_2': 0,
                'v_3': 0,
                'curr_round':0
            },
            'sip': {
                'm_0': 0,
                'm_1': 0,
                'm_2': 0,
                'm_3': 0
            }
        }
        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.keys={}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.set_table_defaults()
        self.paths = {0:['s1','s2','s3','s5','s7'],1:['s1','s2','s3','s6','s7'],2:['s1','s2','s3','s4','s5','s7'],
            3:['s2','s3','s4','s5','s7'],4:['s2','s3','s6','s7'],5:['s2','s3','s5','s7'],
            6:['s4','s5','s7','s6'],7:['s4','s3','s6'],8:['s4','s5','s3','s6']}


    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def set_multicast(self,sw,controller):
        neighbors = list(self.topo.get_intfs()[sw].keys())
        port_number = len(neighbors)

        for i,ingress in enumerate(neighbors):
            group = i+1 #1 2 3 ..
            associate = neighbors[:i] + neighbors[i+1:]
            port_associate = [self.topo.get_intfs()[sw][n]['port'] for n in associate]
            ingress_port = self.topo.get_intfs()[sw][ingress]['port']
            rid =  i
            controller.mc_mgrp_create(group)
            controller.mc_node_create(rid,port_associate)
            controller.mc_node_associate(group,rid)

    def set_table_defaults(self):
        for sw,controller in self.controllers.items():
            controller.table_set_default("ipv4_lpm", "drop", [])
            controller.table_set_default("ecmp_group_to_nhop", "drop", [])
            controller.mirroring_add(100, self.topo.get_cpu_port_index(sw))
            self.set_multicast(sw,controller)

            key0 = int.from_bytes(get_random_bytes(7),'big')
            key1 = int.from_bytes(get_random_bytes(7),'big')

            self.keys[sw] = [key0,key1]
            controller.register_write("sip_key",0,key0)
            controller.register_write("sip_key",1,key1)

    def route(self):

        switch_ecmp_groups = {sw_name:{} for sw_name in self.topo.get_p4switches().keys()}

        for sw_name, controller in self.controllers.items():
            for sw_dst in self.topo.get_p4switches():

                #if its ourselves we create direct connections
                if sw_name == sw_dst:
                    for host in self.topo.get_hosts_connected_to(sw_name):
                        sw_port = self.topo.node_to_node_port_num(sw_name, host)
                        host_ip = self.topo.get_host_ip(host) + "/32"
                        host_mac = self.topo.get_host_mac(host)

                        #add rule
                        print("table_add at {}:".format(sw_name))
                        self.controllers[sw_name].table_add("ipv4_lpm", "set_nhop", [str(host_ip)], [str(host_mac), str(sw_port)])

                #check if there are directly connected hosts
                else:
                    if self.topo.get_hosts_connected_to(sw_dst):
                        paths = self.topo.get_shortest_paths_between_nodes(sw_name, sw_dst)
                        for host in self.topo.get_hosts_connected_to(sw_dst):

                            if len(paths) == 1:
                                next_hop = paths[0][1]

                                host_ip = self.topo.get_host_ip(host) + "/24"
                                sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                                dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)

                                #add rule
                                print("table_add at {}:".format(sw_name))
                                self.controllers[sw_name].table_add("ipv4_lpm", "set_nhop", [str(host_ip)],
                                                                    [str(dst_sw_mac), str(sw_port)])

                            elif len(paths) > 1:
                                next_hops = [x[1] for x in paths]
                                dst_macs_ports = [(self.topo.node_to_node_mac(next_hop, sw_name),
                                                   self.topo.node_to_node_port_num(sw_name, next_hop))
                                                  for next_hop in next_hops]
                                host_ip = self.topo.get_host_ip(host) + "/24"

                                #check if the ecmp group already exists. The ecmp group is defined by the number of next
                                #ports used, thus we can use dst_macs_ports as key
                                if switch_ecmp_groups[sw_name].get(tuple(dst_macs_ports), None):
                                    ecmp_group_id = switch_ecmp_groups[sw_name].get(tuple(dst_macs_ports), None)
                                    print("table_add at {}:".format(sw_name))
                                    self.controllers[sw_name].table_add("ipv4_lpm", "ecmp_group", [str(host_ip)],
                                                                        [str(ecmp_group_id), str(len(dst_macs_ports))])

                                #new ecmp group for this switch
                                else:
                                    new_ecmp_group_id = len(switch_ecmp_groups[sw_name]) + 1
                                    switch_ecmp_groups[sw_name][tuple(dst_macs_ports)] = new_ecmp_group_id

                                    #add group
                                    for i, (mac, port) in enumerate(dst_macs_ports):
                                        print("table_add at {}:".format(sw_name))
                                        self.controllers[sw_name].table_add("ecmp_group_to_nhop", "set_nhop",
                                                                            [str(new_ecmp_group_id), str(i)],
                                                                            [str(mac), str(port)])

                                    #add forwarding rule
                                    print("table_add at {}:".format(sw_name))
                                    self.controllers[sw_name].table_add("ipv4_lpm", "ecmp_group", [str(host_ip)],
                                                                        [str(new_ecmp_group_id), str(len(dst_macs_ports))])


    def pad(self,num,tot):
        num = bin(num)[2:]
        current_length = len(num)
        padding_length = tot - current_length
        if padding_length>0:
            padded_binary = '0' * padding_length + num
            return padded_binary
        return num

    def pre_end_nop(self):
        self.ig_md['sip_tmp']['i_0'] = 0

    def pre_end_m0_compression(self):
        self.ig_md['sip_tmp']['i_0'] = self.hdr['sip']['m_0']

    def pre_end_m1_compression(self):
        self.ig_md['sip_tmp']['i_0'] = self.hdr['sip']['m_1']

    def pre_end_m2_compression(self):
        self.ig_md['sip_tmp']['i_0'] = self.hdr['sip']['m_2']

    def pre_end_m3_compression(self):
        self.ig_md['sip_tmp']['i_0'] = self.hdr['sip']['m_3']

    def start_nop(self):
        self.ig_md['sip_tmp']['i_0'] = 0

    def start_finalization_first(self):

        self.ig_md['sip_tmp']['i_0'] = 0
        self.hdr['sip_meta']['v_2'] ^= 0x00000000000000ff

    def start_finalization_else(self):

        self.ig_md['sip_tmp']['i_0'] = 0

    def write_msgvar_m_0(self):
        self.ig_md['sip_tmp']['i_0'] = self.hdr['sip']['m_0']

    def write_msgvar_m_1(self):
        self.ig_md['sip_tmp']['i_0'] = self.hdr['sip']['m_1']

    def write_msgvar_m_2(self):
        self.ig_md['sip_tmp']['i_0'] = self.hdr['sip']['m_2']

    def write_msgvar_m_3(self):
        self.ig_md['sip_tmp']['i_0'] = self.hdr['sip']['m_3']

    def start_m0_compression(self):

        self.write_msgvar_m_0()

    def start_m1_compression(self):

        self.write_msgvar_m_1()

    def start_m2_compression(self):

        self.write_msgvar_m_2()

    def start_m3_compression(self):

        self.write_msgvar_m_3()

    def sip_init(self,sw):
        key_0 = self.keys[sw][0]
        key_1 = self.keys[sw][1]

        self.hdr['sip_meta']['v_0'] = CONST_0 ^ key_0
        self.hdr['sip_meta']['v_1'] = CONST_1 ^ key_1
        self.hdr['sip_meta']['v_2'] = CONST_2 ^ key_0
        self.hdr['sip_meta']['v_3'] = CONST_3 ^ key_1

    def sip_preround_1(self):

        lower = self.hdr['sip_meta']['v_3'] & MASK32
        lower= self.pad(lower,32)
        mask = ((1 << (64 - 32)) - 1) << 32
        upper = ((self.hdr['sip_meta']['v_3']&mask) >> 32) ^ ((self.ig_md['sip_tmp']['i_0'] & mask) >> 32)
        self.hdr['sip_meta']['v_3'] = int(bin(upper)[2:]+lower,2)

    def sip_preround_2(self):

        a = self.hdr['sip_meta']['v_3'] & MASK32
        b = self.ig_md['sip_tmp']['i_0'] & MASK32
        a = self.pad(a,32)
        b = self.pad(b,32)
        lower = int(a,2) ^ int(b,2)
        lower= self.pad(lower,32)
        upper = self.hdr['sip_meta']['v_3'] >> 32
        self.hdr['sip_meta']['v_3'] = int(bin(upper)[2:]+lower,2)

    def sip_1_a1(self):
        self.ig_md['sip_tmp']['a_0'] = int(bin(self.hdr['sip_meta']['v_0'] + self.hdr['sip_meta']['v_1'])[2:][-64:],2)
        self.ig_md['sip_tmp']['a_2'] = int(bin(self.hdr['sip_meta']['v_2'] + self.hdr['sip_meta']['v_3'])[2:][-64:],2)
        self.ig_md['sip_tmp']['a_1'] =self.hdr['sip_meta']['v_1']<<13

    def sip_1_a2(self):

        upper = self.ig_md['sip_tmp']['a_1'] >> 32
        mask = ((1 << (64 - 51)) - 1) << 51

        a = self.hdr['sip_meta']['v_1'] & 0x000000000007FFFF
        b = (self.hdr['sip_meta']['v_1']& mask ) >> 51
        b = self.pad(b,13)

        lower = int(bin(a)[2:] + b,2)
        lower = self.pad(lower,32)

        self.ig_md['sip_tmp']['a_1'] = int(bin(upper)[2:] + lower,2)

    def sip_1_b1(self):

        self.ig_md['sip_tmp']['a_3'] = self.hdr['sip_meta']['v_3']<<16

    def sip_1_b2(self):

        mask = ((1 << (64 - 48)) - 1) << 48
        b = (self.hdr['sip_meta']['v_3'] & mask) >> 48
        b = self.pad(b,16)

        a = self.hdr['sip_meta']['v_3'] & 0x000000000000FFFF
        all = int( bin(a)[2:] + b,2)
        add = self.pad(all,32)

        keep = self.ig_md['sip_tmp']['a_3'] >> 32
        self.ig_md['sip_tmp']['a_3'] = int( bin(keep)[2:] + add,2)


    def sip_2_a1(self):

        self.hdr['sip_meta']['v_1'] = self.ig_md['sip_tmp']['a_1'] ^ self.ig_md['sip_tmp']['a_0']
        self.hdr['sip_meta']['v_3'] = self.ig_md['sip_tmp']['a_3'] ^ self.ig_md['sip_tmp']['a_2']

        self.hdr['sip_meta']['v_0'] = self.ig_md['sip_tmp']['a_0']<<32
        self.hdr['sip_meta']['v_2'] = self.ig_md['sip_tmp']['a_2']

    def sip_2_a2(self):

        mask = ((1 << (64 - 32)) - 1) << 32
        a0 = (self.ig_md['sip_tmp']['a_0'] & mask) >> 32

        a0 = self.pad(a0,32)
        keep = self.hdr['sip_meta']['v_0'] >> 32
        self.hdr['sip_meta']['v_0'] = int(bin(keep)[2:] + a0,2)

    def sip_3_a1(self):

        self.ig_md['sip_tmp']['a_2'] = int(bin(self.hdr['sip_meta']['v_2'] + self.hdr['sip_meta']['v_1'])[2:][-64:],2)
        self.ig_md['sip_tmp']['a_0'] = int(bin(self.hdr['sip_meta']['v_0'] + self.hdr['sip_meta']['v_3'])[2:][-64:],2)

        mask = ((1 << (47 - 15)) - 1) << 15
        a0 = (self.hdr['sip_meta']['v_1'] & mask) >> 15

        keep = self.ig_md['sip_tmp']['a_1'] & MASK32
        keep = self.pad(keep,32)
        self.ig_md['sip_tmp']['a_1'] = int(bin(a0)[2:] + keep,2)

    def sip_3_a2(self):

        keep = self.ig_md['sip_tmp']['a_1'] >> 32
        a = self.hdr['sip_meta']['v_1'] & 0x0000000000007FFF
        mask_b =  ((1 << (64 - 47)) - 1) << 47
        b = (self.hdr['sip_meta']['v_1'] & mask_b) >> 47
        b = self.pad(b,17)
        add = int( bin(a)[2:] + b ,2)
        add = self.pad(add,32)
        self.ig_md['sip_tmp']['a_1'] = int(bin(keep)[2:]+add,2)

    def sip_3_b1(self):

        mask =  ((1 << (43 - 11)) - 1) << 11
        v3 = (self.hdr['sip_meta']['v_3'] & mask) >> 11
        keep = self.ig_md['sip_tmp']['a_3'] & MASK32
        keep = self.pad(keep,32)

        self.ig_md['sip_tmp']['a_3'] = int(bin(v3)[2:]+keep,2)

    def sip_3_b2(self):

        mask_a = ((1 << (64 - 43)) - 1) << 43
        a = (self.hdr['sip_meta']['v_3'] & mask_a) >> 43
        a = self.pad(a,21)

        b = self.hdr['sip_meta']['v_3'] & 0x00000000000007FF
        add = int(bin(b)[2:] + a,2)
        add = self.pad(add,32)

        keep = self.ig_md['sip_tmp']['a_3'] >> 32
        self.ig_md['sip_tmp']['a_3'] = int(bin(keep)[2:] + add ,2)

    def sip_4_a1(self):

        self.hdr['sip_meta']['v_1'] = self.ig_md['sip_tmp']['a_1'] ^ self.ig_md['sip_tmp']['a_2']
        self.hdr['sip_meta']['v_3'] = self.ig_md['sip_tmp']['a_3'] ^ self.ig_md['sip_tmp']['a_0']

        keep = self.hdr['sip_meta']['v_2'] & MASK32
        keep = self.pad(keep,32)
        add = self.ig_md['sip_tmp']['a_2'] & MASK32
        add = self.pad(add,32)

        self.hdr['sip_meta']['v_2'] = int(add+keep,2)

    def sip_4_a2(self):

        mask =  ((1 << (64 - 32)) - 1) << 32
        add = (self.ig_md['sip_tmp']['a_2'] & mask )>> 32
        add = self.pad(add,32)
        keep = self.hdr['sip_meta']['v_2'] >> 32
        self.hdr['sip_meta']['v_2'] = int(bin(keep)[2:] + add,2)

    def sip_postround_1(self):

        keep = self.hdr['sip_meta']['v_0'] & MASK32
        keep = self.pad(keep,32)

        b = self.ig_md['sip_tmp']['i_0']>>32
        a = self.ig_md['sip_tmp']['a_0']>>32
        add = a ^ b

        self.hdr['sip_meta']['v_0']  = int(bin(add)[2:]+keep,2)

    def sip_postround_2(self):

        keep = self.hdr['sip_meta']['v_0'] >> 32

        b = self.ig_md['sip_tmp']['i_0'] & MASK32
        a = self.ig_md['sip_tmp']['a_0'] & MASK32
        a = self.pad(a,32)
        b = self.pad(b,32)
        xor = int(a,2) ^ int(b,2)
        xor = self.pad(xor,32)

        self.hdr['sip_meta']['v_0'] = int(bin(keep)[2:]+xor,2)

    def sip_speculate_end_1(self):

        keep = self.ig_md['sip_tmp']['hval'] & MASK32
        keep = self.pad(keep,32)

        v0 = self.hdr['sip_meta']['v_0'] >> 32
        v1 = self.hdr['sip_meta']['v_1'] >> 32
        v2 = self.hdr['sip_meta']['v_2'] >> 32
        v3 = self.hdr['sip_meta']['v_3'] >> 32
        add = v0 ^ v1 ^ v2 ^ v3

        self.ig_md['sip_tmp']['hval'] = int(bin(add)[2:]+keep,2)

    def sip_speculate_end_2(self):

        keep = self.ig_md['sip_tmp']['hval'] >> 32

        v0 = self.hdr['sip_meta']['v_0'] & MASK32
        v1 = self.hdr['sip_meta']['v_1'] & MASK32
        v2 = self.hdr['sip_meta']['v_2'] & MASK32
        v3 = self.hdr['sip_meta']['v_3'] & MASK32
        add = v0 ^ v1 ^ v2 ^ v3
        add = self.pad(add,32)

        self.ig_md['sip_tmp']['hval'] = int(bin(keep)[2:]+add,2)

    def get_rnd_bit(self):
        self.ig_md['rnd_bit'] = standard_metadata['ingress_port'] % 2

    def tb_start_round(self):
        if self.hdr['sip_meta']['curr_round'] == 1:
            self.start_nop()
        if self.hdr['sip_meta']['curr_round'] == 2:
            self.start_m1_compression()
        if self.hdr['sip_meta']['curr_round'] == 3:
            self.start_nop()
        if self.hdr['sip_meta']['curr_round'] == 4:
            self.start_m2_compression()
        if self.hdr['sip_meta']['curr_round'] == 5:
            self.start_nop()
        if self.hdr['sip_meta']['curr_round'] == 6:
            self.start_m3_compression()
        if self.hdr['sip_meta']['curr_round'] == 7:
            self.start_nop()
        if self.hdr['sip_meta']['curr_round'] == 8:
            self.start_finalization_first()
        if self.hdr['sip_meta']['curr_round'] == 9:
            self.start_finalization_else()
        if self.hdr['sip_meta']['curr_round'] == 10:
            self.start_finalization_else()
        if self.hdr['sip_meta']['curr_round'] == 11:
            self.start_finalization_else()

    def tb_recirculate_decision(self):
        if hdr['sip_meta']['curr_round'] == 11:
            return hdr['sip_meta']

    def tb_pre_end(self):
    	if self.hdr['sip_meta']['curr_round'] == 1:
    		self.pre_end_m0_compression()
    	elif self.hdr['sip_meta']['curr_round'] == 3:
    		self.pre_end_m1_compression()
    	elif self.hdr['sip_meta']['curr_round'] == 5:
    		self.pre_end_m2_compression()
    	elif self.hdr['sip_meta']['curr_round'] == 7:
    		self.pre_end_m3_compression()
    	else:
    		self.pre_end_nop()

    def reset_hash(self):
        self.ig_md = {
            'sip_tmp': {
                'a_0': 0,
                'a_1': 0,
                'a_2': 0,
                'a_3': 0,
                'i_0': 0,
                'hval': 0
            }
        }
        self.hdr = {
            'sip_meta': {
                'v_0': 0,
                'v_1': 0,
                'v_2': 0,
                'v_3': 0,
                'curr_round':0
            },
            'sip': {
                'm_0': 0,
                'm_1': 0,
                'm_2': 0,
                'm_3': 0
            }
        }

    def compute(self,ttl,session_id,egress_port,hash,sw):

        self.reset_hash()
        while self.hdr['sip_meta']['curr_round']  <= 11:

            if self.hdr['sip_meta']['curr_round']  == 0:

                self.hdr['sip']['m_0'] = int(bin(ttl)[2:] + self.pad(egress_port,16) + self.pad(session_id,8),2)
                self.hdr['sip']['m_1'] = hash
                self.hdr['sip']['m_2'] = 0
                self.hdr['sip']['m_3'] = 0
                self.sip_init(sw)
                self.start_m0_compression()

            else:
                self.tb_start_round()

            self.sip_preround_1()
            self.sip_preround_2()
            # SipRound
            self.sip_1_a1()
            self.sip_1_a2()
            self.sip_1_b1()
            self.sip_1_b2()
            self.sip_2_a1()
            self.sip_2_a2()

            self.sip_3_a1()
            self.sip_3_a2()
            self.sip_3_b1()
            self.sip_3_b2()

            self.sip_4_a1()
            self.sip_4_a2()

            self.tb_pre_end()

            self.sip_postround_1()
            self.sip_postround_2()

            self.sip_speculate_end_1()
            self.sip_speculate_end_2()

            self.hdr['sip_meta']['curr_round']  += 1

        return self.ig_md['sip_tmp']['hval']

    def set_paths_mac(self,ttl,session,egress_last):
        macs = {}

        for p,path in enumerate(self.paths.values()):
            hash = 0
            path_ttl = ttl
            for h,hop in enumerate(path):

                if h >= len(path)-1:
                    output_port = egress_last
                else:
                    next_hop = path[h+1]
                    output_port = self.topo.node_to_node_port_num(hop,next_hop)

                new_hash = self.compute(path_ttl,session,output_port,hash,hop)
                path_ttl = path_ttl-1
                hash = new_hash

            macs[p] = hash
        return macs


    def handle_pkt(self,pkt,iface):

        flag = 0
        sw = iface.split('-')[0]
        if ProbePacket in pkt and (sw == 's7'):
            t0 = time.time()

            ttl = pkt[ProbePacket].ttl
            session = pkt[ProbePacket].session_id
            hash = pkt[ProbePacket].hash
            egress = pkt[ProbePacket].egress_port


            paths_macs = self.set_paths_mac(ttl,session,egress)
            for k,v in paths_macs.items():
                if hash == v:
                    print('Verified path',self.paths[k])
                    print("Single path verification time",time.time()-t0)
                    print("Timestamp",time.time())
                    flag = 1
            if flag != 1:
                print("Attack detected")

    def main(self):

        self.route()
        time.sleep(.5)

        iface = self.topo.get_cpu_port_intf('s7')
        print("Sending notification on interface %s" % (iface))
        pkt = Ether(src=get_if_hwaddr(iface),dst = "ff:ff:ff:ff:ff:ff",type=0x0800)/IP(ttl=0)/UDP(sport=1234,dport=5557)/NotificationPacket(session_id = 5)
        sendp(pkt, iface=iface, verbose=False)

        ifaces = []
        for sw in self.controllers.keys():
            ifaces.append(self.topo.get_cpu_port_intf(sw))

        sniff(iface = ifaces,
              prn = lambda x: self.handle_pkt(x,x.sniffed_on))


if __name__ == "__main__":

    controller = SipHash().main()
