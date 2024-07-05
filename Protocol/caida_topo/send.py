#!/usr/bin/env python3
import argparse
import sys,time
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, BitField, bind_layers, StrField,sniff
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

class ProbePacket(Packet):
    name = "ProbePacket"
    fields_desc = [BitField("session_id",0,8), BitField("hash",0,64),BitField("egress_port",0,16),BitField("ttl",0,8)]

bind_layers(UDP,ProbePacket,dport=5555)

#
# class Sip(Packet):
#     name = "Sip"
#     fields_desc = [BitField("sessionId",0x0,8),BitField("m_0",0x0,64), BitField("m_1",0x0,64), BitField("m_2",0x0,64), BitField("m_3",0x0,64)]
# bind_layers(UDP,Sip,dport=5555)


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <destination>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt = Ether(src=get_if_hwaddr(iface),dst = "ff:ff:ff:ff:ff:ff",type=0x0800)/IP(dst=addr,ttl=7)/UDP(sport=1234,dport=5555)/ProbePacket(session_id = 5)
    pkt1 = Ether(src=get_if_hwaddr(iface),dst = "ff:ff:ff:ff:ff:ff",type=0x0800)/IP(dst=addr,ttl=7)/UDP(sport=1234)

    for _ in range(50):
        sendp(pkt1, iface=iface, verbose=False)
    print("Timestamp",time.time())
    sendp(pkt, iface=iface, verbose=False)
    for _ in range(50):
        sendp(pkt1, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
