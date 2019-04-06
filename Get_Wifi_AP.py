#!/usr/bin/env python

import scapy.all as scapy

Pkt_Info = """
---------------[ Packet Captured ]-----------------------
 Subtype  : {}
 Address 1  : {}
 Address 2 : {} [BSSID]
 Address 3  : {}
 AP  : {} [SSID]

"""
ap_list = []
def PacketHandler(pkt):

    if pkt.haslayer(scapy.Dot11) and pkt.subtype == 2:
        if pkt.addr2 not in ap_list:
            ap_list.append(pkt.addr2)
            print Pkt_Info.format(pkt.subtype,pkt.addr1, pkt.addr2, pkt.addr3, pkt.info)
