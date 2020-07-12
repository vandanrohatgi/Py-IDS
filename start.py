from portScans import ScanDetector
from pingOfDeath import PingOfDeath
from scapy.sendrecv import sniff
import sys

print('Initializing...')

interface=input("Please enter the interface you want to run Py-IDS on:")

scanObj=ScanDetector()
podObj=PingOfDeath()

print('PY-IDS is online and looking for attacks')

def main(pkt):
    scanObj.oneForAll(pkt)
    podObj.podDetect(pkt)

#sniff the packets and send them to functions to detect the attacks
sniff(iface=interface,prn=main)