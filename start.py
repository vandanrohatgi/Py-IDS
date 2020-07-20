from portScans import ScanDetector
from pingOfDeath import PingOfDeath
from landattack import landAttack
from synflood import synFlood
from ddos import Ddos
from deauth import Deauth
#from IPspoof import spoofCheck
#from smurf import Smurf
from scapy.layers.inet import IP
from scapy.sendrecv import sniff
import sys

print('Initializing...')

# making dummy packet to get public IP address of host
# It is done this way to reduce the number of required libraries
dummyPkt = IP(dst='123.123.123.123')
myIP = str(dummyPkt[IP].src)

interface=input("Please enter the interface you want to run Py-IDS on:")

scanObj=ScanDetector(myIP)
podObj=PingOfDeath(myIP)
synobj=synFlood(myIP)
ddosobj=Ddos(myIP)
deauthobj=Deauth()
#smurfobj=Smurf(myIP)

print('PY-IDS is online and looking for attacks')

def main(pkt):
    scanObj.oneForAll(pkt)
    podObj.podDetect(pkt)
    landAttack(pkt,myIP)
    ddosobj.detectDdos(pkt)
    synobj.detectSyn(pkt)
    deauthobj.detectDeauth(pkt)
    #smurfobj.detectSmurf(pkt)
    #spoofCheck(pkt)

#sniff the packets and send them to functions to detect the attacks
sniff(iface=interface,prn=main)
