# this module is not tested and hence not included when running the Py-IDS


from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether


class Smurf:
    def __init__(self):
        # making dummy packet to get public IP address of host
        # It is done this way to reduce the number of required libraries
        dummyPkt = IP(dst='192.168.43.111')
        self.myIP = dummyPkt[IP].src
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def detectSmurf(self, pkt):
        if pkt != None:
            # check if receive packet is a ping packet
            if ICMP in pkt:
                if IP in pkt:
                    ipsrc = pkt[IP].src
                    ipdst = pkt[IP].dst
                    if ipsrc != None and ipdst != None:

                        # if the source IP of packet is same as host IP and it is sent to broadcast IP then alert
                        if str(ipdst)[-3:] == '255' and str(ipsrc) == str(self.myIP):
                            print(
                                f'{self.WARNING}{self.BOLD}Warning! you may be under a smurf attack')
                elif Ether in pkt:
                    dstMac = pkt[Ether].dst
                    ipsrc = pkt[IP].src
                    if dstMac != None and ipsrc != None:
                        # if the source IP is same as host IP and the destination mac address is broadcast mac address then alert
                        if str(dstMac) == 'ff:ff:ff:ff:ff:ff' and str(ipsrc) == str(self.myIP):
                            print(
                                f'{self.WARNING}{self.BOLD}Warning! you may be under a smurf attack')
