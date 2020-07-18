import time
from scapy.sendrecv import sniff
from scapy.layers.inet import IP, TCP, UDP

#class for all types of scans
class ScanDetector:
    def __init__(self,hostIP):
        #dictionaries for storing count of packets received from different ip addresses
        self.myIP=hostIP
        self.syn = {}
        self.xmas = {}
        self.ack = {}
        self.udp = {}
        self.fin = {}
        self.null = {}
        #threshold - Amount of packets per second to cross after which the alert is given out
        self.threshold = 2000
        #bool to store if this type of scan is already detected and if it is then it is not checked for again
        self.synAttacked = False
        self.nullAttcked = False
        self.finAttacked = False
        self.xmasAttacked = False
        self.ackAttacked = False
        self.udpAttacked = False
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    #function to call all other functions
    def oneForAll(self, pkt=None):
        if pkt != None:
            # check for IP layer in packet
            if IP in pkt:
                ip = pkt[IP].src
                if ip != None and ip!=self.myIP:
                    # check for TCP layer in packet
                    if TCP in pkt:
                        # flag type will decide the type of scan to detect
                        flag = pkt[TCP].flags

                        # if flag is none check for null scan and so on...
                        if flag == None:
                            self.nullScan(pkt, ip)
                        elif str(flag) == 'F':
                            self.finScan(pkt, ip)
                        elif str(flag) == 'S':
                            self.synScan(pkt, ip)
                        elif str(flag) == 'A':
                            self.ackScan(pkt, ip)
                        elif str(flag) == 'FPU':
                            self.xmasScan(pkt, ip)
                    # check for UDP layer in packet
                    elif UDP in pkt:
                        self.udpScan(pkt, ip)
                        

    # function to check if threshold has been crossed
    def detect(self, ip, type):
        # get current time
        now = time.time()
        # get the time first packet was received
        start = type[ip]['time']
        # get the total number of packets received
        count = type[ip]['count']
        # check if packets per second is greater than the threshold
        if (count/(now-start)) > self.threshold:
            return True

    #function to detect syn scan
    def synScan(self, pkt=None, ip=None):
        # check if this type of scan is already detected
        if not self.synAttacked:
            # make a new entry in dictionary if this IP address is seen for first time
            if ip not in self.syn.keys():
                self.syn[ip] = {'time': time.time(), 'count': 1}
            # else just increase the count of packets in already existing entry
            else:
                self.syn[ip]['count'] = self.syn[ip]['count']+1
            # loop through all IP addresses in dictionary to detect an attack
            for ip in self.syn.keys():
                if self.detect(ip, self.syn):
                    print(f"{self.WARNING}{self.BOLD}Warning! you may be under a syn scan from IP:"+ip)
                    self.synAttacked = True
                    break
    
    # function to check for christmas scan
    def xmasScan(self, pkt=None, ip=None):
        if not self.xmasAttacked:
            if ip not in self.xmas.keys():
                self.xmas[ip] = {'time': time.time(), 'count': 1}
            else:
                self.xmas[ip]['count'] = self.xmas[ip]['count']+1
            for ip in self.xmas.keys():
                if self.detect(ip, self.xmas):
                    print(f"{self.WARNING}{self.BOLD}Warning! you may be under a xmas scan from IP:"+ip)
                    self.xmasAttacked = True
                    break
    
    # function to check for ack/ window scan
    def ackScan(self, pkt=None, ip=None):
        if not self.ackAttacked:
            if ip not in self.ack.keys():
                self.ack[ip] = {'time': time.time(), 'count': 1}
            else:
                self.ack[ip]['count'] = self.ack[ip]['count']+1
            for ip in self.ack.keys():
                if self.detect(ip, self.ack):
                    print(
                        f"{self.WARNING}{self.BOLD}Warning! you may be under a ack / window scan from IP:"+ip)
                    self.ackAttacked = True
                    break
    
    # function to check for udp scan
    def udpScan(self, pkt=None, ip=None):
        if not self.udpAttacked:
            if ip not in self.udp:
                self.udp[ip] = {'time': time.time(), 'count': 1}
            else:
                self.udp[ip]['count'] = self.udp[ip]['count']+1
            for ip in self.udp.keys():
                if self.detect(ip, self.udp):
                    print(f"{self.WARNING}{self.BOLD}Warning! you may be under a udp scan from IP:"+ip)
                    self.udpAttacked = True
                    break
    
    # function to check for fin scan
    def finScan(self, pkt=None, ip=None):
        if not self.finAttacked:
            if ip not in self.fin.keys():
                self.fin[ip] = {'time': time.time(), 'count': 1}
            else:
                self.fin[ip]['count'] = self.fin[ip]['count']+1
            for ip in self.fin.keys():
                if self.detect(ip, self.fin):
                    print(f"{self.WARNING}{self.BOLD}Warning! you may be under a fin scan from IP:"+ip)
                    self.finAttacked = True
                    break

    # function to check for null scan
    def nullScan(self, pkt=None, ip=None):
        if not self.nullAttacked:
            if ip not in self.null.keys():
                self.null[ip] = {'time': time.time(), 'count': 1}
            else:
                self.null[ip]['count'] = self.null[ip]['count']+1
            for ip in self.null.keys():
                if self.detect(ip, self.null):
                    print(f"{self.WARNING}{self.BOLD}Warning! you may be under a null scan from IP:"+ip)
                    self.nullAttacked = True
                    break
