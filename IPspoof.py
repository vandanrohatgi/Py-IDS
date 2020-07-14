# This module didn't pass the testing phase due to en error in logic as follows:-
# To check if the packet has spoofed Ip address we try to ping the source of the packet and then compare the ttl of both the 
# packet(sent ping and the packet sniffed from network) , if they are not the same then alert; but the problem is when we send
#ping to source of packet we also receive a response which is then sniffed by our main program and then again passed to the function
# and hence it results in an endless loop of pings, their responses and sniffed packets. ANy help with this module is appreciated.



'''from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

WARNING = '\033[91m'
BOLD = '\033[1m'


def spoofCheck(pkt):
    # check for IP layer in packet
    if IP in pkt:
        # get the source of packet
        ip = pkt[IP].src
        if ip != None:
            print('received packet from ip:'+str(ip))
            # create a packet to ping the source of packet
            print('sending ping ')
            ping = IP(dst=ip)/ICMP()
            ans = sr1(ping, timeout=3,verbose=False)
            if ans!=None:
                print('ping sent')
                print(str(ans))
                print('ans ttl:'+str(ans[IP].ttl))
                print('pkt ttl:'+str(pkt[IP].ttl))
            # if ping doesnt get an answer or the ttl( time to live) don't match then alert
            if ping is None or ping[IP].ttl != pkt[IP].ttl:
                print(
                    f'{WARNING}{BOLD}Warning! someone is sending packets from a spoofed IP address')'''