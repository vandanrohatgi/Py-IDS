from portScans import ScanDetector
from scapy.sendrecv import sniff
import sys

interface=input("Please enter the interface you want to run Py-IDS on:")
print('Initializing...')

scanObj=ScanDetector()

print('PY-IDS is online and looking for attacks')

try:
    # sniff the packets and send them to function oneForAll
    sniff(iface=interface,prn=scanObj.oneForAll)
except:
    print('An error occured. Exiting...')
    sys.exit()