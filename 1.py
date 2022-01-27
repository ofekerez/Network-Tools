from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP, TCP
from scapy.layers.l2 import Ether
from scapy.layers import smb
ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src='08-D4-0C-F0-B9-2C', type=0x800)
ip = IP(src='0.0.0.0', dst='172.19.230.42')
tcp = TCP(sport=21, dport=21)
bootp = BOOTP(ciaddr='0.0.0.0', xid=0x01020304, flags=1)
dhcp = DHCP(options=[("message-type", "discover"), "end"])
# smb = smb()
packet = ip / tcp / b"Hello"
send(packet)
