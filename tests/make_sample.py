#!/usr/bin/env python3
"""Generate a small, readable capture used to test PcapKit."""
import os

from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

CLI_MAC = "02:00:00:00:00:10"
SRV_MAC = "02:00:00:00:00:01"
GW_MAC = "02:00:00:00:00:01"
BCAST = "ff:ff:ff:ff:ff:ff"
CLI_IP = "192.168.1.10"
GW_IP = "192.168.1.1"
WEB_IP = "93.184.216.34"

pkts = []
t = 1700000000.0


def add(pkt):
    global t
    pkt.time = t
    t += 0.05
    pkts.append(pkt)


add(Ether(src=CLI_MAC, dst=BCAST) / ARP(op=1, hwsrc=CLI_MAC, psrc=CLI_IP, hwdst="00:00:00:00:00:00", pdst=GW_IP))
add(Ether(src=GW_MAC, dst=CLI_MAC) / ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=CLI_MAC, pdst=CLI_IP))

add(Ether(src=CLI_MAC, dst=GW_MAC) / IP(src=CLI_IP, dst=GW_IP) / UDP(sport=53000, dport=53)
    / DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
add(Ether(src=GW_MAC, dst=CLI_MAC) / IP(src=GW_IP, dst=CLI_IP) / UDP(sport=53, dport=53000)
    / DNS(id=0x1234, qr=1, aa=1, qd=DNSQR(qname="example.com", qtype="A"),
          an=DNSRR(rrname="example.com", type="A", ttl=300, rdata=WEB_IP)))

add(Ether(src=CLI_MAC, dst=SRV_MAC) / IP(src=CLI_IP, dst=WEB_IP) / TCP(sport=51000, dport=80, seq=1000, flags="S"))
add(Ether(src=SRV_MAC, dst=CLI_MAC) / IP(src=WEB_IP, dst=CLI_IP) / TCP(sport=80, dport=51000, seq=5000, ack=1001, flags="SA"))
add(Ether(src=CLI_MAC, dst=SRV_MAC) / IP(src=CLI_IP, dst=WEB_IP) / TCP(sport=51000, dport=80, seq=1001, ack=5001, flags="A"))

request = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: PcapKit-test\r\n"
           b"Accept: text/html\r\n\r\n")
add(Ether(src=CLI_MAC, dst=SRV_MAC) / IP(src=CLI_IP, dst=WEB_IP)
    / TCP(sport=51000, dport=80, seq=1001, ack=5001, flags="PA") / Raw(request))
response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n"
            b"Connection: close\r\n\r\nHello PcapKit")
add(Ether(src=SRV_MAC, dst=CLI_MAC) / IP(src=WEB_IP, dst=CLI_IP)
    / TCP(sport=80, dport=51000, seq=5001, ack=1001 + len(request), flags="PA") / Raw(response))

add(Ether(src=CLI_MAC, dst=GW_MAC) / IP(src=CLI_IP, dst="8.8.8.8") / ICMP(type=8, id=1, seq=1) / Raw(b"ping"))
add(Ether(src=GW_MAC, dst=CLI_MAC) / IP(src="8.8.8.8", dst=CLI_IP) / ICMP(type=0, id=1, seq=1) / Raw(b"ping"))

body = (bytes([1, 0, 0, 0x2B]) + bytes([3, 3]) + bytes(range(32)) + bytes([0])
        + bytes([0, 2, 0, 0x2F]) + bytes([1, 0]) + bytes([0, 0]))
hello = bytes([0x16, 0x03, 0x01]) + len(body).to_bytes(2, "big") + body
add(Ether(src=CLI_MAC, dst=SRV_MAC) / IP(src=CLI_IP, dst=WEB_IP)
    / TCP(sport=51001, dport=443, seq=2000, flags="PA") / Raw(hello))

add(Ether(src=CLI_MAC, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=bytes.fromhex(CLI_MAC.replace(":", "")) + b"\x00" * 10)
    / DHCP(options=[("message-type", "discover"), "end"]))

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.pcap")
wrpcap(out, pkts)
print(out)
