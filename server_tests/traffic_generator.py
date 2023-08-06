from scapy.all import *


def send_test_packets(target_ip):
    packet = IP(src='', dst=target_ip) / TCP(dport=123, flags='F')
    send(packet, count=10000)


target_ip = ''

send_test_packets(target_ip)
