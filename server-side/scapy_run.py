from scapy.all import *
import sys
import email_sender
import json


def process_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    sport = packet.sport
    dport = packet.dport
    size = len(packet)

    if proto == 6:
        proto_str = 'tcp'
    elif proto == 17:
        proto_str = 'udp'
    else:
        proto_str = 'other'

    if src_ip not in stats:
        stats[src_ip] = {}
    if dst_ip not in stats[src_ip]:
        stats[src_ip][dst_ip] = {'count': 0, 'size': 0, 'tcp': [], 'udp': [], 'icmp': [], 'other': []}

    stats[src_ip][dst_ip]['count'] += 1
    stats[src_ip][dst_ip]['size'] += size
    stats[src_ip][dst_ip][proto_str].append(dport)

    if src_ip not in stats_by_port:
        stats_by_port[src_ip] = {}
    if dst_ip not in stats_by_port:
        stats_by_port[dst_ip] = {}
    if sport not in stats_by_port[src_ip]:
        stats_by_port[src_ip][sport] = {'count': 0, 'size': 0}
    if dport not in stats_by_port[dst_ip]:
        stats_by_port[dst_ip][dport] = {'count': 0, 'size': 0}

    stats_by_port[src_ip][sport]['count'] += 1
    stats_by_port[src_ip][sport]['size'] += size
    stats_by_port[dst_ip][dport]['count'] += 1
    stats_by_port[dst_ip][dport]['size'] += size

    stats_by_port[src_ip][sport]['proto_str'] = proto_str
    stats_by_port[dst_ip][dport]['proto_str'] = proto_str


print("argv" + str(sys.argv[1]))
path_to_dump = str(sys.argv[1])
packets = rdpcap(path_to_dump)

stats = {}
stats_by_port = {}

for packet in packets:
    if IP in packet:
        process_packet(packet)

print(f"\n{'Source IP':<15} {'proto':<10} {'Port':<10} {'count':<10} {'size':<13} {'size':<10}")
for src_ip in stats_by_port:
    for port in stats_by_port[src_ip]:
        data = stats_by_port[src_ip][port]
        dst_ip = next((ip for ip in stats_by_port if port in stats_by_port[ip]), '')
        print(
            f"{src_ip:<15} {data['proto_str']:<10} {port:<10} {data['count']:<10} {data['size']:<13} {data['size'] // data['count']}B")


def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    ip_count = {}
    port_count = {}
    ip_flags = {}

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            if src_ip not in ip_count:

                ip_count[src_ip] = 1
            else:
                ip_count[src_ip] += 1

            if dst_ip not in ip_count:
                ip_count[dst_ip] = 1
            else:
                ip_count[dst_ip] += 1

            if protocol == 6 and TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                if src_ip not in ip_flags:
                    ip_flags[src_ip] = [packet[TCP].flags]
                if dst_ip not in ip_flags:
                    ip_flags[dst_ip] = [packet[TCP].flags]

                if sport not in port_count:
                    port_count[sport] = 1
                else:
                    port_count[sport] += 1

                if dport not in port_count:
                    port_count[dport] = 1
                else:
                    port_count[dport] += 1
    print(ip_flags)
    print(packets)
    sorted_ip_count = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

    result = dict()
    for ip, count in sorted_ip_count:
        if count > 50:
            result[ip] = count
    if len(result) > 0:
        result = json.dumps(result)
        print(result)
        email_sender.send_to_yandex('Вас дудосят!!!!!!!!!!!!!!!!!!!!!', result, 'laba3ruslan@yandex.ru',
                                    'laba3ruslan@yandex.ru')


analyze_pcap(path_to_dump)
