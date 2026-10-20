
from collections import Counter, defaultdict
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP

from .threat_detector import detect_threats


def analyze_pcap(file_path):
    total_packets = 0
    unique_ips = set()
    protocols = Counter()
    source_counts = Counter()
    destination_counts = Counter()
    source_ports = defaultdict(set)
    packet_details = []
    events = []
    all_packets = []

    # Read packets and collect them for threat detection.
    with PcapReader(file_path) as capture:
        for packet in capture:
            all_packets.append(packet)

            total_packets += 1

            src_ip = None
            dst_ip = None
            protocol = "OTHER"
            src_port = None
            dst_port = None

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            if src_ip:
                unique_ips.add(src_ip)
                source_counts[src_ip] += 1

            if dst_ip:
                unique_ips.add(dst_ip)
                destination_counts[dst_ip] += 1

            if TCP in packet:
                protocol = "TCP"
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)

                # Record TCP destination ports per source IP.
                if src_ip:
                    source_ports[src_ip].add(dst_port)

            elif UDP in packet:
                protocol = "UDP"
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)

            elif ICMP in packet:
                protocol = "ICMP"

            elif IPv6 in packet:
                protocol = "IPv6"

            elif IP in packet:
                protocol = "IP"

            protocols[protocol] += 1

            if len(packet_details) < 200:
                packet_details.append({
                    "source": src_ip or "Non-IP",
                    "destination": dst_ip or "Non-IP",
                    "protocol": protocol,
                    "source_port": (
                        src_port if src_port is not None else "-"
                    ),
                    "destination_port": (
                        dst_port if dst_port is not None else "-"
                    ),
                    "size": len(packet),
                })

    # Detect SYN-based and other supported threats.
    events = detect_threats(all_packets)

    # Detect TCP port diversity for each source IP.
    for ip_address, ports in source_ports.items():
        if len(ports) >= 10 and not any(
            event["source"] == ip_address
            for event in events
        ):
            events.append({
                "source": ip_address,
                "finding": "Multiple TCP destination ports contacted",
                "count": len(ports),
                "severity": "Medium",
                "evidence": (
                    f"{len(ports)} distinct TCP destination ports observed"
                ),
            })

    return {
        "total_packets": total_packets,
        "unique_ips": len(unique_ips),
        "protocols": dict(protocols),
        "top_sources": source_counts.most_common(10),
        "top_destinations": destination_counts.most_common(10),
        "source_counts": dict(source_counts),
        "destination_counts": dict(destination_counts),
        "packets": packet_details,
        "events": events,
        "packets_shown": len(packet_details),
    }
