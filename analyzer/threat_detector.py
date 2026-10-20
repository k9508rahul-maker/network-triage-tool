
from collections import defaultdict
from scapy.all import IP, IPv6, TCP


def detect_threats(packets):
    findings = []
    tcp_ports = defaultdict(set)
    syn_counts = defaultdict(int)

    for packet in packets:
        src_ip = None

        if IP in packet:
            src_ip = packet[IP].src
        elif IPv6 in packet:
            src_ip = packet[IPv6].src

        if not src_ip or TCP not in packet:
            continue

        tcp = packet[TCP]
        flags = int(tcp.flags)

        # SYN set, ACK unset: initial TCP connection attempt.
        if (flags & 0x02) and not (flags & 0x10):
            tcp_ports[src_ip].add(int(tcp.dport))
            syn_counts[src_ip] += 1

    for ip, ports in tcp_ports.items():
        if len(ports) >= 10:
            findings.append({
                "source": ip,
                "finding": "Possible TCP SYN port scan",
                "count": len(ports),
                "severity": "High",
                "evidence": (
                    f"{len(ports)} distinct TCP destination ports "
                    f"and {syn_counts[ip]} initial SYN packets"
                ),
            })

    return findings
