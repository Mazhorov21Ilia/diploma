import psutil
import time
from scapy.all import sniff, IP
from collections import deque, defaultdict
import socket

packet_buffer = []
last_cleanup_time = time.time()

incoming_tr = psutil.net_io_counters().bytes_recv
outcoming_tr = psutil.net_io_counters().bytes_recv

def packet_handler(pkt):
    global packet_buffer
    current_time = time.time()
    while packet_buffer and current_time - packet_buffer[0].time > 15:
        packet_buffer.pop(0)
    if IP in pkt:
        packet_buffer.append(pkt)
def start_background_sniffer():
    bpf_filter = "tcp or udp"
    sniff(
        prn=packet_handler,
        store=False,
        filter=bpf_filter
    )
def aggregate_ip_traffic():
    global packet_buffer
    traffic = defaultdict(lambda: {"sent": 0, "received": 0})
    for pkt in packet_buffer:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            size = len(pkt)
            traffic[src_ip]["sent"] += size
            traffic[dst_ip]["received"] += size
    ip_stats = []
    for ip, stats in traffic.items():
        stats["total"] = stats["sent"] + stats["received"]
        stats["ip_address"] = ip
        ip_stats.append(stats)
    ip_stats.sort(key=lambda x: x["total"], reverse=True)
    packet_buffer = []
    return ip_stats[:5]
def collect_network_metrics(config):
    global last_cleanup_time, incoming_tr, outcoming_tr
    current_time = time.time()
    if current_time - last_cleanup_time > 5:
        while packet_buffer and current_time - packet_buffer[0].time > config.get("packet_buffer_duration"):
            packet_buffer.pop(0)
        last_cleanup_time = current_time
    io_counters = psutil.net_io_counters()
    connections = psutil.net_connections()
    metrics = {
        "device_id": config.get("device_id", "unknown_device"),
        "incoming_traffic": io_counters.bytes_recv - incoming_tr if io_counters.bytes_recv > 2 else 0,
        "outgoing_traffic": io_counters.bytes_sent - outcoming_tr if io_counters.bytes_sent > 2 else 0,
        "active_tcp_connections": sum(1 for conn in connections if conn.status == 
                                      "ESTABLISHED" and conn.type == socket.SOCK_STREAM),
        "active_udp_connections": sum(1 for conn in connections if conn.type == 
                                      socket.SOCK_DGRAM),
    }
    incoming_tr = io_counters.bytes_recv
    outcoming_tr = io_counters.bytes_sent
    metrics["ip_traffic"] = aggregate_ip_traffic()
    return metrics
