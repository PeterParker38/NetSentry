from scapy.all import sniff, IP, TCP, UDP
import sqlite3
from datetime import datetime
from detection.rules import detect_port_scan

DB = "netsentry.db"

def process_packet(packet):
    if IP in packet:

        protocol = "Other"
        src_port = None
        dst_port = None

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Convert UNIX timestamp to readable datetime
        timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(DB)
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO packets 
            (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            packet[IP].src,
            packet[IP].dst,
            protocol,
            src_port,
            dst_port,
            len(packet)
        ))

        conn.commit()
        conn.close()

        # Run detection logic on this IP
        detect_port_scan(packet[IP].src)

def start_sniffing():
    sniff(prn=process_packet, store=False)
