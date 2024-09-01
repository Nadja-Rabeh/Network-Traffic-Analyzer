import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)

def analyze_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Packet: {ip_src} -> {ip_dst}")
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":
            print("[!] SYN Packet Detected!")

if __name__ == "__main__":
    sniff_packets("eth0")
