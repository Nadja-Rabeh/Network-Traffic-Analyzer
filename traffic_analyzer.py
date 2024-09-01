from packet_sniffer import sniff_packets

def filter_packets(packet, protocol=None):
    if protocol and packet.haslayer(protocol):
        return True
    return False

def analyze_traffic(interface):
    print("Starting traffic analysis...")
    sniff_packets(interface)

if __name__ == "__main__":
    interface = "eth0"
    analyze_traffic(interface)
