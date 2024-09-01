def generate_report(packets):
    report = "Network Traffic Report\n"
    report += "----------------------\n"
    for packet in packets:
        report += f"Packet: {packet.src} -> {packet.dst}\n"
    with open("traffic_report.txt", "w") as file:
        file.write(report)

if __name__ == "__main__":
    packets = []  # This should be the list of captured packets
    generate_report(packets)
