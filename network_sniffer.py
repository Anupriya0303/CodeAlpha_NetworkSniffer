from scapy.all import sniff, IP, TCP, UDP

def packet_info(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        print(f"Protocol : {protocol}")
        print(f"Source IP     : {src}")
        print(f"Destination IP: {dst}")
        print("-" * 40)

print("🔍 Network Sniffer Started... Capturing 20 packets")
print("=" * 40)
sniff(prn=packet_info, count=20)
print("✅ Capture Complete!")