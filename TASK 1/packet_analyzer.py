from scapy.all import sniff, IP


def packet_callback(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("\n--- Packet Captured ---")
        print("Source IP      :", source_ip)
        print("Destination IP :", destination_ip)
        print("Protocol       :", protocol)
        print("Packet Data    :", packet.summary())


print("===================================")
print("      NETWORK PACKET ANALYZER")
print("===================================")
print("Capturing packets...")
print("Press CTRL + C to stop.\n")

sniff(prn=packet_callback, store=False)
