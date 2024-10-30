from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Function to process each packet
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = packet.proto

        # Default values for TCP/UDP info
        src_port = "-"
        dst_port = "-"

        # Check for TCP or UDP layer and get ports
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport

        # Determine payload type without displaying exact value
        payload = bytes(packet[IP].payload)
        if not payload:
            payload_type = "No Payload"
        elif b'Raw' in payload:
            payload_type = "Raw"
        elif b'Padding' in payload:
            payload_type = "Padding"
        else:
            payload_type = "Data"

        # Print the packet information in a formatted way
        print(f"{src_ip:<18} {dst_ip:<18} {str(src_port):<15} {str(dst_port):<18} {str(protocol):<10} {payload_type}")

# Print header once with more spacing
print(f"{'Source IP':<18} {'Destination IP':<18} {'Source Port':<15} {'Destination Port':<18} {'Protocol':<10} {'Payload'}")
print("-" * 90)

# Start sniffing on the default network interface
print("Starting packet sniffer. Press Ctrl+C to stop.")
sniff(prn=packet_callback, filter="ip", store=0)
