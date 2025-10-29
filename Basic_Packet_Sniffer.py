from scapy.all import*
import collections
import time

class PacketSniffer:
    def __init__(self):
        self.packet_counts = 0
        self.protocol_stats = collections.Counter
        self.time = time.time()

    def packet_handler(self, packet):
        self.packet_counts += 1
       
        if packet.haslayer(Ether):
            eth = packet[Ether]
            self.protocol_stats['Ethernet'] += 1
            print(f"MAC: {eth.src} -> {eth.dest}")
        

        if packet.hasLayer(IP):
            ip = packet[IP]
            self.protocol_stats['IP'] += 1
            print(f"IP: {ip.src} -> {ip.dest}")

            #analysing the protocols
            proto = ip.proto
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol_name = protocol_map.get(proto, f"Other({proto})")

            self.protocol_stats[protocol_name] += 1
            print(f"Protocol: {protocol_name}")

            print(f"TTL: {ip.ttl}")
            print(f"Size: {len(packet)} bytes")

        #analysing Transport Layer(TCP/UDP/ICMP)
        self.analyse_trasport(self,packet)

        #display summary every 10 packets
        if self.packet_counts % 10 == 0:
            self.display_summary()

    # fun to analysse transport layer
    def analyse_trasport(self, packet):

        #TCP
        if packet.haslayer(TCP):

            tcp = packet[TCP]
            self.protocol_stats['TCP'] += 1
            print(f"TCP Port: {tcp.sport} -> {tcp.dport}")
            print(f"Flags: {self.get_TCP_flags(tcp)}")

            #analysing payload
            if tcp.haslayer(Raw):
                payload = tcp[Raw].load
                self.analyse_payload(payload)
        #UDP
        elif packet.haslayer(UDP):

            udp = packet[UDP]
            self.protocol_stats['UDP'] += 1
            print(f"UDP Port: {udp.sport} -> {udp.dport}")

            #analysing payload
            if udp.haslayer(Raw):
                payload = udp[Raw].load
                self.analyse_payload(payload)

        #ICMP
        elif packet.haslayer(ICMP):
            self.protocol_stats['ICMP'] += 1
            print("ICMP Packet")        

    #fun to convert TCP flags to human readable format
    def get_TCP_flags(self, tcp): 
        flag_names = {
            'F': 'FIN', 'S': 'SYN', 'R': 'RST',
            'P': 'PSH', 'A': 'ACK', 'U': 'URG',
            'E': 'ECE', 'C': 'CWR' }
        return ' '.join([name for flag, name in flag_names.items() if tcp.flags & getattr(TCP, flag)])

    #fun to analyse payload
    def analyse_payload(self, payload):
        if len(payload) > 0:
            print(f"Payload ({len(payload)} bytes):")
            print(payload)

            #trying to detect https content
            if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
                print("Possible HTTP content detected.")

                try:
                    payload_text = payload.decode('utf-8', errors='ignore')
                    headers = payload_text.split('\r\n')[:5]
                    for header in headers:
                        if header.strip():
                            print(f"  {header.strip()}")
                except:
                    pass

            #show hex preview for non-text payloads
            elif len(payload) < 50:
                print("Hex Preview:")
                print(payload.hex())
