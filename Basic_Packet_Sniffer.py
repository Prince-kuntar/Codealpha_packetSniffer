from scapy.all import *
import collections
import time


# Green color codes
GREEN = '\033[92m'
BOLD = '\033[1m'
RESET = '\033[0m'

class PacketSniffer:
    def __init__(self):
        self.packet_counts = 0
        self.protocol_stats = collections.Counter()
        self.start_time = time.time()

    def packet_handler(self, packet):
        self.packet_counts += 1
       
        if packet.haslayer(Ether):
            eth = packet[Ether]
            self.protocol_stats['Ethernet'] += 1
            print(f"MAC: {eth.src} -> {eth.dst}\n")
        

            if packet.haslayer(IP):
                ip = packet[IP]
                self.protocol_stats['IP'] += 1
                print(f"IP: {ip.src} -> {ip.dst}")

                #analysing the protocols
                proto = ip.proto
                protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                protocol_name = protocol_map.get(proto, f"Other({proto})")

                self.protocol_stats[protocol_name] += 1
                print(f"Protocol: {protocol_name}")

                print(f"TTL: {ip.ttl}")
                print(f"Size: {len(packet)} bytes")
                
                #analysing Transport Layer(TCP/UDP/ICMP)
                self.analyse_transport(packet)

            else:
                print("Non-IP Packet")
                print("=======================================================================================")
                    
        else:
            print("Non-Ethernet Packet")
            print("=======================================================================================")
        #display summary every 10 packets
        if self.packet_counts % 10 == 0:
            self.display_summary()

    # fun to analyse transport layer
    def analyse_transport(self, packet):

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
            else:
                print("No paylod")
                print("=======================================================================================")
        #UDP
        elif packet.haslayer(UDP):

            udp = packet[UDP]
            self.protocol_stats['UDP'] += 1
            print(f"UDP Port: {udp.sport} -> {udp.dport}")

            #analysing payload
            if udp.haslayer(Raw):
                payload = udp[Raw].load
                self.analyse_payload(payload)
            else:
                print("No paylod")
                print("=======================================================================================")

        #ICMP
        elif packet.haslayer(ICMP):
            self.protocol_stats['ICMP'] += 1
            print("ICMP Packet") 
            print("=======================================================================================")  

        else:
            print("Other Transport Layer Protocol")
            print("=======================================================================================")                                 

    #fun to convert TCP flags to human readable format
    def get_TCP_flags(self, tcp): 
        flag_names = {
            'F': 'FIN', 'S': 'SYN', 'R': 'RST',
            'P': 'PSH', 'A': 'ACK', 'U': 'URG',
            'E': 'ECE', 'C': 'CWR' }
        # Try to get a string representation of TCP flags (e.g. "S" or "SA")
        try:
            flags_str = tcp.sprintf("%flags%")
        except Exception:
            flags_str = str(tcp.flags)

        # If sprintf returns empty or numeric, fall back to numeric bit mask
        if not flags_str or flags_str.isdigit():
            try:
                flags_val = int(flags_str)
            except Exception:
                flags_val = int(tcp.flags)
            masks = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08, 'A': 0x10, 'U': 0x20, 'E': 0x40, 'C': 0x80}
            return ' '.join([name for ch, name in flag_names.items() if flags_val & masks[ch]])
        else:
            return ' '.join([name for ch, name in flag_names.items() if ch in flags_str])

    #fun to analyse payload
    def analyse_payload(self, payload):
        if len(payload) > 0:
            print(f"Payload ({len(payload)} bytes):")
            print(f"{GREEN}\nPayload ---{RESET}")
            print(f"{GREEN}   Payload length: {len(payload)} bytes{RESET}")
            try:
                # Try to decode as text
                text = payload.decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in text[:50]):
                    print(f"{GREEN}   Payload preview: {text[:100]}...{RESET}")
            except:
                print(f"{GREEN}   Payload (hex): {payload.hex()[:100]}...{RESET}")

            print("=======================================================================================")            


            #trying to detect https cont1ent
            if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
                print("Possible HTTP content detected.")

                try:
                    payload_text = payload.decode('utf-8', errors='ignore')
                    headers = payload_text.split('\r\n')[:5]
                    for header in headers:
                        if header.strip():
                            print(f"  {header.strip()}")

                    print("=======================================================================================")        
                except:
                    pass
            
                
            #show hex preview for non-text payloads
            elif len(payload) < 50:
                print("Hex Preview:")
                print(payload.hex())
                print("=======================================================================================")
        else:
            print("No Payload")
            print("=======================================================================================")
    #function to display statistics summary
    def display_summary(self):
        duration = time.time() - self.start_time
        print("\n---------------------------- Summary ----------------------------------")
        print(f"Total Packets: {self.packet_counts}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"\n Statistics (after {self.packet_counts} packets, {duration:.1f}s):")
        if self.packet_counts:
            for protocol, count in self.protocol_stats.most_common():
                percentage = (count / self.packet_counts) * 100
                print(f"  {protocol}: {count} packets ({percentage:.1f}%)")
        print()
        print("=======================================================================================")
#end of PacketSniffer class


def display_banner():
    """Display Ultimate Sniffer banner in green"""
    banner = f"""
{GREEN}{BOLD}

    ██╗   ██╗██╗  ████████╗███╗   ███╗ █████╗ ████████╗███████╗    
    ██║   ██║██║  ╚══██╔══╝████╗ ████║██╔══██╗╚══██╔══╝██╔════╝    
    ██║   ██║██║     ██║   ██╔████╔██║███████║   ██║   █████╗      
    ██║   ██║██║     ██║   ██║╚██╔╝██║██╔══██║   ██║   ██╔══╝      
    ╚██████╔╝███████╗██║   ██║ ╚═╝ ██║██║  ██║   ██║   ███████╗    
     ╚═════╝ ╚══════╝╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝    
                                                              
               ███████╗███╗   ██╗██╗███████╗███████╗██████╗         
               ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔══██╗        
               ███████╗██╔██╗ ██║██║█████╗  █████╗  ██████╔╝        
               ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══██╗        
               ███████║██║ ╚████║██║██╗     ███████╗██║  ██║        
               ╚══════╝╚═╝  ╚═══╝╚═╝╚══     ╚══════╝╚═╝  ╚═╝        
                                                              
                     by Prince Damiano                        
                                                              
{RESET}
"""
    print(banner)


def display_menu():
    """Display the main menu"""
    print(f"{GREEN}{BOLD}")
    print("┌─────────────────────────────────────────────┐")
    print("│              MAIN MENU                      │")
    print("├─────────────────────────────────────────────┤")
    print("│                                             │")
    print("│   1. Start Packet Sniffing                  │")
    print("│   2. View Help                              │")
    print("│   3. Exit                                   │")
    print("│                                             │")
    print("└─────────────────────────────────────────────┘")
    print(f"{RESET}")


def display_help():

    print(f"{GREEN}")
    print("┌─────────────────────────────────────────────┐")
    print("│                  HELP                       │")
    print("├─────────────────────────────────────────────┤")
    print("│                                             │")
    print("│   This sniffer will capture:                │")
    print("│   • IP Packets                              │")
    print("│   • TCP Segments                            │")
    print("│   • UDP Datagrams                           │")
    print("│   • ICMP Messages                           │")
    print("│                                             │")
    print("│   Information displayed:                    │")
    print("│   • Source/Destination IPs                  │")
    print("│   • Source/Destination Ports                │")
    print("│   • Protocol types                          │")
    print("│   • Packet payloads                         │")
    print("│                                             │")
    print("│   Press Ctrl+C to stop sniffing             │")
    print("│                                             │")
    print("└─────────────────────────────────────────────┘")
    print(f"{RESET}")

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')    

def main():
    sniffer = PacketSniffer()
    clear_screen()
    display_banner()
    display_menu()
    

    choice = input(f"{GREEN}Select an option (1-3): {RESET}").strip()
        
    if choice == "1":
            print("Starting packet capture... Press Ctrl+C to stop.")

            try:
                sniff(prn=sniffer.packet_handler, store=0)
            except KeyboardInterrupt:
                print("\nPacket capture stopped.")
                sniffer.display_summary()
                print("Exiting.")
                print("Sniffer terminated.")    
    elif choice == "2":
            clear_screen()
            display_banner()
            display_help()
            input(f"{GREEN}\nPress Enter to continue...{RESET}")
    elif choice == "3":
        print(f"{GREEN}\n Thank you for using Ultimate Sniffer!{RESET}")
        print(f"{GREEN}👨‍💻 Created by Prince Damiano{RESET}")

    else:
            print(f"{GREEN} Invalid option. Please choose 1, 2, or 3.{RESET}")
            time.sleep(2)   

if __name__ == "__main__":
    main()        

  