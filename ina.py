#!/usr/bin/env python3
"""
Ultimate Network Sniffer using Scapy
by Prince Damiano
"""

from scapy.all import *
import time
import os

# Green color codes
GREEN = '\033[92m'
BOLD = '\033[1m'
RESET = '\033[0m'

def display_banner():
    """Display Ultimate Sniffer banner in green"""
    banner = f"""
{GREEN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗██╗  ████████╗███╗   ███╗ █████╗ ████████╗███████╗  ║
║   ██║   ██║██║  ╚══██╔══╝████╗ ████║██╔══██╗╚══██╔══╝██╔════╝  ║
║   ██║   ██║██║     ██║   ██╔████╔██║███████║   ██║   █████╗    ║
║   ██║   ██║██║     ██║   ██║╚██╔╝██║██╔══██║   ██║   ██╔══╝    ║
║   ╚██████╔╝███████╗██║   ██║ ╚═╝ ██║██║  ██║   ██║   ███████╗  ║
║    ╚═════╝ ╚══════╝╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝  ║
║                                                              ║
║   ███████╗███╗   ██╗██╗███████╗███████╗██████╗ ███████╗      ║
║   ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔══██╗██╔════╝      ║
║   ███████╗██╔██╗ ██║██║█████╗  █████╗  ██████╔╝█████╗        ║
║   ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══██╗██╔══╝        ║
║   ███████║██║ ╚████║██║██      ███     ██║  ██║███████╗      ║
║   ╚══════╝╚═╝  ╚═══╝╚═╝╚═      ══╝     ╚═╝  ╚═╝╚══════╝      ║
║                                                              ║
║                     by Prince Damiano                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{RESET}
"""
    print(banner)

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

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
    """Display help information"""
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

def get_packet_count():
    """Ask user how many packets to capture"""
    while True:
        try:
            print(f"{GREEN}")
            count = input("How many packets to capture? (Enter for unlimited): ").strip()
            if count == "":
                return 0  # Unlimited
            count = int(count)
            if count > 0:
                return count
            else:
                print("Please enter a positive number or press Enter for unlimited")
        except ValueError:
            print("Please enter a valid number")

def get_interface():
    """Ask user for network interface"""
    print(f"{GREEN}")
    interface = input("Enter network interface (Enter for default): ").strip()
    return interface if interface else None

def packet_handler(packet):
    """
    This function processes each captured packet in GREEN!
    """
    print(f"{GREEN}\n" + "="*50)
    print(f"📦 Packet captured at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50 + f"{RESET}")
    
    # Display basic packet information
    print(f"{GREEN}📋 Packet summary: {packet.summary()}{RESET}")
    
    # Check if packet has IP layer
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"{GREEN}\n🌐 IP Layer ---{RESET}")
        print(f"{GREEN}   Source IP:      {ip.src}{RESET}")
        print(f"{GREEN}   Destination IP: {ip.dst}{RESET}")
        print(f"{GREEN}   Protocol:       {ip.proto}{RESET}")
        
        # Common protocol numbers
        protocols = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP"
        }
        proto_name = protocols.get(ip.proto, f"Unknown ({ip.proto})")
        print(f"{GREEN}   Protocol Name:  {proto_name}{RESET}")
    
    # Check for TCP layer
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"{GREEN}\n🔄 TCP Layer ---{RESET}")
        print(f"{GREEN}   Source Port:      {tcp.sport}{RESET}")
        print(f"{GREEN}   Destination Port: {tcp.dport}{RESET}")
        print(f"{GREEN}   Flags:            {tcp.flags}{RESET}")
        
        # Show payload if present
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"{GREEN}\n📦 Payload ---{RESET}")
            print(f"{GREEN}   Payload length: {len(payload)} bytes{RESET}")
            try:
                # Try to decode as text
                text = payload.decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in text[:50]):
                    print(f"{GREEN}   Payload preview: {text[:100]}...{RESET}")
            except:
                print(f"{GREEN}   Payload (hex): {payload.hex()[:100]}...{RESET}")
    
    # Check for UDP layer
    if packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"{GREEN}\n📨 UDP Layer ---{RESET}")
        print(f"{GREEN}   Source Port:      {udp.sport}{RESET}")
        print(f"{GREEN}   Destination Port: {udp.dport}{RESET}")
        print(f"{GREEN}   Length:           {udp.len}{RESET}")
    
    # Check for ICMP layer
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        print(f"{GREEN}\n📡 ICMP Layer ---{RESET}")
        print(f"{GREEN}   Type: {icmp.type}{RESET}")
        print(f"{GREEN}   Code: {icmp.code}{RESET}")

def start_sniffing():
    """
    Start packet sniffing with user configuration
    """
    clear_screen()
    display_banner()
    
    print(f"{GREEN}🚀 Configuring Sniffer...{RESET}")
    
    # Get user preferences
    interface = get_interface()
    packet_count = get_packet_count()
    
    clear_screen()
    display_banner()
    
    print(f"{GREEN}🚀 Starting Ultimate Network Sniffer...{RESET}")
    if packet_count > 0:
        print(f"{GREEN}📡 Capturing {packet_count} packets{RESET}")
    else:
        print(f"{GREEN}📡 Capturing unlimited packets{RESET}")
    
    if interface:
        print(f"{GREEN}🔧 Interface: {interface}{RESET}")
    else:
        print(f"{GREEN}🔧 Using default interface{RESET}")
    
    print(f"{GREEN}⏹️  Press Ctrl+C to stop{RESET}")
    print(f"{GREEN}" + "─" * 50 + f"{RESET}\n")
    
    try:
        # Sniff packets
        if packet_count > 0:
            # Limited packet count
            if interface:
                packets = sniff(iface=interface, prn=packet_handler, count=packet_count)
            else:
                packets = sniff(prn=packet_handler, count=packet_count)
        else:
            # Unlimited packets
            if interface:
                packets = sniff(iface=interface, prn=packet_handler)
            else:
                packets = sniff(prn=packet_handler)
            
        print(f"{GREEN}\n✅ Capture completed!{RESET}")
        
    except KeyboardInterrupt:
        print(f"{GREEN}\n\n🛑 Sniffer stopped by user{RESET}")
    except Exception as e:
        print(f"{GREEN}❌ Error: {e}{RESET}")
    
    input(f"{GREEN}\nPress Enter to continue...{RESET}")

def main():
    """Main program loop"""
    while True:
        clear_screen()
        display_banner()
        display_menu()
        
        choice = input(f"{GREEN}Select an option (1-3): {RESET}").strip()
        
        if choice == "1":
            start_sniffing()
        elif choice == "2":
            clear_screen()
            display_banner()
            display_help()
            input(f"{GREEN}\nPress Enter to continue...{RESET}")
        elif choice == "3":
            print(f"{GREEN}\n👋 Thank you for using Ultimate Sniffer!{RESET}")
            print(f"{GREEN}👨‍💻 Created by Prince Damiano{RESET}")
            break
        else:
            print(f"{GREEN}❌ Invalid option. Please choose 1, 2, or 3.{RESET}")
            time.sleep(2)

if __name__ == "__main__":
    main()