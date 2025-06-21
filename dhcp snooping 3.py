from scapy.all import *
import time

observed_dhcp_servers = set()
def dhcp_snooping_callback(packet):
    if packet.haslayer(DHCP):
        dhcp_options = packet[DHCP].options
        dhcp_message_type = None


        for option in dhcp_options:
            print("options", option) 
            if option[0] == 'message-type':
                dhcp_message_type = option[1]
                print("dhcp message type", dhcp_message_type) 
                break

        source_ip = packet[IP].src if packet[IP].src != '0.0.0.0' else 'Unassigned (0.0.0.0)'

   
        if dhcp_message_type == 1: 
            print(f"DHCP Discover from {source_ip}")
        elif dhcp_message_type == 2:  # DHCP Offer
            print(f"DHCP Offer from {packet[IP].src}")
            observed_dhcp_servers.add(packet[IP].src)
        elif dhcp_message_type == 3:  # DHCP Request
            print(f"DHCP Request from {source_ip}")
        elif dhcp_message_type == 5: 
            print(f"DHCP Ack from {packet[IP].src}")
        elif dhcp_message_type == 6: 
            print(f"DHCP NAK from {packet[IP].src}")
        else:
            print(f"Unknown DHCP message from {packet[IP].src}")

        if dhcp_message_type == 2:
            if len(observed_dhcp_servers) > 1:
                print(f"Warning: Multiple DHCP Servers detected!")
                print(f"Observed DHCP Servers: {', '.join(observed_dhcp_servers)}")

          
                rogue_servers = [server for server in observed_dhcp_servers if server != '192.168.0.1']
                if rogue_servers:
                    print(f"Potential Rogue DHCP Server(s) detected: {', '.join(rogue_servers)}")
                else:
                    print("No rogue servers detected.")


def start_dhcp_snooping():
    print("Starting DHCP snooping...")
    try:

        sniff(filter="udp and (port 67 or 68)", prn=dhcp_snooping_callback, store=0, timeout=60)
    except KeyboardInterrupt:
        print("\nDHCP snooping stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    start_dhcp_snooping()
