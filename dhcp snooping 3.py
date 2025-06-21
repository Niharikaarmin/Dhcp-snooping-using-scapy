from scapy.all import *
import time
# Store observed DHCP servers (IP addresses)
observed_dhcp_servers = set()
# Function to process and log DHCP packets
def dhcp_snooping_callback(packet):
    if packet.haslayer(DHCP):
        dhcp_options = packet[DHCP].options
        dhcp_message_type = None

        # Parse the DHCP message type (Discover, Offer, Request, Ack, etc.)
        for option in dhcp_options:
            print("options", option)  # Debug: print the DHCP options
            if option[0] == 'message-type':
                dhcp_message_type = option[1]
                print("dhcp message type", dhcp_message_type)  # Debug: print message type
                break

        # Check for source IP, handling the "0.0.0.0" case for clients in DHCP Request
        source_ip = packet[IP].src if packet[IP].src != '0.0.0.0' else 'Unassigned (0.0.0.0)'

        # Logging based on message type
        if dhcp_message_type == 1:  # DHCP Discover
            print(f"DHCP Discover from {source_ip}")
        elif dhcp_message_type == 2:  # DHCP Offer
            print(f"DHCP Offer from {packet[IP].src}")
            observed_dhcp_servers.add(packet[IP].src)  # Record DHCP server IP
        elif dhcp_message_type == 3:  # DHCP Request
            print(f"DHCP Request from {source_ip}")
        elif dhcp_message_type == 5:  # DHCP Acknowledgment (ACK)
            print(f"DHCP Ack from {packet[IP].src}")
        elif dhcp_message_type == 6:  # DHCP NAK (Negative Acknowledgment)
            print(f"DHCP NAK from {packet[IP].src}")
        else:
            print(f"Unknown DHCP message from {packet[IP].src}")

        # Potential rogue DHCP server detection: log if there are multiple DHCP Offers
        if dhcp_message_type == 2:  # DHCP Offer
            if len(observed_dhcp_servers) > 1:
                print(f"Warning: Multiple DHCP Servers detected!")
                print(f"Observed DHCP Servers: {', '.join(observed_dhcp_servers)}")

                # Log potential rogue DHCP server
                rogue_servers = [server for server in observed_dhcp_servers if server != '192.168.0.1']
                if rogue_servers:
                    print(f"Potential Rogue DHCP Server(s) detected: {', '.join(rogue_servers)}")
                else:
                    print("No rogue servers detected.")

# Start sniffing for DHCP packets
def start_dhcp_snooping():
    print("Starting DHCP snooping...")
    try:
        # Sniff DHCP Discover, Offer, Request, and Ack packets
        sniff(filter="udp and (port 67 or 68)", prn=dhcp_snooping_callback, store=0, timeout=60)
    except KeyboardInterrupt:
        print("\nDHCP snooping stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the DHCP snooping function
if __name__ == "__main__":
    start_dhcp_snooping()
