#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    Written by ChatGPT with prompts by Mike Holcomb (mike@mikeholcomb.com).
#
#    This POC sends a broadcast payload to discover any CLICK PLCs on a network subnet.

import socket
from scapy.all import *
import psutil

def get_interfaces():
    interfaces = psutil.net_if_addrs()
    iface_list = []
    print()
    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        if addrs := interfaces.get(iface):
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    print(f"{idx}: {iface} ({addr.address})")
                    iface_list.append((iface, addr.address))
                    break
    return iface_list

def send_udp_broadcast(broadcast_ip, payload, src_port, dest_port, iface, src_ip):
    packet = IP(src=src_ip, dst=broadcast_ip) / UDP(sport=src_port, dport=dest_port) / Raw(load=payload)
    send(packet, iface=iface, verbose=0)

# Listen for responses on the specified port
def listen_for_responses(port, iface):
    responses = []
    def udp_packet_callback(packet):
        if UDP in packet and packet[UDP].sport == port:
            ip = packet[IP].src
            responses.append(ip)
    sniff(filter=f"udp and port {port}", prn=udp_packet_callback, timeout=10, iface=iface)
    return responses

def main():
    iface_list = get_interfaces()

    while True:
        print()
        iface_idx = input("Select the network interface to use (number): ")
        if iface_idx.isdigit() and int(iface_idx) in range(len(iface_list)):
            iface, src_ip = iface_list[int(iface_idx)]
            break
        else:
            print("Invalid selection. Please try again.")

    broadcast_ip = "255.255.255.255"
    payload = bytes.fromhex('4b4f50000100edd5040045016680')
    src_port = 2770
    dest_port = 25425

    print()
    print(f"Sending UDP broadcast packet to {broadcast_ip} using interface {iface} from {src_ip}...")
    send_udp_broadcast(broadcast_ip, payload, src_port, dest_port, iface, src_ip)

    print()
    print("Listening for responses...")
    responses = listen_for_responses(dest_port, iface)

    if responses:
        print()
        print("Received responses from:")
        print("========================")
        for ip in responses:
            print(f"{ip}")
    else:
        print("No responses received.")

if __name__ == "__main__":
    main()
