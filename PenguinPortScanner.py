# VERSION FOR LINUX
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from tqdm import tqdm
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
dest_ip = ""
begin_dest_ports = 0
end_dest_ports = 0
def std_tcp_scan(dest_ip, begin_dest_ports, end_dest_ports):
    tcp_packet = IP(dst=dest_ip)/TCP(dport=0, flags="S")

    open_ports = []
    for port in tqdm(range(begin_dest_ports, end_dest_ports + 1), desc='Scanning TCP ports'):
        tcp_packet[TCP].dport = port

        os.system("clear")

        tcp_response = sr1(tcp_packet, timeout=1, verbose=0)
        if (tcp_response):
            if (tcp_response[TCP].flags == "SA"):
                open_ports.append(port)

    if (len(open_ports) > 0):
        print(f"Open ports: {open_ports}")
    else:
        print(f"Found 0 open ports.")

def udp_scan(dest_ip, begin_dest_ports, end_dest_ports):
    udp_packet = IP(dst=dest_ip)/UDP(dport=0)

    open_ports = []

    for port in tqdm(range(begin_dest_ports, end_dest_ports+1), desc='Scanning UDP ports'):
        udp_packet[UDP].dport = port

        os.system("clear")

        udp_response = sr1(udp_packet, timeout=1, verbose=0)
        if (udp_response):
            if (udp_response == None):
                open_ports.append(port)
            elif (udp_response.haslayer(UDP)):
                open_ports.append(port)
    if (len(open_ports) > 0):
        print(f"\nOpen ports: {open_ports}")
    else:
        print(f"\nFound 0 open ports")



print("Welcome to Penguin Port Scanner!\n")

done = False
while not done:
    dest_ip = input("Enter destination IP address:\t")
    try:
        print(f"Entered dest_ip: {dest_ip}.")
        done = True
        continue
    except ValueError:
        print("Input must be in format 000.000.000.000, please try again")

done = False
while not done:
    try:
        begin_dest_ports = int(input("Enter starting port (1-1000):\t"))
        end_dest_ports = int(input("Enter end port (1-1000):\t"))

        if (begin_dest_ports >= 1 and end_dest_ports <= 1000):
            print(f"Port range is between {begin_dest_ports} and {end_dest_ports}")
            break
        else:
            print("Ports must be between 1 and 1000. Please try again")
    except ValueError:
        print("Ports must be entered as 'int' values. Please try again")

done = False
while not done:
    try:
        type_scan = str(input("Enter the protocol: T/t for TCP, U/u for UDP:\t"))
        if (type_scan == "T" or type_scan == "t"):
            std_tcp_scan(dest_ip, begin_dest_ports, end_dest_ports)
            done = True
        elif (type_scan == "U" or type_scan == "u"):
            udp_scan(dest_ip, begin_dest_ports, end_dest_ports)
            done = True
        else:
            print("Input must be 'T/t' or 'U/u'. Please try again")
    except ValueError:
        print("Invalid input. Please try again")

