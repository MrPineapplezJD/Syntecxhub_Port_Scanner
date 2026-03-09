#   Port Scanner
#   09/03/2026

import socket
import subprocess
import sys
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
import os

socket.setdefaulttimeout(0.5)

#   Clear Screen
os.system('cls' if os.name == 'nt' else 'clear')

open_ports = []
lock = threading.Lock()

scanned_ports = 0
progress_lock = threading.Lock()


#   Host & Port Range Input
try:
    remoteServer = input("Enter a remote Host to Scan: ")   #scanme.nmap.org
    remoteServerIP = socket.gethostbyname(remoteServer)

    start_port = int(input("Enter Start port: "))
    end_port = int(input("Enter End port: "))

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid port range.")
        sys.exit()

except socket.gaierror:
    print("Hostname could not be resolved.")
    sys.exit()

except socket.error:
    print("Could not connect to server.")
    sys.exit()


#   Print Scan Header
print("_" * 60)
print("Scanning remote Host", remoteServerIP)
print("_" * 60)

#   Start Timer
t1 = datetime.now()


#   Functions
def grab_banner(sock):
    try:
        sock.settimeout(0.5)
        sock.send(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        banner = sock.recv(1024)
        return banner.decode(errors = "ignore").strip()
    except:
        return "No banner received"

def scan_port(port):
    global scanned_ports

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex((remoteServerIP, port))

            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"

                banner = grab_banner(sock)

                with lock:
                    open_ports.append((port, service, banner))
                
                print(f"\nPort {port}: Open ({service})")
                print(f"Banner: {banner}")
       
        #   Track Progress
        with progress_lock:
            scanned_ports += 1
            print(f"Progress: {scanned_ports}/{total_ports} ports scanned", end="\r")

    except:
        pass
    

#   Adaptive Thread Calcuations & Execution
total_ports = end_port - start_port + 1
max_threads = min(500, total_ports)

print(f"\nScanning {total_ports} ports using {max_threads} threads...\n")

try:
    with ThreadPoolExecutor(max_workers = max_threads) as executor:
        executor.map(scan_port, range(start_port, end_port + 1))

except KeyboardInterrupt:
    print("\nScan interrupted.")
    sys.exit()


#   Stop Timer
t2 = datetime.now()
total = t2 - t1


open_ports.sort()


#   Print Results
if len(open_ports) == 0:
    print("\nNo open ports found.")
else:
    print("\nOpen Ports: ", open_ports)

print("\nOpen Ports found:", len(open_ports))
print("Scanning Completed in:", total)


#   Save Resuts to File
file = open("scan_results.txt", "w")

file.write("Port Scan Results\n")
file.write("Host: " + remoteServer + " (" + remoteServerIP + ")\n")
file.write("Scan Time: " + str(total) + "\n")
file.write("Open Ports:\n")

for port, service, banner in open_ports:
    file.write(f"Port {port} ({service})\n")
    file.write(f"Banner: {banner}\n\n")

file.write("\nTotal Open Ports: " + str(len(open_ports)))

file.close()

print("\nResults saved to scan_results.txt")
