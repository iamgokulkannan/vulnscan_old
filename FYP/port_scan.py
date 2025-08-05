import nmap
import time
import socket

def get_ip_address(target):
    ip_address = socket.gethostbyname(target)
    return ip_address

def scan_single_port(target, port):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    result = scanner.scan(ip_address, arguments=f'-p {port}')
    if result['scan'][ip_address]['tcp'][int(port)]['state'] == 'open':
        print('\033[32m' + f"Port {port} is open" + '\033[0m')
    else:
        print('\033[31m' + f"Port {port} is closed" + '\033[0m')

def scan_custom_ports(target, ports):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    scanner.scan(ip_address, arguments=f'-p {",".join(str(port) for port in ports)} -sT')
    open_ports = []
    closed_ports = []
    
    for port in ports:
        port_state = scanner[ip_address]['tcp'][port]['state']
        if port_state == 'open':
            open_ports.append(port)
        else:
            closed_ports.append(port)
    
    print('\033[33m' + "Open Ports:" + '\033[0m')
    if open_ports:
        for port in open_ports:
            print('\033[32m' + f"\tPort {port} is open" + '\033[0m')
    else:
        print("\tNo open ports found in the specified range.")
    
    print('\033[33m' + "Closed Ports:" + '\033[0m')
    if closed_ports:
        for port in closed_ports:
            print('\033[31m' + f"\tPort {port} is closed" + '\033[0m')
    else:
        print("\tNo closed ports found in the specified range.")

def scan_range_of_ports(target, start_port, end_port):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    port_range = f"{start_port}-{end_port}"
    result = scanner.scan(ip_address, arguments=f'-p {port_range}')
    open_ports = []
    for port in result['scan'][ip_address]['tcp']:
        if result['scan'][ip_address]['tcp'][port]['state'] == 'open':
            open_ports.append(int(port))
    print('\033[33m' + "Open Ports:" + '\033[0m')    
    if open_ports:
        for port in open_ports:
            print('\033[32m' + f"\tPort {port} is open" + '\033[0m')
    else:
        print("\tNo open ports found in the specified range.")


if __name__ == "__main__":
    target_website = input("Enter the target website: ")
    while True:
        print("\nPort Scanning Options:")
        print("1. Scan a single port")
        print("2. Scan custom ports")
        print("3. Scan a range of ports")
        print("4. Exit Port Scan")
        try:
            port_option = int(input("\nEnter your choice (1, 2, 3, or 4): "))
            if port_option == 1:
                port = input("\nEnter the port number to scan: ")
                start_time = time.time()
                scan_single_port(target_website, port)
                elapsed_time = time.time() - start_time
                print(f"Elapsed time: {elapsed_time:.2f} seconds")
            elif port_option == 2:
                ports_input = input("\nEnter the port numbers to scan (comma-separated): ")
                ports = [int(port.strip()) for port in ports_input.split(",")]
                start_time = time.time()
                scan_custom_ports(target_website, ports)
                elapsed_time = time.time() - start_time
                print(f"Elapsed time: {elapsed_time:.2f} seconds")
            elif port_option == 3:
                start_port, end_port = map(int, input("\nEnter the port range to scan (e.g., 1-65535): ").split("-"))
                start_time = time.time()
                scan_range_of_ports(target_website, start_port, end_port)
                elapsed_time = time.time() - start_time
                print(f"Elapsed time: {elapsed_time:.2f} seconds")
            elif port_option == 4:
                print("\nExiting Port Scan.....")
                break
            else:
                print("\nInvalid option. Please enter a valid option (1, 2, 3, or 4)")
        except ValueError:
            print("\nInvalid input. Please enter a valid option (1, 2, 3 or 4)")