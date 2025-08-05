import socket
import nmap
import requests
import threading
import queue
import time
from progress.bar import Bar
import optparse

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

def from_file(filename):
    with open(filename, 'r') as f:
        subdomains = f.read().split('\n')
        return subdomains

def check_subdomain(domain, sub):
    subdomain = f"http://{sub.strip()}.{domain}"
    try:
        response = requests.get(subdomain, timeout=5)
        print(f"Response code for {sub}.{domain}: {response.status_code}")  # Print response code
        if response.status_code == 200:
            return True
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        return False
    return False

def append_if_exists(host, sub):
    if check_subdomain(host, sub):
        with lock:
            active_domains.append(f"{sub}.{host}")

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--input", dest="input_list", default="subdomains.txt",
                      help="read the list from INPUT_FILE", metavar="INPUT_FILE")
    parser.add_option("-f", "--file", dest="output_file", default="",
                      help="write report to FILE", metavar="FILE")
    parser.add_option("-t", "--threads", type=int, dest="n_threads", help="Set the number of threads",
                      metavar="N_THREADS", default=12)
    return parser.parse_args()

def get_active():
    global q
    while True:
        i = q.get()
        append_if_exists(domain_name, i)
        bar.next()
        q.task_done()

if __name__ == "__main__":
    target_website = input("Enter the target website: ")

    while True:
        print("\nSelect an option:")
        print("1. Port Scan")
        print("2. Subdomain Scan")
        print("3. Exit Program")
        try:
            option = int(input("\nEnter your choice (1, 2, or 3): "))
            if option == 1:
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
                            print("\nExiting Port Scan.")
                            break
                        else:
                            print("\nInvalid option. Please try again.")
                    except ValueError:
                        print("\nInvalid input. Please enter a valid option.")
            elif option == 2:
                q = queue.Queue()
                active_domains = []
                lock = threading.Lock()

                options, args = get_args()
                for subdomain in from_file(options.input_list):
                    q.put(subdomain)
                bar = Bar("Subdomain scanning...", max=q.qsize())

                domain_name = target_website

                session = requests.Session()
                session.headers[
                    "User-Agent"
                ] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                
                try:
                    pre_time = time.time()
                    for i in range(options.n_threads):
                        t = threading.Thread(target=get_active)
                        t.daemon = True
                        t.start()
                    q.join()
                except KeyboardInterrupt:
                    pass
                finally:
                    if options.output_file:
                        with open(options.output_file, "w") as f:
                            f.write("\n".join(active_domains))
                    else:
                        if active_domains:
                            print("\nActive subdomains:")
                            for e in active_domains:
                                print(e)
                        else:
                            print("\nNo active subdomains found.")

                    print(f"\nFound {len(active_domains)} active subdomains")
                    print("Total time taken: %s seconds" % (time.time() - pre_time))
                pass
            elif option == 3:
                print("\nExiting the program.")
                break
            else:
                print("\nInvalid option. Please try again !!!")
        except ValueError:
            print("\nInvalid input. Please enter a valid option (1, 2 or 3).")