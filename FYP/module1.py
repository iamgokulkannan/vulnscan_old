import requests
import threading
import queue
import optparse
import nmap
import time
import socket
import sys
from progress.bar import Bar
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os
from pprint import pprint
import colorama

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

    if ip_address in result['scan']:
        port_data = result['scan'][ip_address]
        
        if 'tcp' in port_data:
            for port, port_info in port_data['tcp'].items():
                if port_info['state'] == 'open':
                    print('\033[32m' + f"Port {port} is open" + '\033[0m')
        else:
            print('\033[31m' + f"\tNo open ports found in the specified range." + '\033[0m')
    else:
        print("No scan results found for the target IP.")



# Function to read subdomains from a file
def from_file(filename):
    with open(filename, 'r') as f:
        subdomains = f.read().split('\n')
        return subdomains

# Function to check if a subdomain is active
def check_subdomain(domain, sub):
    subdomain = f"http://{sub.strip()}.{domain}"
    try:
        response = requests.get(subdomain, timeout=5)
        print(f" Response code for {sub}.{domain}: {response.status_code}")  # Print response code
        if response.status_code == 200:
            return True
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        return False
    return False

# Function to append active subdomains to a list if they exist
def append_if_exists(host, sub):
    if check_subdomain(host, sub):
        with lock:
            active_domains.append(f"{sub}.{host}")

# Function for thread worker to get active subdomains
def get_active():
    while True:
        try:
            i = q.get_nowait()
        except queue.Empty:
            break
        append_if_exists(domain_name, i)
        bar.next()
        q.task_done()

# Function to get command-line arguments
def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--input", dest="input_list", default="subdomains.txt",
                      help="read the list from INPUT_FILE", metavar="INPUT_FILE")
    parser.add_option("-t", "--threads", type=int, dest="n_threads", help="Set the number of threads",
                      metavar="N_THREADS", default=12)
    return parser.parse_args()

def get_server_info(target_domain):
    url = f"http://{target_domain}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            server_header = response.headers.get("Server", "N/A")
            x_powered_by_header = response.headers.get("X-Powered-By", "N/A")

            print(f"\nServer header: {server_header}")
            print(f"X-Powered-By header: {x_powered_by_header}")
        else:
            print(f"\nFailed to retrieve data from {url}. Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"\nFailed to connect to {url}: {str(e)}")



# Create a session with a User-Agent header
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Win64; x64) AppleWebKit/537.36 Chrome/87.0.4280.88"

# List of XSS payloads to test
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert('XSS')'>",
    # Add more payloads here as needed
]


# Function to retrieve forms from a URL
def get_forms(url):
    response = s.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")

# Function to extract form details
def form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []

    # Extract input fields
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append(
            {"type": input_type, "name": input_name, "value": input_value}
        )

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

# Function to check for SQL injection vulnerability
def is_vulnerable(response):
    # Customize this function to detect SQL injection vulnerabilities in your application's context
    # You may want to check for specific error messages or behaviors indicative of SQL injection
    return False

# Function to perform SQL injection testing
def test_sql_injection(url):
    # Ensure the URL starts with "http://" or "https://"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    forms = get_forms(url)
    print(f"\n[+] {len(forms)} forms found on {url}.")

    for form in forms:
        form_details_dict = form_details(form)
        
        # Initialize variables to track detection for each payload
        single_quote_detected = False
        double_quote_detected = False
        
        for payload in ["'", "\""]:
            data = {}

            # Create payloads for each input field
            for input_tag in form_details_dict["inputs"]:
                input_name = input_tag["name"]
                input_value = input_tag["value"]
                if input_value:
                    data[input_name] = input_value + payload
                elif input_tag["type"] != "submit":
                    data[input_name] = "test" + payload

            # Construct the URL and make the request
            target_url = urljoin(url, form_details_dict["action"])
            if form_details_dict["method"] == "post":
                response = s.post(target_url, data=data)
            elif form_details_dict["method"] == "get":
                response = s.get(target_url, params=data)

            # Check for SQL injection vulnerability and update detection status
            if is_vulnerable(response):
                if payload == "'":
                    single_quote_detected = True
                elif payload == "\"":
                    double_quote_detected = True

        # Print detection status for each payload
        if single_quote_detected:
            print("\nSingle quote SQL injection detected:", target_url)
        else:
            print("\nNo single quote SQL injection detected")

        if double_quote_detected:
            print("\nDouble quote SQL injection detected:", target_url)
        else:
            print("\nNo double quote SQL injection detected")


def get_all_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        return requests.get(target_url, params=data)

def scan_xss(url):
    # Ensure the URL starts with "http://" or "https://"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    forms = get_all_forms(url)
    print(f"\n[+] Detected {len(forms)} forms on {url}.")

    # Initialize a flag to track if any payload is detected
    any_payload_detected = False

    for form in forms:
        form_details = get_form_details(form)

        # Initialize variables to track detection for each payload
        xss_detected = {}

        for payload in xss_payloads:
            response = submit_form(form_details, url, payload)
            if payload in response.content.decode():
                xss_detected[payload] = True
                any_payload_detected = True
            else:
                xss_detected[payload] = False

        # Print detection status for each payload
        for payload, detected in xss_detected.items():
            if detected:
                print(colorama.Fore.RED + f"[!]XSS detected for payload '{payload}': {url}")
                print(colorama.Fore.YELLOW + f"[*] Form details:")
                pprint(form_details)
            else:
                print(f"\nNo XSS detected for payload '{payload}'")



if __name__ == "__main__":
    while True:
        domain_name = input("\nEnter the target domain : ")
        options, args = get_args()
        ip_address = socket.gethostbyname(domain_name)
        print(f"\nIP Address: {ip_address}")

        while True:
            print("\n1. Change Domain")
            print("2. Port Scan")
            print("3. Domain enumeration")
            print("4. Domain Fingerprinting")
            print("5. SQL Injection Testing")
            print("6. XSS Testing")
            print("7. Exit\n")
            choice = input("Enter a choice from the given options (1, 2, 3, 4, 5, 6, or 7): ")

            if choice == '1':
                break  # Change Domain

            elif choice == '2':
                while True:
                    print("\nPort Scanning Options:")
                    print("\n1. Scan a single port")
                    print("2. Scan custom ports")
                    print("3. Scan a range of ports")
                    print("4. Exit Port Scan\n")
                    try:
                        port_option = int(input("\nEnter your choice (1, 2, 3, or 4): "))
                        if port_option == 1:
                            port = input("\nEnter the port number to scan: ")
                            start_time = time.time()
                            scan_single_port(domain_name, port)
                            elapsed_time = time.time() - start_time
                            print(f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 2:
                            ports_input = input("\nEnter the port numbers to scan (comma-separated): ")
                            ports = [int(port.strip()) for port in ports_input.split(",")]
                            start_time = time.time()
                            scan_custom_ports(domain_name, ports)
                            elapsed_time = time.time() - start_time
                            print(f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 3:
                            start_port, end_port = map(int, input("\nEnter the port range to scan (e.g., 1-65535): ").split("-"))
                            start_time = time.time()
                            scan_range_of_ports(domain_name, start_port, end_port)
                            elapsed_time = time.time() - start_time
                            print(f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 4:
                            print("\nExiting Port Scan...\n")
                            break  # Break out of the port scanning loop
                        else:
                            print("\nInvalid option. Please enter a valid option (1, 2, 3, or 4)")
                    except ValueError:
                        print("\nInvalid input. Please enter a valid option (1, 2, 3, or 4)")

            elif choice == '3':
                q = queue.Queue()  # Create the queue before using it
                for subdomain in from_file(options.input_list):
                    q.put(subdomain)
                bar = Bar("Subdomain scanning...", max=q.qsize())

                # Use a session for making requests
                session = requests.Session()
                
                # Specify the User-Agent header
                session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

                # Set up threading for concurrent subdomain scanning
                active_domains = []
                lock = threading.Lock()
                q = queue.Queue()
                
                for subdomain in from_file(options.input_list):
                    q.put(subdomain)
                    
                threads = []
                for i in range(options.n_threads):
                    t = threading.Thread(target=get_active)
                    t.daemon = True
                    t.start()
                    threads.append(t)
                    
                for t in threads:
                    t.join()

                # Print the results
                if active_domains:
                    print("\n\nActive subdomains:")
                    for e in active_domains:
                        print(e)
                else:
                    print("No active subdomains found.")
                pass

            elif choice == '4':
                get_server_info(domain_name)
            elif choice == '5':
                test_sql_injection(domain_name)
            elif choice == '6':
                colorama.init()
                scan_xss(domain_name)
                colorama.deinit()
            elif choice == '7':
                print("Exiting the script...")
                sys.exit()
            else:
                print("\nInvalid option. Please enter a valid option (1, 2, 3, 4, 5, 6, or 7)")
