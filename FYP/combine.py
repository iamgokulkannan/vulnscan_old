import socket
import nmap
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import threading
import time
import queue
from progress.bar import Bar
import optparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch




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


# Example usage
target_website = input("Enter the target website: ")

print("Select an option:")
print("1. Scan a single port")
print("2. Scan custom ports")
print("3. Scan a range of ports")
option = int(input("Enter your choice (1, 2, or 3): "))

if option == 1:
    port = input("Enter the port number to scan: ")
    start_time = time.time()
    scan_single_port(target_website, port)
    elapsed_time = time.time() - start_time
    print(f"Elapsed time: {elapsed_time:.2f} seconds")
elif option == 2:
    ports_input = input("Enter the port numbers to scan (comma-separated): ")
    ports = [int(port.strip()) for port in ports_input.split(",")]
    start_time = time.time()
    scan_custom_ports(target_website, ports)
    elapsed_time = time.time() - start_time
    print(f"Elapsed time: {elapsed_time:.2f} seconds")
elif option == 3:
    start_port, end_port = map(int, input("Enter the port range to scan (e.g., 1-65535): ").split("-"))
    start_time = time.time()
    scan_range_of_ports(target_website, start_port, end_port)
    elapsed_time = time.time() - start_time
    print(f"Elapsed time: {elapsed_time:.2f} seconds")
else:
    print("Invalid option. Exiting.")

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

#  Function to get all forms 
def get_forms(url, session):
    response = session.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type, 
            "name" : input_name,
            "value" : input_value,
        })
        
    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

def vulnerable(response):
    if response is None:
        return False
    errors = {"quoted string not properly terminated", 
              "unclosed quotation mark after the character string",
              "you have an error in your SQL syntax" 
             }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def fix_url(url):
    # Check if the URL starts with "http://" or "https://"
    if not url.startswith("http://") and not url.startswith("https://"):
        # Add "http://" prefix by default
        url = "http://" + url
    return url

def sql_injection_scan(url, session):
    # Fix the URL to include "http://" if needed
    url = fix_url(url)

    forms = get_forms(url, session)
    print(f"\n[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)
        res = None

        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"
        
            form_details(form)

            if details["method"] == "post":
                res = session.post(url, data=data)
            elif details["method"] == "get":
                res = session.get(url, params=data)

            if vulnerable(res):
                print("[+] SQL Injection vulnerability detected.")
                return True  # SQL injection vulnerability found

    print("[+] No SQL Injection vulnerability detected.")
    return False  # No SQL injection vulnerability found




q = queue.Queue()
bar = None

active_domains = []
lock = threading.Lock()

def from_file(filename):
    with open(filename, 'r') as f:
        subdomains = f.read().split('\n')
        return subdomains

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


def generate_pdf_report(target, port, sql_injection_result, subdomains_result):
    pdf_filename = f"{target}_report.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    story = []

    # Title
    title_style = getSampleStyleSheet()["Title"]
    title = Paragraph(f"Vulnerability Scan Report for {target}", title_style)
    story.append(title)
    story.append(Spacer(1, 0.5 * inch))

    # Target Information
    info_style = getSampleStyleSheet()["Normal"]
    target_info = f"Target: {target}\nPort: {port}\n"
    target_info_paragraph = Paragraph(target_info, info_style)
    story.append(target_info_paragraph)
    story.append(Spacer(1, 0.2 * inch))

    # Port Scanning Results
    
    if port:
        port_result = f"Port {port} is open" 
    else:
        port_result = f"Port {port} is closed" 
         
    port_result_paragraph = Paragraph(port_result, info_style)
    story.append(port_result_paragraph)
    story.append(Spacer(1, 0.5 * inch))

    # SQL Injection Scan Results
    sql_injection_style = getSampleStyleSheet()["Heading2"]
    sql_injection_result_text = "SQL Injection Scan Results"
    sql_injection_result_paragraph = Paragraph(sql_injection_result_text, sql_injection_style)
    story.append(sql_injection_result_paragraph)

    result_text_style = getSampleStyleSheet()["BodyText"]
    if sql_injection_result:
        result_text = "SQL Injection vulnerability detected.\n\n"
    else:
        result_text = "No SQL Injection vulnerability detected.\n\n"

    result_paragraph = Paragraph(result_text, result_text_style)
    story.append(result_paragraph)
    story.append(Spacer(1, 0.5 * inch))

    # Active Subdomains
    subdomains_style = getSampleStyleSheet()["Heading2"]
    subdomains_text = "Active Subdomains"
    subdomains_paragraph = Paragraph(subdomains_text, subdomains_style)
    story.append(subdomains_paragraph)

    if subdomains_result:
        for subdomain in subdomains_result:
            subdomain_paragraph = Paragraph(f"- {subdomain}", result_text_style)
            story.append(subdomain_paragraph)
    else:
        no_subdomains_paragraph = Paragraph("No active subdomains found.", result_text_style)
        story.append(no_subdomains_paragraph)

    doc.build(story)

    print(f"\nPDF report generated: {pdf_filename}")


def generate_text_report(target, port, sql_injection_result, subdomains_result):
    # Function to generate a text report
    report_filename = f"{target}_report.txt"
    with open(report_filename, "w") as f:
        f.write(f"Target Information:\n")
        f.write(f"Target: {target}\n")
        f.write(f"Port: {port}\n\n")
        f.write(f"Port Scanning Results:\n")
        ip_address = get_ip_address(target)
        scanner = nmap.PortScanner()
        result = scanner.scan(ip_address, arguments=f'-p {port}')
        port_state = result['scan'][ip_address]['tcp'][int(port)]['state']
        f.write(f"Port {port} is {port_state}\n\n")
        
        f.write(f"SQL Injection Scan Results:\n")
        if sql_injection_result:
            f.write("SQL Injection vulnerability detected.\n\n")
        else:
            f.write("No SQL Injection vulnerability detected.\n\n")

        f.write(f"Active Subdomains:\n")
        if subdomains_result:
            for subdomain in subdomains_result:
                f.write(f"{subdomain}\n")
        else:
            f.write("No active subdomains found.\n")

    print(f"Text report generated: {report_filename}")

def check_xss_vulnerability(url, session):
    forms = get_forms(url, session)
    print(f"\n[+] Detected {len(forms)} forms on {url}.")

    xss_vulnerable_forms = []
    
    for form in forms:
        details = form_details(form)
        res = None

        for input_tag in details["inputs"]:
            if input_tag["type"] in ["text", "url", "search"]:
                data = {input_tag["name"]: "<script>alert('XSS Vulnerable')</script>"}

                if details["method"] == "post":
                    res = session.post(url, data=data)
                elif details["method"] == "get":
                    res = session.get(url, params=data)

                if "<script>alert('XSS Vulnerable')</script>" in res.text:
                    xss_vulnerable_forms.append(details)
                    print(f"[+] XSS vulnerability detected in form on {url}:")
                    print(f"\tAction: {details['action']}")
                    print(f"\tMethod: {details['method']}")
                    print("\tInputs:")
                    for input_tag in details["inputs"]:
                        print(f"\t\tName: {input_tag['name']}, Type: {input_tag['type']}")
                else:
                    print(f"[+] No XSS vulnerability detected in form on {url}:")
                    print(f"\tAction: {details['action']}")
                    print(f"\tMethod: {details['method']}")
                    print("\tInputs:")
                    for input_tag in details["inputs"]:
                        print(f"\t\tName: {input_tag['name']}, Type: {input_tag['type']}")

    if not xss_vulnerable_forms:
        print(f"[+] No XSS vulnerability detected in any form on {url}.")




def check_csrf_protection(url, session):
    forms = get_forms(url, session)
    print(f"\n[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)
        if details["method"] == "post":
            csrf_token = None
            csrf_token_name = None

            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden":
                    csrf_token_name = input_tag["name"]
                    csrf_token = input_tag["value"]
                    break

            if csrf_token:
                data_without_token = {"data": "test"}
                data_with_token = {csrf_token_name: csrf_token, "data": "test"}

                # Make a request without the CSRF token
                res_without_token = session.post(url, data=data_without_token)
                # Make a request with the CSRF token
                res_with_token = session.post(url, data=data_with_token)

                if res_without_token.status_code == res_with_token.status_code:
                    print(f"[+] CSRF protection might be missing for {url}")
                else:
                    print(f"[+] CSRF protection is present for {url}")
                return

    print(f"[+] No forms with 'POST' method found on {url}.\n")



if __name__ == "__main__":
    options, args = get_args()
    for subdomain in from_file(options.input_list):  # Rename 's' to 'subdomain'
        q.put(subdomain)
    bar = Bar("Subdomain scanning...", max=q.qsize())

    domain_name = target_website  # Prompt for the domain name

    session = requests.Session()  # Create the session object here
    session.headers[
        "User-Agent"
    ] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    
    
    sql_injection_result = False  # Declare sql_injection_result before try block
    try:
        pre_time = time.time()
        for i in range(options.n_threads):
            t = threading.Thread(target=get_active)
            t.daemon = True
            t.start()
        q.join()
        sql_injection_result = sql_injection_scan(target_website, session)  # Use 'session', not 's'
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
                print("No active subdomains found.")

        print(f"\nFound {len(active_domains)} active subdomains")
        print("Executed in %s seconds" % (time.time() - pre_time))

        urlToBeChecked = target_website
        if not urlToBeChecked.startswith("http://") and not urlToBeChecked.startswith("https://"):
            urlToBeChecked = "https://" + urlToBeChecked
        
         # Call sql_injection_scan and store the result in sql_injection_result
        print("\n[+] SQL injection Scan:")
        sql_injection_result = sql_injection_scan(urlToBeChecked, session)

        # Generate reports
        generate_pdf_report(target_website, port, sql_injection_result, active_domains)
        generate_text_report(target_website, port, sql_injection_result, active_domains)

        # XSS vulnerability scan
        print("\n[+] XSS Vulnerability Scan:")
        check_xss_vulnerability(urlToBeChecked, session)

        # CSRF protection check
        print("\n[+] CSRF Protection Check:")
        check_csrf_protection(urlToBeChecked, session)

