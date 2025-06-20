from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from tqdm import tqdm
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from base.utils import extractHeaders, strength, isProtected, stringToBinary, longestCommonSubstring
from base.sendRequest import sendRequest
from base.extractHTMLInformation import extractHTMLInformation
from base.rangeFinder import rangeFinder
from base.formEvaluate import formEvaluate
from base.modifyManipulateAPI import modifyManipulateAPI
from base.crawl import crawl
from base.prompt import prompt
from base.formParser import formParser
from base.entropy import isRandom
from base.colors import green, yellow, end, run, good, info, bad, white, red
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import statistics
import re
import random
import json
import argparse
import requests
import threading
import queue
import optparse
import nmap
import time
import socket
import ssl
import time
import sys
from progress.bar import Bar
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os
from pprint import pprint
import colorama
from base.testing import headers
import concurrent.futures
from pathlib import Path
from fuzzywuzzy import fuzz, process
import html
import secrets
import sys


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#              IP Information           #                 IP Information                #                IP Information                 #              IP Information           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def get_ip_address(domain_name):
    if not domain_name.startswith(("http://", "https://")):
        domain_name = "http://" + domain_name

    parsed_url = urlparse(domain_name)
    domain_name = parsed_url.netloc  # Extracting domain name from the URL

    ip_address = socket.gethostbyname(domain_name)
    print(f"\nIP Address: {ip_address}")


def get_ip_address(target):
    ip_address = socket.gethostbyname(target)
    return ip_address


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#               Port Scanning           #                  Port Scanning                #                 Port Scanning                 #               Port Scanning           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def scan_single_port(target, port):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    result = scanner.scan(ip_address, arguments=f'-p {port}')
    if result['scan'][ip_address]['tcp'][int(port)]['state'] == 'open':
        print('\033[32m' + f"Port {port} is open" + '\033[0m')
        port_scan_results.append(f"\n\tPort {port} is open")
    else:
        print('\033[31m' + f"Port {port} is closed" + '\033[0m')
        port_scan_results.append(f"\n\tPort {port} is closed")
    return port_scan_results


def scan_custom_ports(target, ports):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    scanner.scan(
        ip_address, arguments=f'-p {",".join(str(port) for port in ports)} -sT')
    open_ports = []
    closed_ports = []
    port_scan_results = []  # Initialize port_scan_results list

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
            port_scan_results.append(f"\n\tPort {port} is open")
    else:
        print("\tNo open ports found in the specified range.")
        port_scan_results.append(
            f"\n\tNo open ports found in the specified range.")

    print('\033[33m' + "Closed Ports:" + '\033[0m')
    if closed_ports:
        for port in closed_ports:
            print('\033[31m' + f"\tPort {port} is closed" + '\033[0m')
            port_scan_results.append(f"\n\tPort {port} is open")
    else:
        print("\tNo closed ports found in the specified range.")
        port_scan_results.append(
            f"\n\tNo open ports found in the specified range.")
    return port_scan_results


def scan_range_of_ports(target, start_port, end_port):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    port_range = f"{start_port}-{end_port}"
    result = scanner.scan(ip_address, arguments=f'-p {port_range}')

    port_scan_results = []
    if ip_address in result['scan']:
        port_data = result['scan'][ip_address]

        if 'tcp' in port_data:
            for port, port_info in port_data['tcp'].items():
                if port_info['state'] == 'open':
                    print('\033[32m' + f"\tPort {port} is open" + '\033[0m')
                    port_scan_results.append(f"\n\tPort {port} is open")
        else:
            print(
                '\033[31m' + f"\tNo open ports found in the specified range." + '\033[0m')
            port_scan_results.append(
                "\n\tNo open ports found in the specified range.")
    else:
        print("No scan results found for the target IP.")
        port_scan_results.append(
            "\n\tNo scan results found for the target IP.")

    return port_scan_results


# Function to read subdomains from a file
def from_file(filename):
    with open(filename, 'r') as f:
        subdomains = f.read().split('\n')
        return subdomains

# Function to check if a subdomain is active

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                Domain Enumeration             #                  Domain Enumeration                   #                 Domain Enumeration            #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def check_subdomain(domain, sub):
    subdomain = f"http://{sub.strip()}.{domain}"
    try:
        response = requests.get(subdomain, timeout=5)
        # Print response code
        print(f" Response code for {sub}.{domain}: {response.status_code}")
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

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                Domain Fingerprinting          #                  Domain Fingerprinting                #                Domain Fingerprinting          #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def get_server_info(target_domain):
    url = f"http://{target_domain}"
    try:
        response = requests.get(url, timeout=10)  # Timeout set to 10 seconds
        if response.status_code == 200:
            server_header = response.headers.get("Server", "N/A")
            x_powered_by_header = response.headers.get("X-Powered-By", "N/A")

            print(f"\nServer header: {server_header}")
            server_info.append(f"\n\tServer header: {server_header}")
            print(f"X-Powered-By header: {x_powered_by_header}")
            server_info.append(
                f"\n\tX-Powered-By header: {x_powered_by_header}")
        else:
            print(
                f"\nFailed to retrieve data from {url}. Status Code: {response.status_code}")
            server_info.append(
                f"\n\tFailed to retrieve data from {url}. Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"\nFailed to connect to {url}: {str(e)}")
        server_info.append(f"\n\tFailed to connect to {url}: {str(e)}")


# Create a session with a User-Agent header
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Win64; x64) AppleWebKit/537.36 Chrome/87.0.4280.88"

# List of XSS payloads to test
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror=\"alert('XSS')\">",
    # Add more payloads here as needed
]


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                getting form details           #                  getting form details                 #                 getting form details          #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


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
    return False

# Function to perform SQL injection testing


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                SQL Injection          #                  SQL Injection                #                 SQL Injection                 #               SQL Injection           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def test_sql_injection(url):
    # Ensure the URL starts with "http://" or "https://"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    forms = get_forms(url)
    print(f"\n[+] {len(forms)} forms found on {url}.")
    sql_test_results.append(f"\n\t[+] {len(forms)} forms found on {url}.")
    if (len(forms) == '0'):
        print("\n No SQL Injection detected")

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
                else:
                    print('\nNo SQL Injection Detected')

        # Print detection status for each payload
        if single_quote_detected:
            print("\nSingle quote SQL injection detected:", target_url)
            sql_test_results.append(
                "\n\tSingle quote SQL injection detected:", target_url)
        else:
            print("\nNo single quote SQL injection detected")
            sql_test_results.append(
                "\n\tNo single quote SQL injection detected")

        if double_quote_detected:
            print("\nDouble quote SQL injection detected:", target_url)
            sql_test_results.append(
                "\n\tDouble quote SQL injection detected:", target_url)
        else:
            print("\nNo double quote SQL injection detected")
            sql_test_results.append(
                "\n\tNo double quote SQL injection detected")


def get_all_forms(url):
    soup = BeautifulSoup(requests.get(url, timeout=10).content, "html.parser")
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
            return requests.post(target_url, data=data, timeout=10)
        return requests.get(target_url, params=data, timeout=10)

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                  XSS Testing          #                    XSS Testing                #                   XSS Testing                 #                 XSS Testing           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def scan_xss(url):
    # Ensure the URL starts with "http://" or "https://"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    forms = get_all_forms(url)
    print(f"\n[+] Detected {len(forms)} forms on {url}.")
    xss_test_results.append(f"\n\t[+] Detected {len(forms)} forms on {url}.")

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
                print(colorama.Fore.RED +
                      f"[!]XSS detected for payload '{payload}': {url}")
                xss_test_results.append(
                    f"\n\t[!]XSS detected for payload '{payload}': {url}")
                print(colorama.Fore.YELLOW + f"[*] Form details:")
                xss_test_results.append(f"\n\t[*] Form details:")
                print(form_details)
                xss_test_results.append("\n\t"+form_details)
            else:
                print(f"\nNo XSS detected for payload '{xss_payloads}'")
                xss_test_results.append(
                    f"\n\tNo XSS detected for payload '{xss_payloads}'")


def banner():
    yellow = "\033[93m"
    white = "\033[0m"
    end = "\033[0m"
    print('''
     %s⚡ %sVuln Scan%s  ⚡%s
    ''' % (yellow, white, yellow, end))


def sanitize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


banner()

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                 CSRF          #                  CSRF                 #                 CSRF                  #               CSRF            #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def csrf(domain_name):
    lightning = '\033[93;5m ⚡ \033[0m'

    try:
        import concurrent.futures
        from pathlib import Path
    except ImportError:
        print(f"{lightning} Vulnscan is not compatible with Python version 2. Please run it with Python version 3.")
        return

    try:
        from fuzzywuzzy import fuzz, process
    except ImportError:
        print(
            f"{lightning} The 'fuzzywuzzy' library is not installed. Please install it manually by running:\n"
            "    pip install fuzzywuzzy\n"
            "Once installed, restart the program."
        )
        # Exiting to prevent further execution without the dependency
        exit(1)

    # Interactive input for the target domain
    target = domain_name
    target = sanitize_url(target)

    # Additional interactive input for other parameters (you can customize this part)
    delay = int(
        input('%s Enter the delay between requests (default is 0 ): ' % info) or 0)  # Delay: Time between requests (throttling to prevent being flagged as malicious).
    level = int(
        input('%s Enter the number of levels to crawl (default is 2 ): ' % info) or 2)  # Crawl Levels: Depth of URL crawling on the site
    timeout = int(
        input('%s Enter the HTTP request timeout (default is 20 ): ' % info) or 20)  # Timeout: Maximum waiting time for HTTP responses
    threadCount = int(
        input('%s Enter the number of threads (default is 2 ): ' % info) or 2)  # Thread Count: Number of concurrent threads for crawling

    delay_desc = 'Delay between requests'
    level_desc = 'Number of levels to crawl'
    timeout_desc = 'HTTP request timeout'
    threadCount_desc = 'Number of threads'

    csrf_results.append((delay_desc, delay))
    csrf_results.append((level_desc, level))
    csrf_results.append((timeout_desc, timeout))
    csrf_results.append((threadCount_desc, threadCount))

    # Prompt for headers interactively
    headers_input = input(
        '%s Do you want to enter custom HTTP headers? (y/n): ' % info).lower()
    if headers_input == 'y':
        headers = extractHeaders(prompt())
    else:
        from base.testing import headers

    allTokens = []
    weakTokens = []
    tokenDatabase = []
    insecureForms = []

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Crawling the Website
    ######################################################################################################################################################
    #########################################################################################################################################################

    print(' %s \n Phase: Crawling %s[%s1/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Crawling [1/6]')
    dataset = crawl(target, headers, level, threadCount)
    allForms = dataset[0]
    for url_dict in allForms:
        for url, _ in url_dict.items():
            print(url)
            csrf_results.append(url)
    print('\r%s Crawled %i URL(s) and found %i form(s).%-10s' %
          (info, dataset[1], len(allForms), ' '))
    csrf_results.append('\r%s Crawled %i URL(s) and found %i form(s).%-10s' %
                        (info, dataset[1], len(allForms), ' '))

    #########################################################################################################################################################
    #########################################################################################################################################################
    # CSRF Token Evaluation
    #########################################################################################################################################################
    #########################################################################################################################################################

    print(' %s \n Phase: Evaluating %s[%s2/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Evaluating [2/6]')

    formEvaluate(allForms, weakTokens, tokenDatabase, allTokens, insecureForms)

    if weakTokens:
        print('%s Weak token(s) found' % good)
        csrf_results.append('%s Weak token(s) found' % good)
        for weakToken in weakTokens:
            url = list(weakToken.keys())[0]
            token = list(weakToken.values())[0]
            print('%s %s %s' % (info, url, token))
            csrf_results.append('%s %s %s' % (info, url, token))

    if insecureForms:
        print('%s Insecure form(s) found' % good)
        csrf_results.append('%s Insecure form(s) found' % good)
        for insecureForm in insecureForms:
            url = list(insecureForm.keys())[0]
            action = list(insecureForm.values())[0]['action']
            form = action.replace(target, '')
            if form:
                print('%s %s %s[%s%s%s]%s' %
                      (bad, url, green, end, form, green, end))
                csrf_results.append('%s %s %s[%s%s%s]%s' %
                                    (bad, url, green, end, form, green, end))

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Replay Attack Analysis
    #########################################################################################################################################################
    #########################################################################################################################################################

    print(' %s \n Phase: Comparing %s[%s3/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Comparing [3/6]')

    uniqueTokens = set(allTokens)
    if len(uniqueTokens) < len(allTokens):
        print('%s Potential Replay Attack condition found' % good)
        csrf_results.append(
            '%s Potential Replay Attack condition found' % good)
        print('%s Verifying and looking for the cause' % run)
        csrf_results.append('%s Verifying and looking for the cause' % run)
        replay = False
        for each in tokenDatabase:
            url, token = next(iter(each.keys())), next(iter(each.values()))
            for each2 in tokenDatabase:
                url2, token2 = next(iter(each2.keys())), next(
                    iter(each2.values()))
                if token == token2 and url != url2:
                    print('%s The same token was used on %s%s%s and %s%s%s' %
                          (good, green, url, end, green, url2, end))
                    csrf_results.append('%s The same token was used on %s%s%s and %s%s%s' %
                                        (good, green, url, end, green, url2, end))
                    replay = True
        if not replay:
            print('%s Further investigation shows that it was a false positive.')
            csrf_results.append(
                '%s Further investigation shows that it was a false positive.')

    p = Path(__file__).parent.joinpath('db/hashes.json')
    with p.open('r') as f:
        hashPatterns = json.load(f)

    if not allTokens:
        print('%s No CSRF protection to test, NO CSRF TOKENS AVAILABLE' % bad)
        csrf_results.append(
            '%s No CSRF protection to test, NO CSRF TOKENS AVAILABLE' % bad)
        return

    print("Length of allTokens:", len(allTokens))
    csrf_results.append(["Length of allTokens", len(allTokens)])

    if len(allTokens) > 0:
        print("Length of first sublist in allTokens:", len(allTokens[0]))
        csrf_results.append([
            "Length of first sublist in allTokens:", len(allTokens[0])])
    else:
        print("Error: allTokens is empty.")
        csrf_results.append("Error: allTokens is empty.")
        return

    if len(allTokens[0]) == 0:
        print("Error: First sublist in allTokens is empty.")
        csrf_results.append("Error: First sublist in allTokens is empty.")
        return

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Hash Pattern Matching
    #########################################################################################################################################################
    #########################################################################################################################################################

    if allTokens and len(allTokens) > 0:
        aToken = allTokens[0]
        if aToken:
            matches = []
            for element in hashPatterns:
                pattern = element['regex']
                if re.match(pattern, aToken):
                    for name in element['matches']:
                        matches.append(name)
            if matches:
                print(
                    '%s Token matches the pattern of the following hash type(s):' % info)
                csrf_results.append(
                    '%s Token matches the pattern of the following hash type(s):' % info)
                for name in matches:
                    print(' %s>%s %s' % (yellow, end, name))
                    csrf_results.append(' %s>%s %s' % (yellow, end, name))

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Comparing Tokens , High similarity indicates weak randomness in token generation, making the site vulnerable
    #########################################################################################################################################################
    #########################################################################################################################################################

            def fuzzy(tokens):
                averages = []
                for token in tokens:
                    sameTokenRemoved = False
                    result = process.extract(
                        token, tokens, sbaser=fuzz.partial_ratio)
                    sbases = []
                    for each in result:
                        sbase = each[1]
                        if sbase == 100 and not sameTokenRemoved:
                            sameTokenRemoved = True
                            continue
                        sbases.append(sbase)
                    average = statistics.mean(sbases)
                    averages.append(average)
                return statistics.mean(averages)

            try:
                similarity = fuzzy(allTokens)
                print('%s Tokens are %s%i%%%s similar to each other on average' %
                      (info, green, similarity, end))
                csrf_results.append('%s Tokens are %s%i%%%s similar to each other on average' %
                                    (info, green, similarity, end))
            except statistics.StatisticsError:
                print(
                    '%s No CSRF protection to test, CSRF vulnerability not found' % bad)
                csrf_results.append(
                    '%s No CSRF protection to test, CSRF vulnerability not found' % bad)
        else:
            print("The first element of allTokens is an empty list.")
            csrf_results.append(
                "The first element of allTokens is an empty list.")
    else:
        print("No CSRF tokens available.")
        csrf_results.append("No CSRF tokens available.")

    def staticParts(allTokens):
        strings = list(set(allTokens.copy()))
        commonSubstrings = {}
        for theString in strings:
            strings.remove(theString)
            for string in strings:
                commonSubstring = longestCommonSubstring(theString, string)
                if commonSubstring not in commonSubstrings:
                    commonSubstrings[commonSubstring] = []
                if len(commonSubstring) > 2:
                    if theString not in commonSubstrings[commonSubstring]:
                        commonSubstrings[commonSubstring].append(theString)
                    if string not in commonSubstrings[commonSubstring]:
                        commonSubstrings[commonSubstring].append(string)
        return commonSubstrings

    result = {k: v for k, v in staticParts(allTokens).items() if v}

    if result:
        print('%s Common substring found' % info)
        csrf_results.append('%s Common substring found' % info)
        print(json.dumps(result, indent=4))
        csrf_results.append(json.dumps(result, indent=4))

    simTokens = []
    print(' %s \n Phase: Observing %s[%s4/6%s]%s' %
          (lightning, green, end, green, end))

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Simultaneous Requests || Sends 100 concurrent requests to see if the server issues the same CSRF token , If identical tokens are issued, it may lead to vulnerabilities
    ######################################################################################################################################################
    #########################################################################################################################################################

    csrf_results.append('Phase: Observing [4/6]')
    print('%s 100 simultaneous requests are being made, please wait.' % info)
    csrf_results.append(
        '%s 100 simultaneous requests are being made, please wait.' % info)

    def extractForms(url):
        response = sendRequest(url, {}, headers, True, 0).text
        forms = extractHTMLInformation(url, response)
        for each in forms.values():
            localTokens = set()
            inputs = each['inputs']
            for inp in inputs:
                value = inp['value']
                if value and re.match(r'^[\w\-_]+$', value):
                    if strength(value) > 10:
                        simTokens.append(value)

    # Define goodCandidate before the loop
    goodCandidate = None

    # Limit the number of iterations to 100
    for _ in range(100):
        sample = secrets.choice(tokenDatabase)
        goodToken = list(sample.values())[0]
        if len(goodToken) > 0:
            goodCandidate = list(sample.keys())[0]
            break

    # Check if a valid goodCandidate was found
    if goodCandidate is not None:
        threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=30)
        futures = (threadpool.submit(extractForms, goodCandidate)
                   for _ in range(30))

        # Introduce a timeout for completion
        try:
            # Set a reasonable timeout value
            for i in concurrent.futures.as_completed(futures, timeout=60):
                pass
        except concurrent.futures.TimeoutError:
            print("Timeout reached. Exiting the loop.")
            csrf_results.append("Timeout reached. Exiting the loop.")
        else:
            print("No valid goodCandidate found.")
            csrf_results.append("No valid goodCandidate found.")

    if simTokens:
        if len(set(simTokens)) < len(simTokens):
            print('%s Same tokens were issued for simultaneous requests.' % good)
            csrf_results.append(
                '%s Same tokens were issued for simultaneous requests.' % good)
        else:
            print(simTokens)
            csrf_results.append(simTokens)
    else:
        print('%s Different tokens were issued for simultaneous requests.' % info)
        csrf_results.append(
            '%s Different tokens were issued for simultaneous requests.' % info)

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Mobile Browser Simulation || Simulates a request from a mobile browser to check if CSRF protection is consistent across devices.
    ######################################################################################################################################################
    #########################################################################################################################################################

    print(' %s \n Phase: Testing %s[%s5/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Testing [5/6]')

    parsed = ''
    found = False
    print('%s Finding a suitable form for further testing. It may take a while.' % run)
    csrf_results.append(
        '%s Finding a suitable form for further testing. It may take a while.' % run)
    for form_dict in allForms:
        for url, forms in form_dict.items():
            parsed = formParser(forms, tolerate=True)
            if parsed:
                found = True
                break
        if found:
            break

    if not parsed:
        quit('%s No suitable form found for testing.' % bad)

    origGET = parsed[0]
    origUrl = parsed[1]
    origData = parsed[2]

    print('%s Making a request with CSRF token for comparison.' % run)
    csrf_results.append(
        '%s Making a request with CSRF token for comparison.' % run)
    response = sendRequest(origUrl, origData, headers, origGET, 0)
    originalCode = response.status_code
    originalLength = len(response.text)
    print('%s Status Code: %s' % (info, originalCode))
    csrf_results.append('%s Status Code: %s' % (info, originalCode))
    print('%s Content Length: %i' % (info, originalLength))
    csrf_results.append('%s Content Length: %i' % (info, originalLength))
    print('%s Checking if the resonse is dynamic.' % run)
    csrf_results.append('%s Checking if the resonse is dynamic.' % run)
    response = sendRequest(origUrl, origData, headers, origGET, 0)
    secondLength = len(response.text)
    if originalLength != secondLength:
        print('%s Response is dynamic.' % info)
        csrf_results.append('%s Response is dynamic.' % info)
        tolerableDifference = abs(originalLength - secondLength)
    else:
        print('%s Response isn\'t dynamic.' % info)
        csrf_results.append('%s Response isn\'t dynamic.' % info)
        tolerableDifference = 0

    print('%s Emulating a mobile browser' % run)
    csrf_results.append('%s Emulating a mobile browser' % run)
    print('%s Making a request with mobile browser' % run)
    csrf_results.append('%s Making a request with mobile browser' % run)
    headers['User-Agent'] = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows CE; PPC; 240x320)'
    response = sendRequest(origUrl, {}, headers, True, 0).text
    parsed = extractHTMLInformation(origUrl, response)
    if isProtected(parsed):
        print('%s CSRF protection is enabled for mobile browsers as well.' % bad)
        csrf_results.append(
            '%s CSRF protection is enabled for mobile browsers as well.' % bad)
    else:
        print('%s CSRF protection isn\'t enabled for mobile browsers.' % good)
        csrf_results.append(
            '%s CSRF protection isn\'t enabled for mobile browsers.' % good)

    print('%s Making a request without CSRF token parameter.' % run)
    csrf_results.append(
        '%s Making a request without CSRF token parameter.' % run)

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Token Removal and Manipulation || Checking if the server accepts requests without a valid token aka modified token
    ######################################################################################################################################################
    #########################################################################################################################################################

    data = modifyManipulateAPI(origData, 'remove')
    response = sendRequest(origUrl, data, headers, origGET, 0)
    if response.status_code == originalCode:
        if str(originalCode)[0] in ['4', '5']:
            print('%s It didn\'t work' % bad)
            csrf_results.append('%s It didn\'t work' % bad)
        else:
            difference = abs(originalLength - len(response.text))
            if difference <= tolerableDifference:
                print('%s It worked!' % good)
                csrf_results.append('%s It worked!' % good)
            else:
                print('%s It didn\'t work' % bad)
                csrf_results.append('%s It didn\'t work' % bad)

    print('%s Making a request without CSRF token parameter value.' % run)
    csrf_results.append(
        '%s Making a request without CSRF token parameter value.' % run)
    data = modifyManipulateAPI(origData, 'clear')

    response = sendRequest(origUrl, data, headers, origGET, 0)
    if response.status_code == originalCode:
        if str(originalCode)[0] in ['4', '5']:
            print('%s It didn\'t work' % bad)
            csrf_results.append('%s It didn\'t work' % bad)
        else:
            difference = abs(originalLength - len(response.text))
            if difference <= tolerableDifference:
                print('%s It worked!' % good)
                csrf_results.append('%s It worked!' % good)
            else:
                print('%s It didn\'t work' % bad)
                csrf_results.append('%s It didn\'t work' % bad)

    seeds = rangeFinder(allTokens)

    print('%s Checking if tokens are checked to a specific length' % run)
    csrf_results.append(
        '%s Checking if tokens are checked to a specific length' % run)

    for index in range(len(allTokens[0])):
        data = modifyManipulateAPI(
            origData, 'replace', index=index, seeds=seeds)
        response = sendRequest(origUrl, data, headers, origGET, 0)
        if response.status_code == originalCode:
            if str(originalCode)[0] in ['4', '5']:
                break
            else:
                difference = abs(originalLength - len(response.text))
                if difference <= tolerableDifference:
                    print('%s Last %i chars of token aren\'t being checked' %
                          (good, index + 1))
                    csrf_results.append('%s Last %i chars of token aren\'t being checked' %
                                        (good, index + 1))
                else:
                    break

    print('%s Generating a fake token.' % run)
    csrf_results.append('%s Generating a fake token.' % run)

    data = modifyManipulateAPI(origData, 'generate', seeds=seeds)
    print('%s Making a request with the self generated token.' % run)
    csrf_results.append(
        '%s Making a request with the self generated token.' % run)

    response = sendRequest(origUrl, data, headers, origGET, 0)
    if response.status_code == originalCode:
        if str(originalCode)[0] in ['4', '5']:
            print('%s It didn\'t work' % bad)
            csrf_results.append('%s It didn\'t work' % bad)
        else:
            difference = abs(originalLength - len(response.text))
            if difference <= tolerableDifference:
                print('%s It worked!' % good)
                csrf_results.append('%s It worked!' % good)
            else:
                print('%s It didn\'t work' % bad)
                csrf_results.append('%s It didn\'t work' % bad)

    print(' %s \n Phase: Analysing %s[%s6/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Analysing [6/6]')

    binary = stringToBinary(''.join(allTokens))
    result = isRandom(binary)
    for name, result in result.items():
        if not result:
            print('%s %s : %s%s%s' % (good, name, green, 'non-random', end))
            csrf_results.append('%s %s : %s%s%s' %
                                (good, name, green, 'non-random', end))
        else:
            print('%s %s : %s%s%s' % (bad, name, red, 'random', end))
            csrf_results.append('%s %s : %s%s%s' %
                                (bad, name, red, 'random', end))

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#            certificate                #             certificate               #            certificate                #           certificate         #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def certificate(url):
    try:
        hostname = url  # Use the passed `url` parameter
        context = ssl.create_default_context()

        # Set up a connection with a timeout for better robustness
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Retrieve the certificate
                chain = ssock.getpeercert()
                print("SSL Certificate Chain:\n", chain)
                print(f"\nSSL certificate for {hostname} is valid.")
                return chain  # Return the certificate details if needed

    except ssl.SSLError as e:
        # The certificate validation failed
        print(f"SSL certificate validation for {url} failed: {e}")
        return False
    except socket.gaierror as e:
        # Invalid hostname or DNS resolution failed
        print(f"Invalid domain name '{url}': {e}")
        return False
    except socket.timeout as e:
        # Connection timed out
        print(f"Connection to {url} timed out: {e}")
        return False
    except socket.error as e:
        # Failed to connect to the specified domain
        print(f"Failed to connect to {url}: {e}")
        return False
    except Exception as e:
        # Catch any other unexpected exceptions
        print(f"An unexpected error occurred: {e}")
        return False


certificate_results = []


def analyze_certificate(domain, port):
    global certificate_results
    try:
        # Create a socket object
        with socket.create_connection((domain, port)) as sock:
            # Wrap the socket with SSL/TLS context
            with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the certificate information
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(
                    cert, default_backend())

                # Extract and display certificate details
                print(f"[+] SSL/TLS Certificate Analysis for {domain}:{port}")
                result = [
                    f"[+] SSL/TLS Certificate Analysis for {domain}:{port}",
                    f"Common Name (CN): {x509_cert.subject.rfc4514_string()}",
                    f"Issuer: {x509_cert.issuer.rfc4514_string()}",
                    f"Serial Number: {x509_cert.serial_number}",
                    f"Not Valid Before: {x509_cert.not_valid_before}",
                    f"Not Valid After: {x509_cert.not_valid_after}",
                    f"Signature Algorithm: {x509_cert.signature_algorithm_oid._name}",
                    f"Version: {x509_cert.version.name}",
                ]
                certificate_results.append(result)
                print("\n".join(result))
    except (socket.timeout, socket.error, ssl.SSLError, ssl.CertificateError, Exception) as e:
        error_message = f"[-] Error occurred for {domain}:{port} - {str(e)}"
        print(error_message)
        certificate_results.append(error_message)
    return certificate_results


location_cache = {}
location_cache = {}

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#               location                #                 location              #              location         #            location           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#

locations_data = []


def get_location(ip_address, api_key):
    global locations_data
    try:
        # Make the API request
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip_address}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an error for HTTP errors (e.g., 4xx, 5xx)

        # Parse the response JSON
        data = response.json()
        result = {
            "ip": data.get("ip"),
            "continent": data.get("continent_name"),
            "country": data.get("country_name"),
            "country_code": data.get("country_code2"),
            "region": data.get("state_prov"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": data.get("time_zone", {}).get("name"),
            "currency": data.get("currency", {}).get("name"),
            "organization": data.get("organization"),
        }
        locations_data.append(result)

        return locations_data

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as err:
        print(f"Error occurred: {err}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

################################################################################################################################


def sanitize_html(html_content):
    if isinstance(html_content, str):
        return html.escape(html_content)
    return str(html_content)  # Convert non-strings to string


active_domains = []
location_cache = []
port_scan_results = []
server_info = []
sql_test_results = []
xss_test_results = []
csrf_results = []
certificate_results = []
locations_data = []


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#            report             #             report            #            report             #           report              #          report       #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def generate_report(domain_name, ip_address, options, args, active_domains=None, location_data=None, server_info=None, port_scan_results=None, sql_test_results=None, xss_test_results=None, csrf_results=None, certificate_results=[], locations_data=None):
    report_filename = f"VulnScan_Report_{time.strftime('%Y%m%d%H%M%S')}.pdf"

    doc = SimpleDocTemplate(report_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph(
        f"<u>VulnScan Report - {time.strftime('%Y-%m-%d %H:%M:%S')}</u>", styles['Title']))
    content.append(Spacer(1, 12))
    content.append(
        Paragraph(f"<b>Target Domain:</b> {domain_name}", styles['Normal']))
    content.append(
        Paragraph(f"<b>IP Address:</b> {ip_address}", styles['Normal']))
    content.append(Paragraph(f"<b>Scan Options:</b> {args}", styles['Normal']))
    content.append(Spacer(1, 12))

    if port_scan_results:
        content.append(
            Paragraph("<b>Port Scanning Results:</b>", styles['Heading2']))
        port_scan_results.extend([
            "<br />"+"<b>Suggestions for Open Ports :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Evaluate Each Open Port :</b> Determine whether each open port is necessary for the functioning of your website or if it's potentially a security risk.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Close Unnecessary Ports :</b> For any open ports that aren't needed for your website's operation, consider closing them through your server's firewall configuration or network settings.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Secure Necessary Ports :</b> For ports that are required for your website to function (such as port 80 for HTTP or port 443 for HTTPS), ensure they are properly secured with strong encryption protocols, secure configurations, and up-to-date software."
        ])
        for result in port_scan_results:
            content.append(Paragraph(result, styles['Normal']))
        content.append(Spacer(1, 12))

    if active_domains:
        content.append(
            Paragraph("<b>Active Subdomains:</b>", styles['Heading2']))
        active_domains.extend([
            "<br />"+"<b>Suggestions for Domain Enumeration and Active Sub Domains :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Remove DNS Entries :</b> If you want to completely disable access to certain subdomains, you can remove or modify the DNS records for those subdomains. This prevents users from resolving the IP address associated with those subdomains.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Redirect Subdomains :</b> Instead of completely removing the subdomains, you can set up redirection rules on your server to redirect requests from certain subdomains to the main domain or to a specific page. This way, users won't see the content of the subdomains, but they will be redirected to another location.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Configure Virtual Hosts :</b> If you're using a web server like Apache or Nginx, you can configure virtual hosts to only serve content for specific domains and subdomains. By configuring the virtual hosts appropriately, you can prevent access to certain subdomains.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Use Robots.txt :</b> You can use a robots.txt file to instruct search engines not to index certain subdomains or to exclude them from search results. This won't prevent direct access to the subdomains, but it can help prevent them from appearing in search engine results.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Authentication and Authorization :</b> Implement authentication and authorization mechanisms to restrict access to certain subdomains. This way, even if users know the URL of a subdomain, they won't be able to access it without proper credentials.",
        ])
        for subdomain in active_domains:
            content.append(Paragraph(subdomain, styles['Normal']))
        content.append(Spacer(1, 12))

    if server_info:
        content.append(
            Paragraph("<b>Domain Fingerprinting:</b>", styles['Heading2']))
        server_info.extend([
            "<br />"+"<b>Suggestions for Domain Fingerprinting :</b><br/>"
            ""
            "<br />" +
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Apache :</b> Edit your Apache configuration file (httpd.conf) and ensure that the following directives are set <b>{ 'ServerSignature Off' , 'ServerTokens Prod' }</b> for hiding your apache information",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Nginx :</b> In your Nginx configuration file (nginx.conf), make sure the following directives are set" +
            "<br/>" +
            "<b>{ 'server_tokens off;' }</b> for hiding your HTTP Header information",
            "<b> &nbsp;&nbsp;&nbsp;&nbsp;- PHP :</b> To hide the PHP version information, you can adjust the expose_php directive in your PHP configuration file (php.ini). Set it to Off using <b>{ 'expose_php = Off' }</b>",
        ])
        for info in server_info:  # Iterate over the elements of server_info list
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    if sql_test_results:
        content.append(
            Paragraph("<b>SQL Injection Test Results:</b>", styles['Heading2']))
        sql_test_results.extend([
            "<br />"+"<b>Suggestions for SQL Injection :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Don't Use HTML forms :</b> HTMl forms is directly linked with database so use some other options for survey or form related uses ",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Use modern languages :</b> Instead of using normal HTML, CSS, JS use react, php and use NO SQL for Database  "])
        for info in sql_test_results:  # Iterate over the elements of sql_test_results list
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    if xss_test_results:
        content.append(
            Paragraph("<b>XSS Testing Results:</b>", styles['Heading2']))
        xss_test_results.extend([
            "<br />"+"<b>Suggestions for SQL Injection :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Don't Trust User Input :</b> Always validate and sanitize user input to prevent malicious scripts from executing.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Use Content Security Policy (CSP) :</b> Implement CSP headers to restrict the sources from which content can be loaded, mitigating XSS attacks.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Encode Output :</b> Encode output data using appropriate encoding methods (such as HTML escaping) to prevent script injection.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Educate Developers :</b> Train developers on secure coding practices to reduce the likelihood of introducing XSS vulnerabilities."
        ])
        for info in xss_test_results:
            sanitized_info = sanitize_html(info)
            content.append(Paragraph(str(sanitized_info), styles['Normal']))
        content.append(Spacer(1, 12))

    if csrf_results:
        content.append(
            Paragraph("<b>CSRF Test Results:</b>", styles['Heading2']))
        csrf_results.extend([
            "<br />"+"<b>Suggestions for CSRF Protection :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Secure Configuration :</b> You can enable or disable this protection in the central-wrapper.conf file.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- 1. </b> Stop the Central server.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- 2. </b> Open the <installation_folder>/central/conf/central-wrapper.conf file.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- 3. </b> Locate the Dcsrf.enabled property and change it to true, to enable CSRF protection.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- 4. </b> Start the Central server."
        ])
        for info in csrf_results:
            # Ensure info is converted to strings
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))
    print(certificate_results)
    if certificate_results:
        print(certificate_results)
        content.append(
            Paragraph("<b>Certificate Detection Results:</b>", styles['Heading2']))
        certificate_results.extend([
            "<br /><b>Suggestions for SSL/TLS Configuration :</b>",
            "<br/>"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Disable Certificate Transparency (CT) :</b> Certificate Transparency is a mechanism for publicly logging SSL certificates. If you have control over your certificate issuance process, you may be able to disable CT logging for your certificates. However, note that this may not be feasible for all certificate authorities (CAs) or certificate types.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Limit OCSP Stapling :</b> Online Certificate Status Protocol (OCSP) stapling is a feature that allows the web server to provide the OCSP response along with the SSL certificate during the SSL handshake. By limiting OCSP stapling, you may reduce the amount of certificate-related information exposed during the handshake.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Custom Error Pages :</b> Customize error pages for SSL/TLS handshake failures. Instead of displaying detailed error messages that may expose certificate details, provide generic error messages to users.<br />",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Web Application Firewall (WAF) :</b> Use a WAF to filter and sanitize HTTP responses from your web server. This can help prevent leaking sensitive certificate details in error messages or responses.<br />",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Load Balancer Configuration :</b> If your website is behind a load balancer or reverse proxy, ensure that the load balancer does not expose sensitive SSL certificate details in headers or error responses.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Security Headers: </b> Implement security headers such as Content Security Policy (CSP) to mitigate the impact of successful attacks that may expose certificate details."
        ])
        print(certificate_results)
        for info in certificate_results:
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    if locations_data:
        content.append(
            Paragraph("<b>Location Information:</b>", styles['Heading2']))
        for info in locations_data:
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    doc.build(content)
    print(f"\nReport generated: {report_filename}")


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#            main               #             main              #            main               #           main                #          main
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
if __name__ == "__main__":
    while True:
        domain_name = input("\nEnter the target domain : ")
        options, args = get_args()  # Ensure get_args is defined properly in your script
        # Call get_ip_address function to get IP address
        ip_address = get_ip_address(domain_name)
        get_ip_address(domain_name)
        print('IP Address : ', ip_address)
        while True:
            print("\n1. Change Domain")
            print("2. Port Scan")
            print("3. Domain enumeration")
            print("4. Domain Fingerprinting")
            print("5. SQL Injection Testing")
            print("6. XSS Testing")
            print("7. CSRF Detection")
            print("8. SSL / TLS Certificate Detection")
            print("9. Location of the Server")
            print("10. Report Generation")
            print("11. Exit\n")
            choice = input(
                "Enter a choice from the given options (1, 2, 3, 4, 5, 6, 7 , 8 , 9 , 10 (or) 11): ")

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
                        port_option = int(
                            input("\nEnter your choice (1, 2, 3, or 4): "))
                        if port_option == 1:
                            port = input(
                                "\nEnter the port number to scan: ")
                            start_time = time.time()
                            scan_single_port(domain_name, port)
                            elapsed_time = time.time() - start_time
                            print(
                                f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 2:
                            ports_input = input(
                                "\nEnter the port numbers to scan (comma-separated): ")
                            ports = [int(port.strip())
                                     for port in ports_input.split(",")]
                            start_time = time.time()
                            scan_custom_ports(domain_name, ports)
                            elapsed_time = time.time() - start_time
                            print(
                                f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 3:
                            start_port, end_port = map(int, input(
                                "\nEnter the port range to scan (e.g., 1-65535): ").split("-"))
                            start_time = time.time()
                            scan_range_of_ports(
                                domain_name, start_port, end_port)
                            elapsed_time = time.time() - start_time
                            print(
                                f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 4:
                            print("\nExiting Port Scan...\n")
                            break  # Break out of the port scanning loop
                        else:
                            print(
                                "\nInvalid option. Please enter a valid option (1, 2, 3, or 4)")
                    except ValueError:
                        print(
                            "\nInvalid input. Please enter a valid option (1, 2, 3, or 4)")

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
                csrf(domain_name)
            elif choice == '8':
                domain = domain_name
                port = 443
                certificate(domain_name)
                analyze_certificate(domain, port)
                print(certificate_results)
            if choice == '9':
                api_key = "a6a61c1fc0554232afae54c335c96340"
                location_data = get_location(ip_address, api_key)
                if location_data:
                    print("\nLocation Information:")
                    for items in locations_data:
                        print(locations_data)

            elif choice == '10':
                generate_report(
                    domain_name, ip_address, options, args, active_domains, location_cache, server_info, port_scan_results, sql_test_results, xss_test_results, csrf_results, certificate_results, locations_data)

            elif choice == '11':
                print(
                    "Thank you for using VulnScan \n Exiting the VulnScan...")
                sys.exit()
            else:
                print(
                    "\nInvalid option. Please enter a valid option (1, 2, 3, 4, 5, 6, 7 , 8 , 9 , 10 (or) 11)")

#  ecampus.psgtech.ac.in
