from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from core.utils import extractHeaders, strength, isProtected, stringToBinary, longestCommonSubstring
from core.requester import requester
from core.zetanize import zetanize
from core.ranger import ranger
from core.evaluate import evaluate
from core.tweaker import tweaker
from core.photon import photon
from core.prompt import prompt
from core.datanize import datanize
from core.entropy import isRandom
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import statistics
import re
import random
import json
import argparse
from core.colors import green, yellow, end, run, good, info, bad, white, red
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
from core.config import headers
import concurrent.futures
from pathlib import Path
from fuzzywuzzy import fuzz, process


def get_ip_address(target):
    ip_address = socket.gethostbyname(target)
    return ip_address


def scan_single_port(target, port):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    result = scanner.scan(ip_address, arguments=f'-p {port}')
    if result['scan'][ip_address]['tcp'][int(port)]['state'] == 'open':
        print('\033[32m' + f"\tPort {port} is open" + '\033[0m')
    else:
        print('\033[31m' + f"\tPort {port} is closed" + '\033[0m')


def scan_custom_ports(target, ports):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    scanner.scan(
        ip_address, arguments=f'-p {",".join(str(port) for port in ports)} -sT')
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
                    print('\033[32m' + f"\tPort {port} is open" + '\033[0m')
        else:
            print(
                '\033[31m' + f"\tNo open ports found in the specified range." + '\033[0m')
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
            print(
                f"\nFailed to retrieve data from {url}. Status Code: {response.status_code}")
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
                print(colorama.Fore.RED +
                      f"[!]XSS detected for payload '{payload}': {url}")
                print(colorama.Fore.YELLOW + f"[*] Form details:")
                pprint(form_details)
            else:
                print(f"\nNo XSS detected for payload '{payload}'")


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


def csrf(domain_name):
    lightning = '\033[93;5m⚡\033[0m'

    try:
        import concurrent.futures
        from pathlib import Path
    except ImportError:
        print('%s VulnScan is not compatible with python 2. Please run it with python 3.' % bad)

    try:
        from fuzzywuzzy import fuzz, process
    except ImportError:
        import os
        print('%s fuzzywuzzy library is not installed, installing now.' % info)
        os.system('pip3 install fuzzywuzzy')
        print('%s fuzzywuzzy has been installed, please restart VulnScan.' % info)
        quit()

    # Interactive input for the target domain
    target = domain_name
    target = sanitize_url(target)

    # Additional interactive input for other parameters (you can customize this part)
    delay = int(
        input('%s Enter the delay between requests (default is 0): ' % info) or 0)
    level = int(
        input('%s Enter the number of levels to crawl (default is 2): ' % info) or 2)
    timeout = int(
        input('%s Enter the HTTP request timeout (default is 20): ' % info) or 20)
    threadCount = int(
        input('%s Enter the number of threads (default is 2): ' % info) or 2)

    # Prompt for headers interactively
    headers_input = input(
        '%s Do you want to enter custom HTTP headers? (y/n): ' % info).lower()
    if headers_input == 'y':
        headers = extractHeaders(prompt())
    else:
        from core.config import headers

    allTokens = []
    weakTokens = []
    tokenDatabase = []
    insecureForms = []

    print(' %s \n Phase: Crawling %s[%s1/6%s]%s' %
          (lightning, green, end, green, end))
    dataset = photon(target, headers, level, threadCount)
    allForms = dataset[0]
    for url_dict in allForms:
        for url, _ in url_dict.items():
            print(url)
    print('\r%s Crawled %i URL(s) and found %i form(s).%-10s' %
          (info, dataset[1], len(allForms), ' '))
    print(' %s \n Phase: Evaluating %s[%s2/6%s]%s' %
          (lightning, green, end, green, end))

    evaluate(allForms, weakTokens, tokenDatabase, allTokens, insecureForms)

    if weakTokens:
        print('%s Weak token(s) found' % good)
        for weakToken in weakTokens:
            url = list(weakToken.keys())[0]
            token = list(weakToken.values())[0]
            print('%s %s %s' % (info, url, token))

    if insecureForms:
        print('%s Insecure form(s) found' % good)
        for insecureForm in insecureForms:
            url = list(insecureForm.keys())[0]
            action = list(insecureForm.values())[0]['action']
            form = action.replace(target, '')
            if form:
                print('%s %s %s[%s%s%s]%s' %
                      (bad, url, green, end, form, green, end))

    print(' %s \n Phase: Comparing %s[%s3/6%s]%s' %
          (lightning, green, end, green, end))

    uniqueTokens = set(allTokens)
    if len(uniqueTokens) < len(allTokens):
        print('%s Potential Replay Attack condition found' % good)
        print('%s Verifying and looking for the cause' % run)
        replay = False
        for each in tokenDatabase:
            url, token = next(iter(each.keys())), next(iter(each.values()))
            for each2 in tokenDatabase:
                url2, token2 = next(iter(each2.keys())), next(
                    iter(each2.values()))
                if token == token2 and url != url2:
                    print('%s The same token was used on %s%s%s and %s%s%s' %
                          (good, green, url, end, green, url2, end))
                    replay = True
        if not replay:
            print('%s Further investigation shows that it was a false positive.')

    p = Path(__file__).parent.joinpath('db/hashes.json')
    with p.open('r') as f:
        hashPatterns = json.load(f)

    if not allTokens:
        print('%s No CSRF protection to test, NO CSRF TOKENS AVAILABLE' % bad)
        return

    print("Length of allTokens:", len(allTokens))
    if len(allTokens) > 0:
        print("Length of first sublist in allTokens:", len(allTokens[0]))
    else:
        print("Error: allTokens is empty.")
        return

    if len(allTokens[0]) == 0:
        print("Error: First sublist in allTokens is empty.")
        return

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
                for name in matches:
                    print('    %s>%s %s' % (yellow, end, name))

            def fuzzy(tokens):
                averages = []
                for token in tokens:
                    sameTokenRemoved = False
                    result = process.extract(
                        token, tokens, scorer=fuzz.partial_ratio)
                    scores = []
                    for each in result:
                        score = each[1]
                        if score == 100 and not sameTokenRemoved:
                            sameTokenRemoved = True
                            continue
                        scores.append(score)
                    average = statistics.mean(scores)
                    averages.append(average)
                return statistics.mean(averages)

            try:
                similarity = fuzzy(allTokens)
                print('%s Tokens are %s%i%%%s similar to each other on average' %
                      (info, green, similarity, end))
            except statistics.StatisticsError:
                print(
                    '%s No CSRF protection to test, CSRF vulnerability not found' % bad)

        else:
            print("The first element of allTokens is an empty list.")
    else:
        print("No CSRF tokens available.")

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
        print(json.dumps(result, indent=4))

    simTokens = []

    print(' %s \n Phase: Observing %s[%s4/6%s]%s' %
          (lightning, green, end, green, end))
    print('%s 100 simultaneous requests are being made, please wait.' % info)

    def extractForms(url):
        response = requester(url, {}, headers, True, 0).text
        forms = zetanize(url, response)
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
        sample = random.choice(tokenDatabase)
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
    else:
        print("No valid goodCandidate found.")

    if simTokens:
        if len(set(simTokens)) < len(simTokens):
            print('%s Same tokens were issued for simultaneous requests.' % good)
        else:
            print(simTokens)
    else:
        print('%s Different tokens were issued for simultaneous requests.' % info)

    print(' %s \n Phase: Testing %s[%s5/6%s]%s' %
          (lightning, green, end, green, end))

    parsed = ''
    found = False
    print('%s Finding a suitable form for further testing. It may take a while.' % run)
    for form_dict in allForms:
        for url, forms in form_dict.items():
            parsed = datanize(forms, tolerate=True)
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
    response = requester(origUrl, origData, headers, origGET, 0)
    originalCode = response.status_code
    originalLength = len(response.text)
    print('%s Status Code: %s' % (info, originalCode))
    print('%s Content Length: %i' % (info, originalLength))
    print('%s Checking if the resonse is dynamic.' % run)
    response = requester(origUrl, origData, headers, origGET, 0)
    secondLength = len(response.text)
    if originalLength != secondLength:
        print('%s Response is dynamic.' % info)
        tolerableDifference = abs(originalLength - secondLength)
    else:
        print('%s Response isn\'t dynamic.' % info)
        tolerableDifference = 0

    print('%s Emulating a mobile browser' % run)
    print('%s Making a request with mobile browser' % run)
    headers['User-Agent'] = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows CE; PPC; 240x320)'
    response = requester(origUrl, {}, headers, True, 0).text
    parsed = zetanize(origUrl, response)
    if isProtected(parsed):
        print('%s CSRF protection is enabled for mobile browsers as well.' % bad)
    else:
        print('%s CSRF protection isn\'t enabled for mobile browsers.' % good)

    print('%s Making a request without CSRF token parameter.' % run)

    data = tweaker(origData, 'remove')
    response = requester(origUrl, data, headers, origGET, 0)
    if response.status_code == originalCode:
        if str(originalCode)[0] in ['4', '5']:
            print('%s It didn\'t work' % bad)
        else:
            difference = abs(originalLength - len(response.text))
            if difference <= tolerableDifference:
                print('%s It worked!' % good)
    else:
        print('%s It didn\'t work' % bad)

    print('%s Making a request without CSRF token parameter value.' % run)
    data = tweaker(origData, 'clear')

    response = requester(origUrl, data, headers, origGET, 0)
    if response.status_code == originalCode:
        if str(originalCode)[0] in ['4', '5']:
            print('%s It didn\'t work' % bad)
        else:
            difference = abs(originalLength - len(response.text))
            if difference <= tolerableDifference:
                print('%s It worked!' % good)
    else:
        print('%s It didn\'t work' % bad)

    seeds = ranger(allTokens)

    print('%s Checking if tokens are checked to a specific length' % run)

    for index in range(len(allTokens[0])):
        data = tweaker(origData, 'replace', index=index, seeds=seeds)
        response = requester(origUrl, data, headers, origGET, 0)
        if response.status_code == originalCode:
            if str(originalCode)[0] in ['4', '5']:
                break
            else:
                difference = abs(originalLength - len(response.text))
                if difference <= tolerableDifference:
                    print('%s Last %i chars of token aren\'t being checked' %
                          (good, index + 1))
        else:
            break

    print('%s Generating a fake token.' % run)

    data = tweaker(origData, 'generate', seeds=seeds)
    print('%s Making a request with the self generated token.' % run)

    response = requester(origUrl, data, headers, origGET, 0)
    if response.status_code == originalCode:
        if str(originalCode)[0] in ['4', '5']:
            print('%s It didn\'t work' % bad)
        else:
            difference = abs(originalLength - len(response.text))
            if difference <= tolerableDifference:
                print('%s It worked!' % good)
    else:
        print('%s It didn\'t work' % bad)

    print(' %s \n Phase: Analysing %s[%s6/6%s]%s' %
          (lightning, green, end, green, end))

    binary = stringToBinary(''.join(allTokens))
    result = isRandom(binary)
    for name, result in result.items():
        if not result:
            print('%s %s : %s%s%s' % (good, name, green, 'non-random', end))
        else:
            print('%s %s : %s%s%s' % (bad, name, red, 'random', end))


def certificate(url):
    try:
        hostname = domain_name
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                chain = ssock.getpeercert()
                print(chain)
                print("\n")
                print(f"SSL certificate for {domain_name} is valid.")
    except ssl.SSLError as e:
        # The certificate validation failed
        print(f"SSL certificate validation for {domain_name} failed: {e}")
        return False
    except socket.error as e:
        # Failed to connect to the specified domain
        print(f"Failed to connect to {domain_name}: {e}")
        return False


def analyze_certificate(domain, port):
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
                print(
                    f"\n[+] SSL/TLS Certificate Analysis for {domain}:{port}")
                print(
                    f"Common Name (CN): {x509_cert.subject.rfc4514_string()}")
                print(f"Issuer: {x509_cert.issuer.rfc4514_string()}")
                print(f"Serial Number: {x509_cert.serial_number}")
                print(
                    f"Issue Date / Renewal Date: {x509_cert.not_valid_before}")
                print(f"Not Valid After: {x509_cert.not_valid_after}")
                print(
                    f"Signature Algorithm: {x509_cert.signature_algorithm_oid._name}")
                print(f"Version: {x509_cert.version.name}")

                # Display more detailed information as needed
                # You can access additional certificate properties here

    except socket.timeout:
        print(f"[-] Connection to {domain}:{port} timed out.")
    except socket.error as e:
        print(
            f"[-] Error occurred while connecting to {domain}:{port}: {str(e)}")
    except ssl.SSLError as e:
        print(f"[-] SSL/TLS Error occurred: {str(e)}")
    except x509.CertificateError as e:
        print(f"[-] Certificate Error occurred: {str(e)}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {str(e)}")


location_cache = {}
location_cache = {}


def get_location(ip_address):
    if ip_address in location_cache:
        return location_cache[ip_address]

    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/')
        response.raise_for_status()
        data = response.json()
        location_data = {
            "ip": ip_address,
            "network": data.get("network"),
            "version": data.get("version"),
            "city": data.get("city"),
            "region": data.get("region"),
            "region_code": data.get("region_code"),
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "country_code_iso3": data.get("country_code_iso3"),
            "country_capital": data.get("country_capital"),
            "country_tld": data.get("country_tld"),
            "continent_code": data.get("continent_code"),
            "in_eu": data.get("in_eu"),
            "postal": data.get("postal"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": data.get("timezone"),
            "utc_offset": data.get("utc_offset"),
            "country_calling_code": data.get("country_calling_code"),
            "currency": data.get("currency"),
            "currency_name": data.get("currency_name"),
            "languages": data.get("languages"),
            "country_area": data.get("country_area"),
            "country_population": data.get("country_population"),
            "asn": data.get("asn"),
            "org": data.get("org")
        }
        # Cache the result for future use
        location_cache[ip_address] = location_data
        return location_data
    except requests.exceptions.RequestException as e:
        print(f"Click on this link for better reference --> " +
              f'https://ipapi.co/{ip_address}/json/')
        return None
    finally:
        # Introduce a delay between requests (adjust the time.sleep value based on rate limits)
        time.sleep(5)  # Example: wait for 1 second between requests


if __name__ == "__main__":
    while True:
        domain_name = input("\nEnter the target domain : ")
        options, args = get_args()
        ip_address = socket.gethostbyname(domain_name)
        print(f"\nIP Address: {ip_address}")
        while True:
            print("\n1. Change Domain")
            print("2. Port Scan")
            print("3. Domain Enumeration (Subdomain Scanning)")
            print("4. Domain Fingerprinting (Domain Information)")
            print("5. SQL Injection Testing")
            print("6. XSS Testing")
            print("7. CSRF Detection")
            print("8. SSL / TLS Certificate Detection")
            print("9. Location of the Server")
            print("10. Exit\n")
            choice = input(
                "Enter a choice from the given options (1, 2, 3, 4, 5, 6, 7 , 8 , 9 or 10): ")

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
                            input("\nEnter your choice (1, 2, 3, or 4) for scanning the ports: "))
                        if port_option == 1:
                            port = input("\nEnter the port number to scan: ")
                            start_time = time.time()
                            scan_single_port(domain_name, port)
                            elapsed_time = time.time() - start_time
                            print(f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 2:
                            ports_input = input(
                                "\nEnter the port numbers to scan (comma-separated): ")
                            ports = [int(port.strip())
                                     for port in ports_input.split(",")]
                            start_time = time.time()
                            scan_custom_ports(domain_name, ports)
                            elapsed_time = time.time() - start_time
                            print(f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 3:
                            start_port, end_port = map(int, input(
                                "\nEnter the port range to scan (e.g., 1-65535): ").split("-"))
                            start_time = time.time()
                            scan_range_of_ports(
                                domain_name, start_port, end_port)
                            elapsed_time = time.time() - start_time
                            print(f"Elapsed time: {elapsed_time:.2f} seconds")
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
                port = int(
                    input("Enter the port number (e.g., 443 for HTTPS): "))
                certificate(domain_name)
                analyze_certificate(domain, port)
            if choice == '9':
                location_data = get_location(ip_address)
                if location_data:
                    print("\nLocation Information:")
                    for key, value in location_data.items():
                        print(f"{key}: {value}")
            elif choice == '10':
                print("Thank you for using VulnScan \n Exiting the script...")
                sys.exit()
            else:
                print(
                    "\nInvalid option. Please enter a valid option (1, 2, 3, 4, 5, 6, 7 , 8 , 9 or 10)")
