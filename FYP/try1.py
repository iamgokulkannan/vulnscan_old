import socket
import requests
import ssl

def get_dns_records(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"[+] DNS Records for {domain}")
        print(f"IP Address: {ip_address}")
    except socket.gaierror as e:
        print(f"[-] Error resolving DNS for {domain}: {str(e)}")

def get_http_headers(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url)
        print(f"\n[+] HTTP Headers for {url}")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error retrieving HTTP headers for {domain}: {str(e)}")

def get_ssl_certificate(domain, port=443):
    try:
        with socket.create_connection((domain, port)) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = ssl.DER_cert_to_PEM_cert(cert)
                print(f"\n[+] SSL/TLS Certificate for {domain}:{port}")
                print(x509_cert)  # Remove the decode() method here
    except socket.timeout:
        print(f"[-] Connection to {domain}:{port} timed out.")
    except socket.error as e:
        print(f"[-] Error occurred while connecting to {domain}:{port}: {str(e)}")
    except ssl.SSLError as e:
        print(f"[-] SSL/TLS Error occurred: {str(e)}")


def domain_fingerprinting(domain):
    print(f"\n*** Domain Fingerprinting for {domain} ***")
    get_dns_records(domain)
    get_http_headers(domain)
    get_ssl_certificate(domain)

if __name__ == "__main__":
    domain = input("Enter the target domain: ")
    domain_fingerprinting(domain)
