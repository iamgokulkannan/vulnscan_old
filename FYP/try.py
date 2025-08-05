import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def analyze_certificate(domain, port):
    try:
        # Create a socket object
        with socket.create_connection((domain, port)) as sock:
            # Wrap the socket with SSL/TLS context
            with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the certificate information
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                
                # Extract and display certificate details
                print(f"[+] SSL/TLS Certificate Analysis for {domain}:{port}")
                print(f"Common Name (CN): {x509_cert.subject.rfc4514_string()}")
                print(f"Issuer: {x509_cert.issuer.rfc4514_string()}")
                print(f"Serial Number: {x509_cert.serial_number}")
                print(f"Not Valid Before: {x509_cert.not_valid_before}")
                print(f"Not Valid After: {x509_cert.not_valid_after}")
                print(f"Signature Algorithm: {x509_cert.signature_algorithm_oid._name}")
                print(f"Version: {x509_cert.version.name}")
                
                # Display more detailed information as needed
                # You can access additional certificate properties here

    except socket.timeout:
        print(f"[-] Connection to {domain}:{port} timed out.")
    except socket.error as e:
        print(f"[-] Error occurred while connecting to {domain}:{port}: {str(e)}")
    except ssl.SSLError as e:
        print(f"[-] SSL/TLS Error occurred: {str(e)}")
    except x509.CertificateError as e:
        print(f"[-] Certificate Error occurred: {str(e)}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    domain = input("Enter the target domain: ")
    port = int(input("Enter the port number (e.g., 443 for HTTPS): "))

    analyze_certificate(domain, port)
