import ssl
import socket
import datetime
import os

def check_ssl_expiry(domain):
    """Check the SSL expiry date for a domain."""

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                remaining_days = (expiry_date - datetime.datetime.utcnow()).days

                if remaining_days <= 30:
                    warning = f"The SSL certificate for {domain} will expire in {remaining_days} days. Please renew the certificate."
                else:
                    warning = f"The SSL certificate for {domain} is not expiring within 30 days."

                # Export the domain and warning as environment variables
                os.environ['DOMAIN'] = domain
                os.environ['WARNING'] = warning

    except Exception as e:
        os.environ['DOMAIN'] = domain
        os.environ['WARNING'] = f"Error checking SSL certificate for {domain}: {str(e)}"

def main():
    with open("domains.txt") as f:
        for line in f:
            domain = line.strip()
            check_ssl_expiry(domain)
            print(f"Domain: {os.environ['DOMAIN']}\nWarning: {os.environ['WARNING']}")

if __name__ == "__main__":
    main()
