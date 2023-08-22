import ssl
import socket
import datetime

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
                    warning = f"* Domain: {domain}\n  * Warning: The SSL certificate for {domain} will expire in {remaining_days} days."
                else:
                    warning = f"* Domain: {domain}\n  * Warning: The SSL certificate for {domain} is not expiring within 30 days."

    except Exception as e:
        warning = f"* Domain: {domain}\n  * Error checking SSL certificate: {str(e)}"

    return warning

def main():
    domains = []

    with open("domains.txt") as f:
        for line in f:
            domains.append(line.strip())

    warnings = []

    for domain in domains:
        warning = check_ssl_expiry(domain)
        warnings.append(warning)

    # Join the warnings into a single Slack-formatted message
    slack_message = "\n".join(warnings)

    # Print the Slack-formatted message
    print(slack_message)

if __name__ == "__main__":
    main()
