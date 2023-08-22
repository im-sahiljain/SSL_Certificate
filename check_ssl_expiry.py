import requests
import certifi

def check_ssl_expiry(domain):
  """Check the SSL expiry date for a domain."""

  cert = requests.get(f"https://{domain}:443/", verify=certifi.where())
  cert_info = cert.json()
  expiry_date = cert_info["notAfter"]
  remaining_days = (expiry_date - datetime.datetime.utcnow()).days

  if remaining_days <= 30:
    return f"{domain} will expire in {remaining_days} days."
  else:
    return f"{domain} is not expiring within 30 days."

def main():
  domains = ["example.com", "another-example.com"]
  for domain in domains:
    warning = check_ssl_expiry(domain)
    print(warning)

if __name__ == "__main__":
  main()
