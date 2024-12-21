# info_gather.py
import whois
import socket
import requests
import json

# Function to get WHOIS information
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Error retrieving WHOIS data: {e}"

# Function to get DNS records for a domain
def get_dns_info(domain):
    try:
        dns_info = {}
        dns_info['A'] = socket.gethostbyname(domain)
        return dns_info
    except socket.gaierror as e:
        return f"Error resolving DNS: {e}"

# Function to get geolocation information based on IP address
def get_ip_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url)
        geolocation = response.json()
        return geolocation
    except Exception as e:
        return f"Error retrieving geolocation: {e}"

# Function to get reverse IP lookup (checking for other domains hosted on the same server)
def reverse_ip_lookup(ip):
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        response = requests.get(url)
        domains = response.text
        return domains
    except Exception as e:
        return f"Error performing reverse IP lookup: {e}"

def main():
    domain = input("Enter the domain or IP address: ")
    
    if domain:
        print(f"Gathering information for: {domain}")
        
        # WHOIS information
        whois_info = get_whois_info(domain)
        print("\nWHOIS Information:")
        print(whois_info)

        # DNS Information
        dns_info = get_dns_info(domain)
        print("\nDNS Information:")
        print(dns_info)

        # Get IP Geolocation (only for domain resolved to IP)
        try:
            ip = socket.gethostbyname(domain)
            print("\nIP Address: ", ip)
            geo_info = get_ip_geolocation(ip)
            print("\nGeolocation Info:")
            print(json.dumps(geo_info, indent=4))
        except socket.gaierror as e:
            print(f"Error resolving IP address: {e}")

        # Reverse IP lookup
        reverse_domains = reverse_ip_lookup(ip)
        print("\nReverse IP Lookup Results (other domains hosted on the same server):")
        print(reverse_domains)

if __name__ == "__main__":
    main()
