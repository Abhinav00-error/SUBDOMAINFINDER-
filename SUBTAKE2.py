import requests
import sys
import os
import dns.resolver
from termcolor import colored

def banner():
    print(colored("""
    ==============================================
       🚀 SUBDOMAIN TAKEOVER SCANNER 🚀
    ==============================================
         Created by: ABHINAV VK
    ==============================================
      WARNING: This tool is designed for ethical 
               cybersecurity testing ONLY.
      Unauthorized usage is strictly prohibited.
    ==============================================
    """, 'cyan'))

def get_domain():
    domain = input(colored("\n🌐 Enter the main domain (e.g., example.com): ", 'blue'))
    return domain

def get_subdomains():
    file_path = input(colored("📂 Enter the path to subdomains file: ", 'yellow'))
    if not os.path.exists(file_path):
        print(colored("❌ File not found!", 'red'))
        sys.exit()
    with open(file_path, 'r') as file:
        subdomains = [line.strip() for line in file.readlines()]
    return subdomains

def check_cname(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            return str(rdata.target)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        return None

def check_http_response(subdomain):
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        if response.status_code in [404, 403, 500]:
            return False
        return True
    except requests.RequestException:
        return False

def check_takeover(subdomain):
    cname_record = check_cname(subdomain)
    if cname_record:
        print(colored(f"⚠️ {subdomain} has a CNAME record pointing to {cname_record}", 'yellow'))
        vulnerable_services = ["amazonaws.com", "herokuapp.com", "github.io", "azurewebsites.net", "cloudapp.net", "fastly.net"]
        if any(service in cname_record for service in vulnerable_services) and not check_http_response(subdomain):
            print(colored(f"🚨 POTENTIAL SUBDOMAIN TAKEOVER: {subdomain} (CNAME points to {cname_record})", 'red', attrs=['bold']))
            return subdomain
    elif not check_http_response(subdomain):
        print(colored(f"⚠️ {subdomain} is inactive or down. Further investigation required.", 'yellow'))
    else:
        print(colored(f"✅ {subdomain} is active and safe.", 'green'))
    return None

def main():
    banner()
    domain = get_domain()
    subdomains = get_subdomains()
    print(colored("\n🔍 Scanning for subdomain takeover vulnerabilities...", 'cyan'))
    found_vulnerable = []
    
    for subdomain in subdomains:
        result = check_takeover(f"{subdomain}.{domain}")
        if result:
            found_vulnerable.append(result)
    
    print(colored("\n✅ Scan Complete.", 'green'))
    print(colored("==============================================", 'yellow'))
    
    if found_vulnerable:
        print(colored("\n🚨 WARNING! SUBDOMAIN TAKEOVER RISK DETECTED 🚨", 'red', attrs=['bold']))
        for sub in found_vulnerable:
            print(colored(f"⚠️ {sub}", 'red'))
        print(colored("\n🔴 Your subdomains are vulnerable to takeover! Secure them by reclaiming or removing unclaimed DNS records.", 'red', attrs=['bold']))
    else:
        print(colored("\n✅ No subdomain takeover risks found!", 'green'))
    
    print(colored("==============================================", 'yellow'))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n🔴 Scan interrupted. Displaying results...", 'red', attrs=['bold']))
