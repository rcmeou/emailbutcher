import re                        # regular expression library to search for the IP and domain
import requests                  # requests library to make HTTP requests
import whois                     # whois library to get information about the domain
from ipwhois import IPWhois      # obtain ISP from the IP address
import dns.resolver              # dns.resolver library to get information about the domain
import socket                    # socket library to get information about the domain
from email import parser    # email.parser library to get information about the domain
import sys                       # sys library to open file as command line argument




#check if email file is imported using command line argument
if len(sys.argv) < 2:
    print("Usage: python3 emailbutcher.py filename.eml")
    sys.exit(1)

#open file as command line argument
file = open(sys.argv[1], "r")


# parse email and print out header
email_parse = parser.Parser()
email_message = email_parse.parsestr(file.read())


# Iterate a search for IP and Domain to add to a set with update preventing duplicates

#finds ip address by matching the pattern and being between 0-255 (https://uibakery.io/regex-library/ip-address-regex-python )
#finds domain based on text after the "@" symbol
ip_addr_search = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
domain_search = r'@[\w.-]+\.[a-zA-Z]{2,}'
#sets to prevent the duplicates
ip_addresses_set = set()
domains_set = set()

for header, value in email_message.items():
    ip_addresses = re.findall(ip_addr_search, str(value))
    ip_addresses_set.update(ip_addresses)
    

    domains = re.findall(domain_search, str(value))
    domains_set.update(domains)
print("\n====== IP Addresses ======")
for ip_addr in ip_addresses_set:
    print("  ", ip_addr)

#remove @ symbol in the domain set
domains_set = {domain.replace('@', '') for domain in domains_set}

print("\n====== Domains ======")
for domain in domains_set:
    print("  ", domain)

# use the IP's from the ip_addresses_set to search whois
print("\n====== Whois Domain Lookup ======")
for domain in domains_set:
    whois_info = whois.whois(domain)
    print("  Domain:", domain)
    print("    Registrar:", whois_info.registrar)
    print("    Creation Date:", whois_info.creation_date)
    print("    Expiration Date:", whois_info.expiration_date)
    print("    Name Servers:", whois_info.name_servers)
    print("    Status:", whois_info.status)
    print("    Email:", whois_info.emails)
    print("    Organization:", whois_info.org)
    print("    Address:", whois_info.address)
    print("    City:", whois_info.city)
    print("    State:", whois_info.state)
    print("    Zipcode:", whois_info.zipcode)
    print("    Country:", whois_info.country) in ip_addresses_set

print("\n====== Whois IP Lookup ======")
for ip_addr in ip_addresses_set:
    whois_info = whois.whois(ip_addr)
    print("  IP:", ip_addr)
    print("    Registrar:", whois_info.registrar)
    print("    Creation Date:", whois_info.creation_date)
    print("    Expiration Date:", whois_info.expiration_date)
    print("    Name Servers:", whois_info.name_servers)
    print("    Status:", whois_info.status)
    print("    Email:", whois_info.emails)
    print("    Organization:", whois_info.org)
    print("    Address:", whois_info.address)
    print("    City:", whois_info.city)
    print("    State:", whois_info.state)
    print("    Zipcode:", whois_info.zipcode)
    print("    Country:", whois_info.country)
