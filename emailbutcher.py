import re                        # regular expression library to search for the IP and domain
import requests                  # requests library to make HTTP requests
import whois                     # whois library to get information about the domain
import dns.resolver              # dns.resolver library to get information about the domain
import socket                    # socket library to get information about the domain
from email import parser   # email.parser library to get information about the domain
import sys                       # sys library to open file as command line argument

SHODAN_API = "PUT API KEY HERE"


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

for ip_addr in ip_addresses_set:
    print("IP Address: ", ip_addr)

for domain in domains_set:
    print("Domain: ", domain)