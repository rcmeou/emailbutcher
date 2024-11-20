import re                        # regular expression library to search for the IP and domain
import requests                  # requests library to make HTTP requests
import whois                     # whois library to get information about the domain
from ipwhois import IPWhois      # obtain ISP from the IP address
import dns.resolver              # dns.resolver library to get information about the domain
import socket                    # socket library to get information about the domain
from email import parser         # email.parser library to get information about the domain
import sys                       # sys library to open file as command line argument
import csv

def print_ipdomain(ip_addresses_set, domains_set):
    print("\n====== IP Addresses ======")
    for ip_addr in ip_addresses_set:
        print("  ", ip_addr)



    print("\n====== Domains ======")
    for domain in domains_set:
        print("  ", domain)

def who_is_search(domains_set, ip_addresses_set):
    # use the Domains from the domain_set to search whois
    print("\n====== Whois Domain Lookup ======")
    registrar_set = set()
    for domain in domains_set:
        whois_info = whois.whois(domain)
        print("  Domain:", domain)
        if whois_info.registrar is not None:              
            registrar_set.add(whois_info.registrar)  #adds the registrar name to a set
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
        if whois_info.registrar is not None:              
                registrar_set.add(whois_info.registrar)  #adds the registrar name to a set
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
        return registrar_set

def main():
#check if email file is imported using command line argument
    if len(sys.argv) < 2:
        print("Usage: python3 emailbutcher.py filename.eml")
        sys.exit(1)

    #open file as command line argument and store file name 
    file = open(sys.argv[1], "r")
    filename = sys.argv[1]
    filename_text = filename.replace('.eml', '.txt') #for saving output as text later

    # parse email
    email_parse = parser.Parser()
    email_message = email_parse.parsestr(file.read())

    

    #prints logo and prompts for options
    print("""     _______                  __ __      ______         __         __               
    |    ___|.--------.---.-.|__|  |    |   __ \.--.--.|  |_.----.|  |--.-----.----.
    |    ___||        |  _  ||  |  |    |   __ <|  |  ||   _|  __||     |  -__|   _|
    |_______||__|__|__|___._||__|__|    |______/|_____||____|____||__|__|_____|__|  
                                                                                    """)
    print(f"The email file being analyzed is: {filename}\n")

    # Iterate a search for IP and Domain to add to a set with the update method preventing duplicates
    #finds ip address by matching the pattern and being between 0-255 (https://uibakery.io/regex-library/ip-address-regex-python )
    #finds domain based on text after the "@" symbol
    ip_addr_search = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    domain_search = r'@([\w.-]+\.[a-zA-Z]{2,})'  #regex. finds text after @ symbol including slashes, dots, hyphens. ensures at least two letters after the last dot
                   
    
    ip_addresses_set = set()    #initialize and use sets to prevent duplicates
    domains_set = set()

    for header, value in email_message.items():
        ip_addresses = re.findall(ip_addr_search, str(value))
        ip_addresses_set.update(ip_addresses)
        

        domains = re.findall(domain_search, str(value))
        domains_set.update(domains)



    #prompt for input with while loop, asks to try again if not 1-5 and exits with 5
    choice = ""
    while choice != "5":
        print("\n==================================\n")
        print("Analysis Options:\n\n")
        print("1. Extract IP and Domains")
        print("2. IP and Domain Whois Lookup")
        print("3. ISP Lookup")
        print(f"4. Save all output as {filename_text}")
        print("5. Exit\n")
        choice = input("Enter your choice: ")
        if choice == "1":
            print_ipdomain(ip_addresses_set, domains_set)
            continue
        if choice == "2":
            if domains_set == set():
                print_ipdomain(ip_addresses_set, domains_set)
                who_is_search(domains_set, ip_addresses_set)
            else:
                who_is_search(domains_set, ip_addresses_set)
            continue
        if choice == "3":
            print("Coming Soon")
            continue
        if choice == "4":
            print("Coming Soon")
            continue
        if choice == "5":
            print("Exit")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")
            continue


if __name__ == "__main__":
    main()
