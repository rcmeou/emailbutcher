import re                               # regular expression library to search for the IP and domain
import whois                            # whois library to get information about the domain
from ipwhois import IPWhois             # ipwhois library to get information about the IP address
from ipwhois.exceptions import IPDefinedError  
from email import parser                # email.parser library to get information about the domain
import sys                              # sys library to open file as command line argument
import csv                              # open csv and search for matching registrar and print out details
from difflib import get_close_matches   # needed a better way to search, this will find the closest match
registrar_set = set()                   #initialize this set as it's used to see if whois has been searched yet



def print_ipdomain(ip_addresses_set, domains_set):
    print("\n====== IP Addresses ======")
    for ip_addr in ip_addresses_set:
        print("  ", ip_addr)



    print("\n====== Domains ======")
    for domain in domains_set:
        print("  ", domain)


def who_is_search(domains_set, ip_addresses_set):        # use the Domains from the domain_set to search whois
    global registrar_set
    if registrar_set:                   # checks registrar_set and if it's already been populated it returns
        return registrar_set            # and skips the the rest of the function so whois is not queried again
    registrar_set = set()
    for domain in domains_set:
        try:
            whois_info = whois.whois(domain)
            if whois_info.registrar is not None:
                registrar_set.add(whois_info.registrar)  #adds the registrar name to a set
        except whois.parser.PywhoisError:
            pass # Simply skip domains that cause this error
    pass



    for ip_addr in ip_addresses_set:
        whois_info = whois.whois(ip_addr)

        if whois_info.registrar is not None:              
                registrar_set.add(whois_info.registrar)  #adds the registrar name to a set

        return registrar_set

def who_is_print(domains_set, ip_addresses_set):
    global registrar_set
    if registrar_set == set():
        registrar_set = who_is_search(domains_set, ip_addresses_set) # this will run the who_is_search function if it hasn't been done (for saving to txt)
    for ip_addr in ip_addresses_set:
        try:
            ipwhois_info = IPWhois(ip_addr)
            ipwhois_info = ipwhois_info.lookup_rdap()
            print("\n====== Whois IP Lookup ======")
            print("  IP:", ip_addr)
            print("    Network Name:", ipwhois_info.get('network', {}).get('name'))
            print("    CIDR:", ipwhois_info.get('network', {}).get('cidr'))
            print("    Country:", ipwhois_info.get('network', {}).get('country'))
            print("    ASN:", ipwhois_info.get('asn'))
            print("    ASN Description:", ipwhois_info.get('asn_description'))
        except IPDefinedError:
            print(f"Error: Unable to perform WHOIS lookup for {ip_addr}")
            pass
    for domain in domains_set:
        try:
            whois_info = whois.whois(domain)
            print("\n====== Whois Domain Lookup ======")
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
            print("    Country:", whois_info.country) in domains_set
        except whois.parser.PywhoisError:
            print("\nNothing returned from WHOIS for that Domain")
            pass

def csv_search(registrar_set):
    # Open the CSV file and make it a reader object (part of the csv module)
    with open('registrar.csv', 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        csv_registrars = []
        
        rows = list(reader)  # Store all rows
        csv_registrars = [row[0] for row in rows]  # Get first column of each row

        for registrar in registrar_set:
            closest_matches = get_close_matches(registrar, csv_registrars, n=1, cutoff=0.6) #similarity threshold 0-1 with 1 requiring the highest similarity

            if closest_matches:
                for row in rows:
                    if row[0] == closest_matches[0]:                                    
                        if registrar == "MarkMonitor, Inc.":   # Skip if the registrar is MarkMonitor, Inc.
                            continue
                        print("===============================\n\nRegistrar searched: ", registrar)
                        print("Closest Match:      ", closest_matches[0])
                        print("===============================\n\n")
                        # Remove the outer for loop here - it was causing the duplicate prints
                        for detail in row:
                            print(detail)
                        break  # Add this to exit after finding the match
    
    print("\n====== Registrars Found in Email ======")
    for registrar in registrar_set:
        print("  ", registrar)
    print("\n This tool is not always accurate, ensure the Registrar/ISP name matches the results")    
    print(" Check search.org for matches if you have no returns for a registrar/ISP")    
    print("\n\n\n\n\n               *************\n               Registrar/ISP Information current as of 11/18/2024\n               Please verify information on search.org\n               *************")

def save_text(filename_text, ip_addresses_set, domains_set):
    global registrar_set
    print("Be patient, can take up to a minute depending on how many registrars/ISP's are found")
    original_stdout = sys.stdout
    with open(filename_text, 'w') as file:
        sys.stdout = file
        print_ipdomain(ip_addresses_set, domains_set)
        who_is_print(domains_set, ip_addresses_set)
        csv_search(registrar_set)
        sys.stdout = original_stdout
    print(f"\nOutput saved to {filename_text}")


def main():
    global registrar_set
    #check if email file is imported using command line argument
    if len(sys.argv) < 2:
        print("Usage: python3 emailbutcher.py filename.eml")
        sys.exit(1)

    #open file as command line argument and store file name 
    file = open(sys.argv[1], "r", encoding='utf-8', errors='ignore')
    filename = sys.argv[1]
    filename_text = filename.replace('.eml', '.txt') #for saving output as text later
    temp_text = []    # list to store all printed text that can be saved to a text file. prevents running all of the functions again

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
    ip_addr_search = r'(?<=\s)(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)(?!\d)'
    domain_search = r'@(?:[a-zA-Z0-9-]+\.)*([a-zA-Z0-9-]+\.[a-zA-Z]{2,3})(?:\s|$|[^\w.-])'  #regex. finds text after @ symbol including slashes, dots, hyphens. ensures at least two letters after the last dot
                   
    
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
                who_is_print(domains_set, ip_addresses_set)
            else:
                who_is_print(domains_set, ip_addresses_set)
            continue
        if choice == "3":
            if registrar_set == set():
                registrar_set = who_is_search(domains_set, ip_addresses_set)
                csv_search(registrar_set)
            else:
                csv_search(registrar_set)
            continue
        if choice == "4":
            save_text(filename_text, ip_addresses_set, domains_set)
            continue
        if choice == "5":
            print("Exit")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")
            continue


if __name__ == "__main__":
    main()









