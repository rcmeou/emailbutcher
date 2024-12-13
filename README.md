
# Email Butcher

Python script that parses a downloaded email's header for IP and domain names. It then uses OSINT tools to search for related information, the ISP, and contact details for the ISP. This simplifies the process in locating information necessary to contact an ISP for legal processes.


## Pre-requisites

### Registrar.csv  

CSV file must be in the same directory as the script

### Python & PIP

> sudo apt install python3 python3-pip

### PythonWhois

> pip install pythonwhois

## Deployment

#### Place *.eml file in the same directory as emailbutcher.py

> python emailbutcher.py *.eml
