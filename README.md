# Certificate Assurance - certassurance

Based on the certificate OIDs determine the certificate assurance level DV, OV, or EV.

## Usage:
`./main.py -i <file>`

Where file is a flat ascii file with on each line a location to HTTPS. By default port 443 is used.


## Certificate Policies
To probe are the Certificate Policies on: 
* OID for DV = "2.23.140.1.2.1"
* OID for OV = "2.23.140.1.2.2"
* OID for EV = "2.23.140.1.1"


## Top 10 million websites
Source: https://www.domcop.com/top-10-million-websites


## TODO: identify QWAC certificates
