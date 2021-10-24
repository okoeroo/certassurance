# Certificate Assurance - certassurance

Based on the certificate OIDs determine the certificate assurance level DV, OV, or EV.

## Usage:
`./main.py -i <file>`
Where file is a flat ascii file with on each line a location to HTTPS. By default probe port 443 is used.

`./main.py -p <port number>`
Start a service and listen on port number.

## Service example:
GET request example
`http://localhost:8080/certassurance/oscar.koeroo.net`

Reply:
`{"fqdn": "oscar.koeroo.net", "assurance": "DV"}`



## Certificate Policies
To probe are the Certificate Policies on: 
* OID for DV        = "2.23.140.1.2.1"
* OID for OV        = "2.23.140.1.2.2"
* OID for EV        = "2.23.140.1.1"
* OID for QWAC Web  = "0.4.0.194112.1.4"
* OID for PSD2 Web  = "0.4.0.19495.3.1"


## Top 10 million websites
Source: https://www.domcop.com/top-10-million-websites

## Data sets from https://basisbeveiliging.nl/#/datasets
* nl_government_urls_only_2021-10-24.list
* nl_healthcare_urls_only_2021-10-24.list
* nl_municipality_urls_only_2021-10-24.list
* nl_province_urls_only_2021-10-24.list


Notes:
http://oid-info.com/get/1.3.6.1.5.5.7.1.3
qcStatements
1.3.6.1.5.5.7.1.3
