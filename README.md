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


## New source of all types of Policy OIDs
ZMap: https://github.com/zmap/constants/blob/master/x509/certificate_policies.csv
This list is extended with an extra column to be explicit about the assurance level.


## Certificate Policies
To probe are the Certificate Policies on: 
* ETSI
* CA/B Forum
* QWAC
* Various CAs
* Other types


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
