import requests
import json
from urlextract import URLExtract
import csv

LINK = "https://cvetrends.com/api/cves/24hrs"
NVD = "https://nvd.nist.gov/vuln/detail/"
#library for URL extraction
extractor = URLExtract
#extract response from link
html = requests.get(LINK).text
#make it into python dictionary format
data = json.loads(html)

#create CSV file w all access to read and write
file = open("CVEVulnTracker.csv","w", newline="")
writer = csv.writer(file)
#state titles one first row
#title = ["CVE","Date Published","Last Modified","NVD link", "Does It Work?"]
#writer.writerow(title)

#for loops for each data in columns CVEs in site and extract their data
#when comma seperate list, it will seperate cells
for cve in data['data']:
    link_data = []
    LINKCVE = []
    # append CVE to link for NVD API for info
    LINKCVE.append(("https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve['cve'] + "?addOns=dictionaryCpes"))
    #for loop will check for description data
    for LINK in LINKCVE:
        NVD_DATA = requests.get(LINK).text
        database = json.loads(NVD_DATA)

        try:
            result = database['result']
            deepresult = result['CVE_Items']
            insideCVEvar = deepresult[0]['cve']
            insideDescription = insideCVEvar['description']['description_data']
            DescriptionValue = insideDescription[0]['value']
            #uncomment if it says DescriptionValue not defined
            link_data.append((cve['cve'], cve["publishedDate"], cve["lastModifiedDate"], NVD + cve['cve'], DescriptionValue))

        # when the NVD link fails to load because it doesn't exist
        except:
            print('NVD link does not exist')
            link_data.append((cve['cve'],'N/A','N/A','N/A','pending'))

    #append data

        #link_data.append((cve['cve'],cve["publishedDate"],cve["lastModifiedDate"],NVD+cve['cve'],DescriptionValue))

    # data all appended double check
    print(link_data)
    # write the data to the tables:
    writer.writerows(link_data)
#close the created file
file.close()

