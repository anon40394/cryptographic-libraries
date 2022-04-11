import requests
import statistics
from bs4 import BeautifulSoup
from datetime import datetime
from natsort import natsorted
import re

systemNames = ['openssl', 'gnutls', 'botan', 'libgcrypt', 'wolfssl', 'nss', 'libressl', 'boringssl', 'bouncycastle', 'matrixssl', 'nettle', 'cryptopp', 'cryptlib', 'rustls', 'pycryptodome', 'sodiumoxide', 'python_cryptography', 'mbedtls', 'pycrypto', 'libtomcrypt', 'orion']

cryptoCwes = ('CWE-310', 'CWE-327', 'CWE-326', 'CWE-320', 'CWE-335', 'CWE-330', 'CWE-311', 'CWE-347')
bufferCwes = ('CWE-119', 'CWE-125', 'CWE-787', 'CWE-131', 'CWE-120')
exposureCwes = ('CWE-200')
resourceCwes = ('CWE-399', 'CWE-476', 'CWE-770', 'CWE-674', 'CWE-824', 'CWE-415', 'CWE-400', 'CWE-362', 'CWE-416', 'CWE-402', 'CWE-755', 'CWE-417', 'CWE-835', 'CWE-502')
inputCwes = ('CWE-20', 'CWE-295', 'CWE-345', 'CWE-354', 'CWE-88')
numericCwes = ('CWE-189', 'CWE-682', 'CWE-193', 'CWE-190')
accessCwes = ('CWE-264', 'CWE-284', 'CWE-287', 'CWE-255')
otherCwes = ('CWE-17', 'CWE-254', 'CWE-203', 'CWE-19', 'CWE-384', 'CWE-470', 'CWE-361')

cweCategories = {cryptoCwes: 0, bufferCwes: 0, exposureCwes: 0, resourceCwes: 0, inputCwes: 0, numericCwes: 0, accessCwes: 0, otherCwes: 0}
cweCounts = {}

def getCveIDs(systemName):
    with open('cves/' + systemName + '_cves.csv') as f:
        lines = f.readlines()
    lines = [x.strip() for x in lines]
    return lines

def getCweNames(cveID):
    # Scrape data from OpenCVE:
    URL = 'https://www.opencve.io/cve/' + cveID
    page = requests.get(URL)    # HTTP request
    soup = BeautifulSoup(page.content, 'html.parser')

    cweTags = soup.find_all("a", href=re.compile(r"/cve\?cwe=CWE"))

    cwes = []
    for tag in cweTags:
        cwes.append(tag.text.strip())
    return cwes


noCweCount = 0
overallCveTotal = 0

for system in systemNames:
    print('-----------------------------------------------------------------------------------------------------------')
        
    print('System: ' + system)
    systemCveList = getCveIDs(system)
    print('Total System CVEs: ' + str(len(systemCveList)))
    overallCveTotal += len(systemCveList)

    for cveID in systemCveList:
        cweNames = getCweNames(cveID)
        if not len(cweNames):
            print(cveID)

            for cwe in cweNames:
                if cwe in cweCounts.keys():
                    cweCounts[cwe] += 1
                else:
                    cweCounts[cwe] = 1
                
                if cwe in cryptoCwes:
                    cweCategories[cryptoCwes] += 1
                elif cwe in bufferCwes:
                    cweCategories[bufferCwes] += 1
                elif cwe in exposureCwes:
                    cweCategories[exposureCwes] += 1
                elif cwe in resourceCwes:
                    cweCategories[resourceCwes] += 1
                elif cwe in inputCwes:
                    cweCategories[inputCwes] += 1
                elif cwe in numericCwes:
                    cweCategories[numericCwes] += 1
                elif cwe in accessCwes:
                    cweCategories[accessCwes] += 1
                elif cwe in otherCwes:
                    cweCategories[otherCwes] += 1
                else:
                    print('Uncategorized CWE: ' + cwe)
                
                for category in cweCategories.keys():
                    if cwe in category:
                        cweCategories[category] += 1
                
        else:
            noCweCount += 1
        

    print('CVEs Without CWE Names: ' + str(noCweCount))
    noCweCount = 0



print('-----------------------------------------------------------------------------------------------------------')
print('\n')

for key, value in cweCategories.items():
    print(key, ': ', str(value))

