import requests
import statistics
from bs4 import BeautifulSoup
from datetime import datetime
from natsort import natsorted
import re

systemNames = ['openssl', 'gnutls', 'botan', 'libgcrypt', 'wolfssl', 'nss', 'libressl', 'boringssl', 'bouncycastle', 'matrixssl', 'nettle', 'cryptopp', 'cryptlib', 'rustls', 'pycryptodome', 'sodiumoxide', 'cryptography']
cryptoCwes = ['CWE-959', 'CWE-958', 'CWE-903', 'CWE-816', 'CWE-719', 'CWE-649', 'CWE-347', 'CWE-338', 'CWE-335', 'CWE-330', 'CWE-327', 'CWE-326', 'CWE-325', 'CWE-323', 'CWE-321', 'CWE-320', 'CWE-311', 'CWE-310', 'CWE-1279', 'CWE-1240', 'CWE-1205', 'CWE-1013']

def getCveIDs(systemName):
    with open('cves/' + systemName + '_cves.csv') as f:
        lines = f.readlines()
    lines = [x.strip() for x in lines]
    return lines

def getOpenCveCvss(cveID):
    # Scrape data from OpenCVE:
    URL = 'https://www.opencve.io/cve/' + cveID
    page = requests.get(URL)
    soup = BeautifulSoup(page.content, 'html.parser')

    cvssTag = soup.find('a', href='#cvss3')
    if cvssTag is None:
        return
    cvssText = cvssTag.findAll('span')[0].text
    return cvssText.split()[0].strip()

def getCweName(cveID):
    # Scrape data from OpenCVE:
    URL = 'https://www.opencve.io/cve/' + cveID
    page = requests.get(URL)
    soup = BeautifulSoup(page.content, 'html.parser')

    cweTags = soup.find_all("a", href=re.compile(r"/cve\?cwe=CWE"))

    cwes = []
    for tag in cweTags:
        cwes.append(tag.text.strip())
    return cwes


noCweCount = 0
cryptoCveCount = 0
nonCryptoCveCount = 0

systemNoCweCount = 0
systemCryptoCveCount = 0
systemNonCryptoCveCount = 0

severeNoCweCount = 0
severeCryptoCveCount = 0
severeNonCryptoCveCount = 0

for system in systemNames:
    print('-----------------------------------------------------------------------------------------------------------')
        
    print('System: ' + system)
    systemCves = getCveIDs(system)
    print('Total System CVEs: ' + str(len(systemCves)))

    for cveID in systemCves:
        cweNames = getCweName(cveID)
        if cweNames:
            # This is hacky in order to avoid double-counting CVEs with one crypto and one non-crypto CWE.
            crypto = False
            for cwe in cweNames:
                if cwe in cryptoCwes:
                    cryptoCveCount += 1
                    systemCryptoCveCount += 1

                    crypto = True
                    break
            if crypto is False:
                nonCryptoCveCount += 1
                systemNonCryptoCveCount += 1
        else:
            noCweCount += 1
            systemNoCweCount += 1

    print('CVEs Without CWE Names: ' + str(systemNoCweCount))
    print('Crypto CVE Count: ' + str(systemCryptoCveCount))
    print('Non-Crypto CVE Count: ' + str(systemNonCryptoCveCount) + '\n')

    systemNoCweCount = 0
    systemCryptoCveCount = 0
    systemNonCryptoCveCount = 0

    severeCves = []
    for cveID in systemCves:
        cvss = getOpenCveCvss(cveID)
        if cvss is None:
            continue
        if float(cvss) >= 7.0:
            severeCves.append(cveID)

    for cveID in severeCves:
        cweNames = getCweName(cveID)
        if cweNames:
            crypto = False
            for cwe in cweNames:
                if cwe in cryptoCwes:
                    severeCryptoCveCount += 1
                    crypto = True
                    break
            if crypto is False:
                severeNonCryptoCveCount += 1
        else:
            severeNoCweCount += 1



print('All CVEs (n = ' + str(noCweCount + cryptoCveCount + nonCryptoCveCount) + '):')
print('CVEs Without CWE Names: ' + str(noCweCount))
print('Crypto CVE Count: ' + str(cryptoCveCount))
print('Non-Crypto CVE Count: ' + str(nonCryptoCveCount))


print('\n')

print('Severe CVEs (n = ' + str(severeNoCweCount + severeCryptoCveCount + severeNonCryptoCveCount) + '):')
print('Severe CVEs Without CWE Names: ' + str(severeNoCweCount))
print('Severe Crypto CVE Count: ' + str(severeCryptoCveCount))
print('Severe Non-Crypto CVE Count: ' + str(severeNonCryptoCveCount))



