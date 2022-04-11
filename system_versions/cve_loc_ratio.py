import requests
import statistics
from bs4 import BeautifulSoup
from datetime import datetime
from distutils.version import StrictVersion
from natsort import natsorted

systemNames = ['Openssl', 'Ubuntu', 'Wireshark']

systemToVendor = {
	'Openssl': 'Openssl',
	'Gnutls': 'GNU',
	'Botan': 'Botan Project',
    'Network Security Services': 'Mozilla',
	'Matrixssl': 'Matrixssl',
	'Android': 'Google',
    'Ubuntu Linux': 'Canonical',
    'Wireshark': 'Wireshark'
}

systemVersions = []
individualCount = 0
totalCount = 0

def getCVEIDs(systemName):
    with open(systemName + '_cves_cvedetails.csv') as f:
        lines = f.readlines()
    lines = [x.strip() for x in lines]
    return lines

def getProductVersions(systemName):
    with open(systemName + '_versions.csv') as f:
        lines = f.readlines()
    separatedLines = [x.split(',') for x in lines]

    productVersions = {}
    for line in separatedLines:
        versionNum = line[0].strip()
        systemVersions.append(versionNum)

        versionDate = line[1].strip()
        productVersions[versionNum] = versionDate

    # Order from earliest versions to most recent.
    systemVersions.reverse()

    return productVersions

def getValidCveVersions(systemName, versions):
    validVersions = []
    if systemName == 'Ubuntu':
        systemName = 'Ubuntu Linux'
    if systemName == 'NSS':
        systemName = 'Network Security Services'
    
    vendorName = systemToVendor[systemName]

    for v in versions:
        try:
            cols = v.findAll('td')
            vendor = cols[2].text.strip()
            system = cols[3].text.strip()
            versionNum = cols[4].text.strip()

            if ((system == systemName) and (vendor == vendorName) and (versionNum != '-')):
                validVersions.append(v)
        except IndexError as i:
            print('Error retrieving versions')

    return validVersions

def getFirstVersion(cveVersions):
    versionNumbers = []

    for detailedVersion in cveVersions:
        cols = detailedVersion.findAll('td')
        versionNum = cols[4].text.strip()
        if versionNum:
            versionNumbers.append(versionNum)

    
    # Sort, then take first and last to get patch and initial version numbers.
    if versionNumbers:
        try:
            natsorted(versionNumbers)
        except ValueError as e:
            print('Sorting error: ' + e)

        initialAffectedVersion = versionNumbers[0]
        lastAffectedVersion = versionNumbers[-1]

        # Skip CVEs with only one affected version listed.
        if (initialAffectedVersion == lastAffectedVersion):
            return None

        return initialAffectedVersion

    return None

def getCveVersionIntroduced(cveID, systemName, productVersions):
	# Scrape data from CVE Details:
    URL = 'https://www.cvedetails.com/cve/' + cveID + '/'
    page = requests.get(URL)    # HTTP request
    soup = BeautifulSoup(page.content, 'html.parser')

    summary = soup.find('div', class_='cvedetailssummary')
    versionsTable = soup.find(id='vulnprodstable')
    
    if not versionsTable:
        print('Issue with versions table for: ' + str(cveID))
        return
    
    fullVersions = versionsTable.findAll('tr')[1:]

    # Remove unrelated or invalid version numbers.
    cveVersions = getValidCveVersions(systemName, fullVersions)
    	
    # Return if no valid version numbers for the CVE in question.
    if not cveVersions:
    	return

    return getFirstVersion(cveVersions)

''' Check if version introduced is between January 1, 2010 and December 31, 2015. '''
def isInDateRange(versionDate):
    global individualCount
    global totalCount

    try:
        date_format = "%m/%d/%Y"
        if (versionDate):
            d = datetime.strptime(versionDate, date_format)
            beginning = datetime.strptime('8/30/2010', date_format)
            end = datetime.strptime('11/18/2015', date_format)

            if ((d >= beginning) and (d <= end)):
                individualCount += 1
                totalCount += 1
    except ValueError:
        return

def printCount():
    print('\n')
    print('Number of CVEs introduced between 4/2/2010 - 10/22/2015: ' + str(individualCount))
    print('\n')

def getOpenSSLCveVersionIntroduced():
    global individualCount
    with open('openssl_cves_with_versions.csv') as f:
        lines = f.readlines()
    cveData = [x.split(',') for x in lines]
    print('Total CVEs: ' + str(len(cveData)))

    openSSLVersions = getProductVersions('openssl')

    # Format: CVE ID, Version Introduced, Version Patched
    for cve in cveData:
        cveID = cve[0].strip()
        versionIntroduced = cve[1].strip()

        initialVersionDate = openSSLVersions.get(versionIntroduced)
        isInDateRange(initialVersionDate)

    printCount()
    individualCount = 0


for system in systemNames:
    print('-----------------------------------------------------------------------------------------------------------')
    print('System: ' + system)

    if system == 'Openssl':
        getOpenSSLCveVersionIntroduced()
        continue

    cveIDs = getCVEIDs(system)
    print('Total CVEs: ' + str(len(cveIDs)))
    productVersions = getProductVersions(system)

    cveCount = 0

    for cveID in cveIDs:
        print(cveID)
        initialVersionNum = getCveVersionIntroduced(cveID, system, productVersions)

        if (initialVersionNum is None):
            continue

        initialVersionDate = productVersions.get(initialVersionNum)
        isInDateRange(initialVersionDate)
    
    printCount()
    individualCount = 0
    systemVersions.clear()


print('\n')
print('Total number of CVEs introduced in specified range: ' + str(totalCount))



