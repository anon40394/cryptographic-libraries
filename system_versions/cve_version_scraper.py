import requests
import statistics
from bs4 import BeautifulSoup
from datetime import datetime
from distutils.version import StrictVersion
from natsort import natsorted

#systemNames = ['Botan', 'Gnutls', 'Openssl', 'Android', 'Ubuntu', 'Wireshark']
#cryptoSystems = ['Botan', 'Gnutls', 'Openssl']
#nonCryptoSystems = ['Android', 'Ubuntu', 'Wireshark']
systemNames = ['Android']
systemToVendor = {
	'Openssl': 'Openssl',
	'Gnutls': 'GNU',
	'Botan': 'Botan Project',
	'Matrixssl': 'Matrixssl',
	'Android': 'Google',
    'Ubuntu Linux': 'Canonical',
    'Wireshark': 'Wireshark'
}

versionCounts = {}

def getCVEIDs(systemName):
    with open(systemName + '_cves.csv') as f:
        lines = f.readlines()
    lines = [x.strip() for x in lines]
    return lines

def getProductVersions(systemName):
	with open(systemName + '_versions.csv') as f:
		lines = f.readlines()
	separatedLines = [x.split(',') for x in lines]

	productVersions = []
	for line in separatedLines:
		versionNum = line[0].strip()
		productVersions.append(versionNum)

	return productVersions

def getValidCveVersions(systemName, versions):
    validVersions = []
    if systemName == 'Ubuntu':
        systemName = 'Ubuntu Linux'
       
    vendorName = systemToVendor[systemName]

    for v in versions:
        cols = v.findAll('td')
        vendor = cols[2].text.strip()
        system = cols[3].text.strip()
        versionNum = cols[4].text.strip()

        if ((system == systemName) and (vendor == vendorName) and (versionNum != '-')):
            validVersions.append(v)

    return validVersions

def getFirstLastVersions(cveVersions):
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

        initialVersionNum = versionNumbers[0]
        patchVersionNum = versionNumbers[-1]

        return (initialVersionNum, patchVersionNum)

    return (None, None)


def getCveVersion(cveID, systemName):
	# Scrape data from CVE Details:
    URL = 'https://www.cvedetails.com/cve/' + cveID + '/'
    page = requests.get(URL)    # HTTP request
    soup = BeautifulSoup(page.content, 'html.parser')

    summary = soup.find('div', class_='cvedetailssummary')
    versionsTable = soup.find(id='vulnprodstable')
    
    if not versionsTable:
        print(cveID)
        print('None')
        return
    
    fullVersions = versionsTable.findAll('tr')[1:]

    # Remove unrelated or invalid version numbers.
    cveVersions = getValidCveVersions(systemName, fullVersions)
    
    # Return if no valid version numbers for the CVE in question.
    if not cveVersions:
    	print('No valid versions for: ' + str(cveID))
    	return

    initialVersionNum, patchVersionNum = getFirstLastVersions(cveVersions)
    
    # Skip counting CVEs with only one version listed---usually malformed.
    if ((initialVersionNum is None) or (patchVersionNum is None) or (initialVersionNum == patchVersionNum)):
        print('One or fewer versions for: ' + str(cveID))
        return

    versionCounts[initialVersionNum] = versionCounts[initialVersionNum] + 1






for system in systemNames:
	print('------------------------------------------------------------------------------------------')
		
	print('System: ' + system)
	cveIDs = getCVEIDs(system)
	print(len(cveIDs))

	productVersions = getProductVersions(system)
	for version in productVersions:
		versionCounts[version] = 0


	for cveID in cveIDs:
		# print(cveID)
		getCveVersion(cveID, system)

for version in versionCounts:
	print(str(version) + ': ' + str(versionCounts[version]))

