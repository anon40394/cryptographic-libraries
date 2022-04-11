# CVE Details Scraper
# Collects the following: CVE-ID, Version Introduced, Version Fixed

import requests
import statistics
from bs4 import BeautifulSoup
from datetime import datetime
from distutils.version import StrictVersion
from natsort import natsorted


systemNames = ['Botan', 'Gnutls', 'NSS', 'Ubuntu', 'Wireshark']

systemToVendor = {
	'Openssl': 'Openssl',
	'Gnutls': 'GNU',
	'Botan': 'Botan Project',
    'Libgcrypt': 'Gnupg',
    'Wolfssl': 'Wolfssl',
    'Network Security Services': 'Mozilla',
	'Matrixssl': 'Matrixssl',
	'Android': 'Google',
    'Ubuntu Linux': 'Canonical',
    'Wireshark': 'Wireshark'
}

systemVulnLifetimes = []
allVulnLifetimes = []
systemVersions = []

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

    try:
        for v in versions:
            cols = v.findAll('td')
            vendor = cols[2].text.strip()
            system = cols[3].text.strip()
            versionNum = cols[4].text.strip()

            if ((system == systemName) and (vendor == vendorName) and (versionNum != '*') and (versionNum != '-')):
                validVersions.append(v)
    except IndexError as i:
        print('No vendors listed.')

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

        initialAffectedVersion = versionNumbers[0]
        lastAffectedVersion = versionNumbers[-1]

        # Skip CVEs with only one affected version listed.
        if (initialAffectedVersion == lastAffectedVersion):
            return (None, None)
        # print(lastAffectedVersion)

        # To get patch version from last affected version:
        lastAffectedIdx = systemVersions.index(lastAffectedVersion)
        patchVersion = systemVersions[lastAffectedIdx + 1]

        # If dates are the same, get next version date:
        if (productVersions.get(lastAffectedVersion) == productVersions.get(patchVersion)):
            patchVersion = systemVersions[lastAffectedIdx + 2]

        return (initialAffectedVersion, patchVersion)

    return (None, None)


def calculateLifetime(dateIntroduced, dateFixed):
    try:
        date_format = "%m/%d/%Y"
        if (dateIntroduced and dateFixed):
            a = datetime.strptime(dateIntroduced, date_format)
            b = datetime.strptime(dateFixed, date_format)
            delta = b - a
            
            if (delta.days <= 0):
                print('Issue with vulnerability lifetime:')
                print(delta.days)
                return
            
            systemVulnLifetimes.append(delta.days)
            allVulnLifetimes.append(delta.days)
    except ValueError:
        return

def getCveLifetime(cveID, systemName, productVersions):
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
    	# print('No valid versions for: ' + str(cveID))
    	return

    initialVersionNum, patchVersionNum = getFirstLastVersions(cveVersions)

    if ((initialVersionNum is None) or (patchVersionNum is None)):
        # print('One or fewer versions for: ' + str(cveID))
        return

    # print('initial version: ' + str(initialVersionNum))
    # print('patch version: ' + str(patchVersionNum))

    initialVersionDate = productVersions.get(initialVersionNum)
    patchVersionDate = productVersions.get(patchVersionNum)

    if (initialVersionDate and patchVersionDate):
        calculateLifetime(initialVersionDate, patchVersionDate)
    else:
        print('Either initial version date or patch version date is None for: ' + str(cveID))
        print('initial version: ' + str(initialVersionNum))
        print('patch version: ' + str(patchVersionNum))


def getOpenSSLCveLifetimes():
    with open('openssl_cves_with_versions.csv') as f:
        lines = f.readlines()
    cveData = [x.split(',') for x in lines]
    print('Total CVEs: ' + str(len(cveData)))

    openSSLVersions = getProductVersions('openssl')

    # Format: CVE ID, Version Introduced, Version Patched
    for cve in cveData:
        cveID = cve[0].strip()
        versionIntroduced = cve[1].strip()
        versionPatched = cve[2].strip()

        initialVersionDate = openSSLVersions.get(versionIntroduced)
        patchVersionDate = openSSLVersions.get(versionPatched)

        calculateLifetime(initialVersionDate, patchVersionDate)

    printLifetimeStatistics(systemVulnLifetimes)
    systemVulnLifetimes.clear()

def getNssCveLifetimes():
    with open('nss_cves_with_versions.csv') as f:
        lines = f.readlines()
    cveData = [x.split(',') for x in lines]
    print('Total CVEs: ' + str(len(cveData)))

    openSSLVersions = getProductVersions('nss')

    # Format: CVE ID, Version Introduced, Version Patched
    for cve in cveData:
        cveID = cve[0].strip()
        versionIntroduced = cve[1].strip()
        versionPatched = cve[2].strip()

        initialVersionDate = openSSLVersions.get(versionIntroduced)
        patchVersionDate = openSSLVersions.get(versionPatched)

        calculateLifetime(initialVersionDate, patchVersionDate)

    printLifetimeStatistics(systemVulnLifetimes)
    systemVulnLifetimes.clear()

def printLifetimeStatistics(lifetimeData):
    print('\n')
    print('Well-formed CVEs: ' + str(len(lifetimeData)))

    avgCVELifetime = statistics.mean(lifetimeData)
    print('Average: ' + str(avgCVELifetime))

    medianCVELifetime = statistics.median(lifetimeData)
    print('Median: ' + str(medianCVELifetime))

    sampleStdDev = statistics.stdev(lifetimeData)
    print('Sample standard deviation: ' + str(sampleStdDev))

    populationStdDev = statistics.pstdev(lifetimeData)
    print('Population standard deviation: ' + str(populationStdDev))


for system in systemNames:
    print('-----------------------------------------------------------------------------------------------------------')
    print('System: ' + system)

    if system == 'Openssl':
        getOpenSSLCveLifetimes()
        continue

    if system == 'NSS':
        getNssCveLifetimes()
        continue

    cveIDs = getCVEIDs(system)
    print('Total CVEs: ' + str(len(cveIDs)))
    productVersions = getProductVersions(system)

    for cveID in cveIDs:
        # print(cveID)
        getCveLifetime(cveID, system, productVersions)
        # print('\n')

    printLifetimeStatistics(systemVulnLifetimes)

    systemVersions.clear()
    systemVulnLifetimes.clear()



printLifetimeStatistics(allVulnLifetimes)




