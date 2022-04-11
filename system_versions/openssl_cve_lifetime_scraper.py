import statistics
from datetime import datetime

cveLifetimes = []

def getVersionReleaseDates():
    # openssl_versions.csv
    with open('botan_versions.csv') as f:
        lines = f.readlines()
    separatedLines = [x.split(',') for x in lines]

    productVersions = {}
    for line in separatedLines:
        versionNum = line[0].strip()
        #print(versionNum + '-')
        versionDate = line[1].strip()
        productVersions[versionNum] = versionDate

    return productVersions

def calculateCveLifetime(dateIntroduced, dateFixed):
    try:
        date_format = "%m/%d/%Y"
        if (dateIntroduced and dateFixed):
            a = datetime.strptime(dateIntroduced, date_format)
            b = datetime.strptime(dateFixed, date_format)
            delta = b - a

            cveLifetimes.append(delta.days)
            #print(delta.days)
    except ValueError:
    	return

def getCveData():
    with open('botan_cves_with_versions.csv') as f:
        lines = f.readlines()
    cveData = [x.split(',') for x in lines]
    #print(cveData)

    openSSLVersions = getVersionReleaseDates()
    #print(openSSLVersions)

    # Format: CVE ID, Version Introduced, Version Patched
    for cve in cveData:
        cveID = cve[0].strip()
        #print(cveID)
        versionIntroduced = cve[1].strip()
        #print(versionIntroduced)
        versionPatched = cve[2].strip()

        initialVersionDate = openSSLVersions.get(versionIntroduced)
        patchVersionDate = openSSLVersions.get(versionPatched)

        calculateCveLifetime(initialVersionDate, patchVersionDate)

getCveData()

print('System: OpenSSL')

avgCVELifetime = statistics.mean(cveLifetimes)
print('average: ' + str(avgCVELifetime))

medianCVELifetime = statistics.median(cveLifetimes)
print('median: ' + str(medianCVELifetime))

sampleStdDev = statistics.stdev(cveLifetimes)
print('sample standard deviation: ' + str(sampleStdDev))

populationStdDev = statistics.pstdev(cveLifetimes)
print('population standard deviation: ' + str(populationStdDev))





