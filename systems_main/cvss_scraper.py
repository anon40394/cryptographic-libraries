import requests
import statistics
from bs4 import BeautifulSoup
from datetime import datetime
from natsort import natsorted

systemNames = ['openssl', 'gnutls', 'botan', 'libgcrypt', 'wolfssl', 'nss', 'libressl', 'boringssl', 'bouncycastle', 'matrixssl', 'nettle', 'cryptopp', 'cryptlib', 'rustls', 'pycryptodome', 'sodiumoxide', 'cryptography']

def getCveDetailsIDs(systemName):
    with open(systemName + '_cves_cvedetails.csv') as f:
        lines = f.readlines()
    lines = [x.strip() for x in lines]
    return lines

def getOpenCveIDs(systemName):
    with open(systemName + '_cves_opencve.csv') as f:
        lines = f.readlines()
    lines = [x.strip() for x in lines]
    return lines

def getCveDetailsCvss(cveID):
    # Scrape data from CVE Details:
    URL = 'https://www.cvedetails.com/cve/' + cveID + '/'
    page = requests.get(URL)    # HTTP request
    soup = BeautifulSoup(page.content, 'html.parser')

    summary = soup.find('div', class_='cvedetailssummary')
    scoresTable = soup.find(id='cvssscorestable')
    
    if not scoresTable:
        print('Issue with scores table for: ' + str(cveID))
        return
    
    scoreContainer = scoresTable.findAll('tr')[0]
    score = scoreContainer.findAll('td')
    return score[0].text.strip()

def getOpenCveCvss(cveID):
    # Scrape data from OpenCVE:
    URL = 'https://www.opencve.io/cve/' + cveID
    page = requests.get(URL)    # HTTP request
    soup = BeautifulSoup(page.content, 'html.parser')

    div = soup.find('a', href='#cvss2')
    cvssText = div.findAll('span')[0].text
    return cvssText.split()[0].strip()


allScores = []

for system in systemNames:
    print('-----------------------------------------------------------------------------------------------------------')
		
    print('System: ' + system)


    cveDetailsIDs = getCveDetailsIDs(system)
    openCveIDs = getOpenCveIDs(system)
    totalCves = len(cveDetailsIDs) + len(openCveIDs)
    print('Total CVEs: ' + str(totalCves))

    scores = []
    for cveID in cveDetailsIDs:
        s = getCveDetailsCvss(cveID)
        scores.append(float(s))
        allScores.append(float(s))

    for cveID in openCveIDs:
        s = getOpenCveCvss(cveID)
        scores.append(float(s))
        allScores.append(float(s))

    avgCvssScore = statistics.mean(scores)
    print('average: ' + str(avgCvssScore))

    medianCvssScore = statistics.median(scores)
    print('median: ' + str(medianCvssScore))

    sampleStdDev = statistics.stdev(scores)
    print('sample standard deviation: ' + str(sampleStdDev))

    # populationStdDev = statistics.pstdev(vulnLifetimes)
    # print('population standard deviation: ' + str(populationStdDev))


    scores.clear()


print('--------------------------------------------------------------------------')
print('\n')

avgCvssScore = statistics.mean(allScores)
print('Total average: ' + str(avgCvssScore))

medianCvssScore = statistics.median(allScores)
print('Total median: ' + str(medianCvssScore))

sampleStdDev = statistics.stdev(allScores)
print('Total sample standard deviation: ' + str(sampleStdDev))