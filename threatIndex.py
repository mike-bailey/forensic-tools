import json
import re
import urllib2
import os
import sys

# Starts at 50%
# Under 50% = Reason to believe it's safe
# Over 50% = Reason to believe it's unsafe


try:
	filename = sys.argv[1]
except IndexError:
	print "You need to supply a JSON file that's effectively (non-flattened, non-tampered) a non-compressed file from CloudTrail. Please run this script in the following manner: %s cloudtrailfile.json" % sys.argv[0]
	exit(1)

keyrepstore = {}

def dlTor():
	url = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=8.8.8.8"

	file_name = 'tornodes.tmp'
	u = urllib2.urlopen(url)
	f = open(file_name, 'wb')
	meta = u.info()

	block_sz = 2048
	while True:
		buffer = u.read(block_sz)
		if not buffer:
			break
		f.write(buffer)
	
	f.close()

def setup():
	dlTor()	

def checkTor(record):
	ip = record['sourceIPAddress']
	cleanip = ip.replace('.','\.')
	result = [re.findall(r'(^'+ cleanip +'$)', entry) for entry in open('tornodes.tmp')]
	cleanresult = filter(None, result)
	if len(cleanresult) == 0:
		return False
	return True

# This function inspired by Pythons's Bozocrack
def checkAccessKey(record):
	# Pretend to be Chrome to stop Google from detecting our sillyness
	user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.8 (KHTML, like Gecko) Chrome/17.0.938.0 Safari/535.8"
	# Collect Access Key ID to search
	key = record['userIdentity']['accessKeyId']
	# Check cache
	if key in keyrepstore:
		# If search is already cached, just return it
		return keyrepstore[key]
	
	# Search
	url = "http://www.google.com/search?sourceid=chrome&q=%s" % key
	headers = {'User-Agent': user_agent}
	request = urllib2.Request(url, None, headers)
	response = urllib2.urlopen(request)
	respbody = response.read()
	
	# If it didn't show up
	if 'did not match any documents'  in respbody:
		# Cache answer
		keyrepstore[key] = False
		return False
	# If it did show up
	else:
		keyrepstore[key] = True
		return True

def mfaCheck(record):
	if record['userIdentity']['sessionContext']['attributes']['mfaAuthenticated'] == 'true':
		return True
	return False

def sketchyEventName(record):
	suspiciousEventNames = ['RunInstances']
	if record['eventName'] in suspiciousEventNames:
		return True
	return False

def rateEvent(record):
	reputation = 50
	if sketchyEventName(record):
		record['threatLogic']['SensitiveEvent'] = 1
		reputation = reputation * 1.3
	else:
		record['threatLogic']['SensitiveEvent'] = 0
	if mfaCheck(record): 
		record['threatLogic']['MFAactive'] = 1
		reputation = reputation * 0.6
	else: 
		reputation = reputation * 1.2
		record['threatLogic']['MFAactive'] = 0
	if checkTor(record):
		record['threatLogic']['TorNode'] = 1
		reputation = reputation * 1.8
	else:
		record['threatLogic']['TorNode'] = 0
	if checkAccessKey(record): 
		record['threatLogic']['AccessKeyOnInternet'] = 1
		reputation = reputation * 0.7
	else:
		record['threatLogic']['AccessKeyOnInternet'] = 0

	return int(reputation)

setup()

with open(filename) as data_file:    
    data = json.load(data_file)

for record in data['Records']:
	record['threatLogic'] = {}
	record['threatReputation'] = rateEvent(record)
	response = record['sourceIPAddress']

os.remove('tornodes.tmp')

print json.dumps(data)