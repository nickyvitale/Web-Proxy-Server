import subprocess
import random
import sys, os, time
import pandas as pd

# diff_test.sh Test for differences in the output and standard files
# error_test.sh for error tests
dataFolder = "dout"
websites = {"http://www.jamesbyron.net/resume.pdf": "4", "http://google.com/index.html": "2", "http://www.ucsc.edu/index.html": "5", "http://example.com/index.html": "1", "http://ssrc-nas-1.soe.ucsc.edu/cgi-bin/index.php": "3"}
sortedWeb = sorted(list(websites.keys()))
serverPID = None
# general tests
make = subprocess.Popen("make clean",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
make.communicate()
make = subprocess.Popen("make",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
makeData = make.communicate()
valid = subprocess.Popen("valid.sh",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
validData = valid.communicate()

def getServerPid():
	pidProc = subprocess.Popen("ps -e | grep myproxy",shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	pid = pidProc.communicate()
	pid = pid[0].decode() if type(pid[0]) == bytes else pid[0]
	pid = pid.split()
	pid = pid[0] if len(pid)>0 else None
	return pid

# Start the proxy server
# Return its pid
def startProxyServer(portNumber, logFile="acc.log", blockedSites="block"):
	global serverPID
	# ./myproxy listenport forbiddensitesfilepath accesslogfilepath
	runString = "./bin/myproxy " + portNumber + " " + blockedSites + " " + logFile
	print("Starting proxy server with", runString)
	subprocess.Popen(runString, shell=True)# Don't think we need the rest ,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	time.sleep(2)
	serverPID = getServerPid()
	return serverPID

def killProxyServer():
	global serverPID
	subprocess.Popen("killall myproxy",shell=True)
	serverPID = None
	time.sleep(2)

# move head (0), tail (1), or empty (2) list to active blocked list
def switchBlockedWebsites(input):
	proc = subprocess.Popen("rm block",shell=True)
	proc.communicate()
	time.sleep(1)
	assert(0 <= input <= 2)
	if input == 0:
		proc = subprocess.Popen("cp sites-head block",shell=True)
	elif input == 1:
		proc = subprocess.Popen("cp sites-tail block",shell=True)
	elif input == 2:
		proc = subprocess.Popen("touch block",shell=True)
	proc.communicate()
	time.sleep(1)

def cleanDout():
	proc = subprocess.Popen("rm dout/*",shell=True)
	proc.communicate()

def sendCC():
	global serverPID
	if serverPID == None:
		spid = getServerPid()
		if spid == None:
			return
		else:
			serverPID = spid
	killString = "kill -s 2 " + serverPID + " | grep myproxy"
	subprocess.Popen(killString, shell=True)
	time.sleep(2)

def extractData(input):
	takeOne = list("abcdefghijklmnopqrstuvwxyz")
	takeOne.reverse()
	output = dict()
	for key in input:
		dataOrig = input[key][0].decode() if type(input[key][0])==bytes else input[key][0]
		out = dataOrig.split("\n")
		dataOrig += input[key][1].decode() if type(input[key][1])==bytes else input[key][1]
		if key=="valid":
			#print(dataOrig)
			dataOrig = dataOrig.split()
			output[key] = dataOrig[3] # The location of the fork count from valid.sh
		elif key=="make":
			dataOrig = input[key][1].decode() if type(input[key][1])==bytes else input[key][1]
			dataOrig = dataOrig.lower()
			output[key] = "0" if "error" in dataOrig else "0.5" if "warning" in dataOrig else "1"
		elif key in ["name", "sid"]:
			output[key] = input[key]
		else:
			for line in out:
				if "Grade" in line:
					line2 = line.split()
					tempKey = key if key not in output else key+"_"+takeOne.pop()
					grade = line2[-1]
					output[tempKey] = grade
	return output

def runTests(numServersStr):
	switchBlockedWebsites(1)
	startProxyServer(sys.argv[2])
	sid = sys.argv[1].replace("LATE_","").split("_")[2]
	resultsDict = {"name":sys.argv[1],"sid":sid}
	resultsDict["make"] = makeData
	resultsDict["valid"] = validData
	s = "diff_test.sh " + numServersStr + " " + sys.argv[2] + " data " + " ".join(sortedWeb)
	p = subprocess.Popen(s,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	print("Running test:",s)
	pData = p.communicate()
	resultsDict["sites"] = pData
	switchBlockedWebsites(0)
	cleanDout()
	sendCC()
	s = "neg_test.sh " + numServersStr + " " + sys.argv[2] + " data " + " ".join(sortedWeb)
	p = subprocess.Popen(s,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	print("Running block test:",s)
	pData = p.communicate()
	resultsDict["block"] = pData
	switchBlockedWebsites(2)
	cleanDout()
	sendCC()
	s = "error_test.sh 1 " + sys.argv[2] +  " data unused"
	p = subprocess.Popen(s,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	print("Running error tests:",s)
	pData = p.communicate()
	killProxyServer()
	cleanDout()
	resultsDict["errors"] = pData
	return resultsDict

proxyDict = extractData(runTests("5"))
data = pd.DataFrame(proxyDict,index=[1])
data.to_csv("script_grade.csv",index=True)