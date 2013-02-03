#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=1
import time

MACtest = []
pktTime = [] 
detectTimer = 0

def monitor(pkt):

	global MACtest
	global pktTime
	global detectTimer

	MACcounter = 0
	timeCounter = 0
	sourceMAC = pkt.sprintf('%ARP.hwsrc%')
	pktTime.append(time.mktime(time.gmtime())) 
	pktDif = [pktTime[i+1]-pktTime[i] for i in range(len(pktTime)-1)]

	if len(MACtest) < 8:
		MACtest.append(sourceMAC)
		for a in MACtest:
			if a == sourceMAC:
				MACcounter += 1
		if MACcounter == 7:
			for b in pktDif:
				if b == 0:
					timeCounter += 1	
			if timeCounter == 6:
				curTimer = time.mktime(time.gmtime())
				lastDet = curTimer - detectTimer
				print "LAST DETECT: %d" % lastDet 	
				if lastDet > 30:
					detectTimer = time.mktime(time.gmtime())
					print "DETECTED*******************************"
			MACcounter = 0
			timeCounter = 0

	else:
		MACtest = []
		pktTime = [] 
		print "CLEARED"

	print [pktTime[i+1]-pktTime[i] for i in range(len(pktTime)-1)]
	print "MACtest: %s\n" % MACtest

sniff(store=0, filter='arp', prn=monitor, iface="wlan0")
