from multiprocessing import Process, Manager
import threading, logging as log
from scapy.all import *
from math import log10
from time import sleep

#Globals
FSPL = 27.55 #Free-space path loss adapted average constant for home wifi routers

def dbm2m(mhz, dbm):
	m = 10 ** (( FSPL - (20 * log10(mhz)) + dbm ) / 20)
	m=round(m,2)
	return m #Distance in meters

class PacketSnifferProcess(Process):
	def __init__(self, iface, ssid, gbl_targets):
		super(PacketSnifferProcess, self).__init__()
		log.debug("PacketSniffer init")
		self.iface = iface
		self.ssid = ssid
		self.gbl_targets = gbl_targets

	def run(self):
		log.debug("PacketSniffer run")
		try:
			sniff(iface=self.iface, prn = self.PacketHandler, store=0)
		except Exception as e:
			log.debug("scanThread ERROR")
			traceback.print_exc(file=sys.stdout)
			pass
		
	def PacketHandler(self, pkt):

		if pkt.haslayer(Dot11):
			#print("PacketHandler: Packet received...")
			if pkt.addr2 is not None:
				if pkt.type == 0 and pkt.subtype == 8:
					#print("pkt:{} | stored:{}".format((pkt.info).decode('ascii'), self.ssid))
					if (pkt.info).decode('ascii') == self.ssid:
						try:
							extra = pkt.notdecoded
						except:
							extra = None
						
						if extra != None:
							sigstr = -(256-ord(extra[-2:-1]))
						else:
							sigstr = None 
							log.debug("No signal strength found!")
						#prev_lastseen = gbl_targets.get(tgt_ssid,-99)
						self.gbl_targets[self.ssid] = {'signal': sigstr, 'lastseen': time.time()}
						log.debug("WiFi signal strength: {}dBm | Distance: {}m".format(sigstr, dbm2m(2400,abs(sigstr))))


# Scan for all available APs
class ScanAPThread(threading.Thread):
	def __init__(self, iface, lst_aps):
		threading.Thread.__init__(self)
		self.iface = iface
		self.scanned_SSIDs = lst_aps
	def run(self):
		try:
			sniff(iface=self.iface, prn = self.APScanHandler, store=0, timeout=3)
			#return self.gbl_scanned_SSIDs
		except Exception as e:
			log.debug("scanap ERROR")
			log.debug(e)
			pass

	def APScanHandler(self, pkt):
		if pkt.haslayer(Dot11):
			if pkt.addr2 is not None:
				if pkt.type == 0 and pkt.subtype == 8:
					mac = pkt.addr2
					ssid = (pkt.info).decode('ascii')
					if mac not in self.scanned_SSIDs.keys():
						self.scanned_SSIDs[mac] = {'ssid': ssid}

class BeepProcess(Process):
	def __init__(self, ssid, gbl_targets):
		super(BeepProcess, self).__init__()
		log.debug("BeepProcess init")

		self.sleepsec = 3
		self.ssid = ssid
		self.gbl_targets = gbl_targets
		
	def run(self):
		while True:
			#threadLock.acquire()
			
			try:
				
				signal = None
				if self.ssid in self.gbl_targets.keys():
					#if self.gbl_targets[self.ssid]: 
					signal = self.gbl_targets[self.ssid]['signal']
					if signal in range(-35,0):
						self.sleepsec = 0.05
					elif signal in range(-40,-36):
						self.sleepsec = 0.50
					elif signal in range(-45,-41):
						self.sleepsec = 0.75
					elif signal in range(-50,-46):
						self.sleepsec = 1
					elif signal in range(-55,-51):
						self.sleepsec = 1.25
					elif signal in range(-60,-56):
						self.sleepsec = 1.50
					elif signal in range(-65,-61):
						self.sleepsec = 1.75
					elif signal in range(-70,-66):
						self.sleepsec = 2.0
					elif signal in range(-75,-71):
						self.sleepsec = 2.25
					elif signal in range(-80,-76):
						self.sleepsec = 2.50
					elif signal in range(-85,-81):
						self.sleepsec = 2.75
					elif signal in range(-90,-86):
						self.sleepsec = 3.0
					elif signal in range(-95,-91):
						self.sleepsec = 3.25
					elif signal in range(-100,-96):
						self.sleepsec = 3.50
						
					lastseen = self.gbl_targets[self.ssid]['lastseen']
					if (time.time() - lastseen <= 5):
						log.debug("BEEP!...then sleeping for {}s,".format(self.sleepsec))
						os.system('aplay beep2.wav')
					else:
						log.debug("Target went dark!")
				else:
					log.debug("Haven't seen target yet.")
							
				#threadLock.release()
			except Exception as e:
				log.debug("BeepProcess ERROR")
				traceback.print_exc(file=sys.stdout)
				pass
			sleep(self.sleepsec)