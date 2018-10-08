from time import sleep
from scapy.all import *
import sys, threading, json, traceback, datetime, os, logging as log
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from multiprocessing import Process, Manager
from math import log10

#Globals
gbl_manager = Manager()
gbl_scanned_SSIDs = {}
gbl_targets = gbl_manager.dict() # TODO: Pick up here. Share this dict across processes
tgt_ssid = None
proc_hunt = None
proc_beep = None
FSPL = 27.55 #Free-space path loss adapted average constant for home wifi routers

LISTENPORT = 80

log.basicConfig(filename="/tmp/foxpopuli.log", level=log.DEBUG)

class PacketSniffer(Process):
	def __init__(self, iface, ssid, gbl_targets):
		super(PacketSniffer, self).__init__()
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
	global gbl_scanned_SSIDs
	def __init__(self, iface):
		threading.Thread.__init__(self)
		self.iface = iface
	
	def run(self):
		try:
			gbl_scanned_SSIDs = {}
			sniff(iface=self.iface, prn = self.APScanHandler, store=0, timeout=3)
		except Exception as e:
			log.debug("scanap ERROR")
			log.debug(e)
			pass

	def APScanHandler(self, pkt):
		global gbl_scanned_SSIDs
		if pkt.haslayer(Dot11):
			if pkt.addr2 is not None:
				if pkt.type == 0 and pkt.subtype == 8:
					mac = pkt.addr2
					ssid = (pkt.info).decode('ascii')
					if mac not in gbl_scanned_SSIDs.keys():
						gbl_scanned_SSIDs[mac] = {'ssid': ssid}

class BeepProcess(Process):
	def __init__(self, ssid, gbl_targets):
		super(BeepProcess, self).__init__()
		log.debug("BeepProcess init")
		'''pygame.mixer.init()
		pygame.mixer.music.load("beep2.wav")
		pygame.mixer.music.play()'''



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
					signal = gbl_targets[self.ssid]['signal']
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
						#pygame.mixer.music.play()
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

def dbm2m(mhz, dbm):
	m = 10 ** (( FSPL - (20 * log10(mhz)) + dbm ) / 20)
	m=round(m,2)
	return m #Distance in meters

def enableinterface(iface):
	os.system('airmon-ng start {}'.format(iface))
	return True

class MyServer(BaseHTTPRequestHandler):
	def do_HEAD(self):
		self.send_response(200)
		self.send_header("Content-type", "application/json")
		self.end_headers()
		
	def do_GET(self):
		global proc_hunt
		reqPath = self.path
		log.debug("Requested path: {}".format(self.path))
		
		dct_params = parse_qs(reqPath[2:])
		response = {}
		action = dct_params.get('action',None)
		if reqPath == '/':
			with open('index.html','r') as f:
				data = f.read()
			log.debug("[+] sending index.html ({} bytes)...".format(len(data)))
			self.wfile.write(bytes(data, 'utf=8'))
		# If css or js, send all files available under the css or js sub directories
		elif reqPath.startswith("/css/") or reqPath.startswith("/js/"):
			tok = reqPath[1:].split("/")
			if tok[0] == 'css':
				fname = 'css/' + '/'.join(tok[1:])
				with open(fname,'r') as f:
					data = f.read()
				log.debug("[+] sending /css/{} ({} bytes)...".format(tok[1], len(data)))
				self.wfile.write(bytes(data, 'utf=8'))
			elif tok[0] == 'js':
				fname = 'js/' + "/".join(tok[1:])
				# Check if image file
				if fname.endswith('.png') or fname.endswith('.gif'):
					with open(fname,'rb') as f:
						data = f.read()
					log.debug("[+] sending {} ({} bytes)...".format(fname, len(data)))
					self.wfile.write(bytes(data))
				else:
					with open(fname,'r') as f:
						data = f.read()
					log.debug("[+] sending {} ({} bytes)...".format(fname, len(data)))
					self.wfile.write(bytes(data, 'utf=8'))
		elif reqPath == '/favicon.ico':
			with open('favicon.ico','rb') as f:
				data = f.read()
			log.debug("[+] sending /favicon.ico ({} bytes)...".format(len(data)))
			self.wfile.write(bytes(data))
		elif action:
			if action[0] == 'hunt':
				ssid = dct_params.get('ssid',None)
				mac = dct_params.get('mac',None)
				if ssid:
					ssid = ssid[0]
				if mac:
					mac = mac[0]
				if ssid or mac:		
					hunt(ssid, mac)
					flg_hunt = True
					log.debug("Started hunting for SSID {}...".format(ssid))
					response = {'status':'SUCCESS', 'msg':'Successfully started hunting SSID {}'.format(ssid)}
				else:
					response = {'status':'FAIL', 'msg':'Unable start the hunt for SSID {}'.format(ssid)}
			elif action[0] == 'stophunt':
				log.debug("STOPHUNT received")
				if proc_hunt != None:
					proc_hunt.terminate()
					proc_beep.terminate()
					log.debug("Terminated hunt process")
					proc_hunt = None
				else:
					log.debug("Process was not hunting. Unable to terminate.")
			elif action[0] == 'scanap':
				res = scanap()
				if res:
					response = {'status':'SUCCESS', 'msg':'AP Scan successful', 'data': res}
				else:
					response = {'status':'FAIL', 'msg':'Error when scanning for APs.'}
			elif action[0] == 'enablemon0':
				res = enableinterface('wlan1')
				if res:
					response = {'status':'SUCCESS', 'msg':'mon0 successfully enabled'}
				else:
					response = {'status':'FAIL', 'msg':'Error when enabling mon0'}
			else:
				response = {'status':'FAIL', 'msg':'{} is an unsupported action'.format(action)}
		
			response = json.dumps(response)
			self.wfile.write(bytes(response, 'utf-8'))

def scanap():
	iface = 'mon0'
	thScan = ScanAPThread(iface)
	thScan.start()
	thScan.join()
	return gbl_scanned_SSIDs


def hunt(ssid=None, mac=None):
	global tgt_ssid, proc_hunt, proc_beep, gbl_targets
	tgt_ssid = ssid
	iface = 'mon0'
	proc_hunt = PacketSniffer(iface, ssid, gbl_targets)
	proc_hunt.daemon = True
	proc_hunt.start()

	proc_beep = BeepProcess(ssid, gbl_targets)
	proc_beep.daemon = True
	proc_beep.start()

if __name__ == '__main__':
	
	'''pygame.mixer.init()
	pygame.mixer.music.load("beep2.wav")
	pygame.mixer.music.play()'''

	myserver = HTTPServer(("", LISTENPORT), MyServer)
	log.debug("Serving at port {}...".format(LISTENPORT))
	
	try:
		myserver.serve_forever()
	except KeyboardInterrupt:
		pass
	
	myserver.server_close()
	log.debug("Stopped serving.")
	
	log.debug('[+] done..')
