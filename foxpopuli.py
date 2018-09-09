from time import sleep
from scapy.all import *
import sys, threading, pygame, json, traceback, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

#Globals
gbl_targets = {}
tgt_ssid = None
FSPL = 27.55 #Free-space path loss adapted average constant for home wifi routers

LISTENPORT = 80

class scanThread(threading.Thread):
	global gbl_targets
	def __init__(self, iface, ssid):
		threading.Thread.__init__(self)
		self.targets = gbl_targets
		self.ssid = ssid
		self.iface = iface
	
	def run(self):
		try:
			sniff(iface=self.iface, prn = PacketHandler)
		except Exception as e:
			print("scanThread ERROR")
			print(e)
			pass

class beepThread(threading.Thread):
	global gbl_targets
	def __init__(self, ssid):
		threading.Thread.__init__(self)
		pygame.mixer.init()
		pygame.mixer.music.load("beep2.wav")
		self.sleepsec = 3
		self.ssid = ssid
		
	def run(self):
		while True:
			#threadLock.acquire()
			print("Beeping...{}s,".format(self.sleepsec))
			try:
				
				signal = None
				if gbl_targets[self.ssid]: 
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
						
					lastseen = gbl_targets[self.ssid]['lastseen']
					if (time.time() - lastseen <= 5):
						pygame.mixer.music.play() 
							
				#threadLock.release()
			except Exception as e:
				print("beepThread ERROR")
				traceback.print_exc(file=sys.stdout)
				pass
			sleep(self.sleepsec)

def PacketHandler(pkt):
	global gbl_targets, tgt_ssid
	if pkt.haslayer(Dot11):
		if pkt.addr2 is not None:
			if pkt.type == 0 and pkt.subtype == 8:
				if (pkt.info).decode('ascii') == tgt_ssid:
					try:
						extra = pkt.notdecoded
					except:
						extra = None
					
					if extra != None:
						sigstr = -(256-ord(extra[-2:-1]))
					else:
						sigstr = None 
						print("No signal strength found!")
						
					gbl_targets[tgt_ssid] = {'signal': sigstr, 'lastseen': time.time()}
					print("WiFi signal strength: {}".format(sigstr))

def dbm2m(mhz, dbm):
	m = 10 ** (( FSPL - (20 * log10(mhz)) + dbm ) / 20)
	m=round(m,2)
	return m #Distance in meters

def enumaps():
	return [{'essid':'blah', 'bssid':'a1:b2:c3:d4:e5:f6', 'ch':1, 'enc':'yes'}]

class MyServer(BaseHTTPRequestHandler):
	def do_HEAD(self):
		self.send_response(200)
		self.send_header("Content-type", "application/json")
		self.end_headers()
		
	def do_GET(self):
		print("Requested path: {}".format(self.path))
		dct_params = parse_qs(self.path[2:])
		response = {}
		action = dct_params.get('action',None)
		if self.path == '/':
			with open('index.html','r') as f:
				data = f.read()
			print("[+] sending index.html ({} bytes)...".format(len(data)))
			self.wfile.write(bytes(data, 'utf=8'))
		elif self.path == '/css/w3mobile.css':
			with open('css/w3mobile.css','r') as f:
				data = f.read()
			print("[+] sending css/w3mobile.css ({} bytes)...".format(len(data)))
			self.wfile.write(bytes(data, 'utf=8'))
		elif self.path == '/js/jquery.js':
			with open('js/jquery.js','r') as f:
				data = f.read()
			print("[+] sending js/jquery.js ({} bytes)...".format(len(data)))
			self.wfile.write(bytes(data, 'utf=8'))
		elif self.path == '/js/foxpopuli.js':
			with open('js/foxpopuli.js','r') as f:
				data = f.read()
			print("[+] sending js/foxpopuli.js ({} bytes)...".format(len(data)))
			self.wfile.write(bytes(data, 'utf=8'))
		elif self.path == '/favicon.ico':
			with open('favicon.ico','rb') as f:
				data = f.read()
			print("[+] sending favicon.ico ({} bytes)...".format(len(data)))
			self.wfile.write(bytes(data))
		elif action:
			if action[0] == 'hunt':
				ssid = dct_params.get('ssid',None)
				if ssid[0]:
					ssid = ssid[0]
					hunt(ssid)
					print("Started hunting for SSID {}...".format(ssid))
					response = {'status':'SUCCESS', 'msg':'Successfully started hunting SSID {}'.format(ssid)}
				else:
					response = {'status':'FAIL', 'msg':'Unable start the hunt for SSID {}'.format(ssid)}
			elif action[0] == 'test':
				now = datetime.datetime.now() 
				response = {'status':'SUCCESS', 'msg':'Successful test', 'data': "The time is now {}".format(now)}
			else:
				response = {'status':'FAIL', 'msg':'{} is an unsupported action'.format(action)}
		
			response = json.dumps(response)
			self.wfile.write(bytes(response, 'utf-8'))

def hunt(ssid):
	global tgt_ssid
	tgt_ssid = ssid
	iface = 'mon0'
	thScan = scanThread(iface, tgt_ssid)
	thBeep = beepThread(tgt_ssid)
	
	thScan.start()
	thBeep.start()
	
	thScan.join()
	thBeep.join()
		
if __name__ == '__main__':
	'''iface = sys.argv[1]
	tgt_ssid = sys.argv[2]
	
	
	threadLock = threading.Lock()
	thScan = scanThread(iface, tgt_ssid)
	thBeep = beepThread(tgt_ssid)
	
	thScan.start()
	thBeep.start()
	
	thScan.join()
	thBeep.join()'''
	
	myserver = HTTPServer(("", LISTENPORT), MyServer)
	print("Serving at port {}...".format(LISTENPORT))
	
	try:
		myserver.serve_forever()
	except KeyboardInterrupt:
		pass
	
	myserver.server_close()
	print("Stopped serving.")
	
	print('[+] done..')
