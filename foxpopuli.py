
import sys, json, traceback, datetime, os, logging as log
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from foxutils import *

import netifaces

#Globals
gbl_manager = Manager()
gbl_targets = gbl_manager.dict()
gbl_interfaces = {}
tgt_ssid = None
tgt_mac = None
proc_hunt = None
proc_beep = None


LISTENPORT = 80

#log.basicConfig(filename="/tmp/foxpopuli.log", level=log.DEBUG)
log.basicConfig(level=log.DEBUG)

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
				iface = dct_params.get('interface',None)
				
				if ssid:
					ssid = ssid[0]
				if mac:
					mac = mac[0]
				if ssid or mac:		
					hunt(ssid, mac, iface)
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
				iface = dct_params.get('interface',None)
				res = scanap(iface)
				if res:
					response = {'status':'SUCCESS', 'msg':'AP Scan successful', 'data': res}
				else:
					response = {'status':'FAIL', 'msg':'Error when scanning for APs.'}
			elif action[0] == 'getinterfaces':
				res = get_interfaces()
				if res:
					response = {'status':'SUCCESS', 'msg':'Interfaces successfully enumerated', 'data': res}
				else:
					response = {'status':'FAIL', 'msg':'Error when enumerating interfaces'}
			elif action[0] == 'enablemonitormode':
				iface = dct_params.get('interface',None)
				if iface:
					ret, msg = enable_monitor_mode(iface[0])
					if ret:
						response = {'status':'SUCCESS', 'msg':'Monitor mode successfully enabled for interfaces {}. {}'.format(iface, msg)}
					else:
						response = {'status':'FAIL', 'msg': 'Unable to enable monitor mode for interface {}. {}'.format(iface, msg)}
				else:
					response = {'status':'FAIL', 'msg':'A valid interface name is required to enable monitor mode.'}
			elif action[0] == 'disablemonitormode':
				iface = dct_params.get('interface',None)
				if iface:
					ret, msg = disable_monitor_mode(iface[0])
					if ret:
						response = {'status':'SUCCESS', 'msg':'Monitor mode successfully disabled for interfaces {}. {}'.format(iface, msg)}
					else:
						response = {'status':'FAIL', 'msg': 'Unable to disable monitor mode for interface {}. {}'.format(iface, msg)}
				else:
					response = {'status':'FAIL', 'msg':'A valid interface name is required to disable monitor mode.'}
			elif action[0] == 'getmonitorinterfaces':
				ret = get_monitor_mode_interfaces()
				if ret:
					response = {'status':'SUCCESS', 'msg':'{} monitor mode interface(s) successfully returned'.format(len(ret)), 'data':ret}
				else:
					response = {'status':'FAIL', 'msg': 'Unable to retrieve monitor mode interfaces.'}
			elif action[0] == 'gethuntstatus':
				if proc_hunt != None:
					sigstr = gbl_targets[tgt_ssid]['signal']
					distance = dbm2m(2400,abs(sigstr))
					data = {'signal_strength':'{}dBm'.format(sigstr), 'distance':'{}m'.format(distance)}
					response = {'status':'SUCCESS', 'msg':'Status retrieved', 'data':data}
				else:
					response = {'status':'FAIL', 'msg':'No hunt in progress.'}
			else:
				response = {'status':'FAIL', 'msg':'{} is an unsupported action'.format(action)}
		
			response = json.dumps(response)
			self.wfile.write(bytes(response, 'utf-8'))

#Internal functions
def __get_interface_byName(iface):
	for itm in gbl_interfaces:
		if itm.interface.lower() == iface.lower():
			return itm
	return None


def get_monitor_mode_interfaces():
	ret = []
	for itm in gbl_interfaces:
		if (itm.type == Interface.TYPE_MONITOR):
			ret.append(itm.interface)
	return ret

def scanap(iface):
	if (not iface):
		iface = 'mon0'
	scanned_SSIDs = {}
	thScan = ScanAPThread(iface, scanned_SSIDs)
	thScan.start()
	thScan.join()
	return scanned_SSIDs


def hunt(ssid=None, mac=None, iface=None):
	global tgt_ssid, proc_hunt, proc_beep, gbl_targets
	tgt_ssid = ssid
	tgt_mac = mac
	if (not iface):
		iface = 'mon0'
	proc_hunt = PacketSnifferProcess(iface, ssid, mac, gbl_targets)
	proc_hunt.daemon = True
	proc_hunt.start()

	proc_beep = BeepProcess(ssid, gbl_targets)
	proc_beep.daemon = True
	proc_beep.start()

def get_interfaces():
	global gbl_interfaces
	ret = netifaces.interfaces()
	gbl_interfaces = []
	lst_ret_ifaces = []
	for iface in ret:
		if iface not in Interface.FILTER_INTERFACES:
			i = Interface(iface)
			gbl_interfaces.append(i)
			lst_ret_ifaces.append(i.dict())
	return lst_ret_ifaces

def enable_monitor_mode(iface):
	if iface:
		itm = __get_interface_byName(iface)
		if itm:
			return itm.enable_monitor_mode()
		else:
			return False, "No interface {} was found".format(iface)
	else:
		return False, "No interface name was provided"

def disable_monitor_mode(iface):
	if iface:
		itm = __get_interface_byName(iface)
		if itm:
			return itm.disable_monitor_mode()
		else:
			return False, "No interface {} was found".format(iface)
	else:
		return False, "No interface name was provided"

if __name__ == '__main__':	

	myserver = HTTPServer(("", LISTENPORT), MyServer)
	log.debug("Serving at port {}...".format(LISTENPORT))
	
	try:
		myserver.serve_forever()
	except KeyboardInterrupt:
		pass
	
	myserver.server_close()
	log.debug("Stopped serving.")
	
	log.debug('[+] done..')
