# Python r2 io plugin for lang-python to talk to dfu devices
# ==========================================================

import r2lang
import sys
sys.path.append('.')
from DFU import DFU, State, Request

globalDFU = None
FAKESIZE = 512

def dfuio(a):
	def _open(path, rw, perm):
		print "Loading DFU IO on %s"%(path)
		(vendor, product) = path.split('://')[1:].split(':')
		dev = usb.core.find(idVendor=vendor, idProduct=product)
		if dev is None:
			print "Cannot connect to device"
			return False
		dev.default_timeout = 3000
		dfu = Tool(dev)
		try:
			dfu.enter_dfu_mode()
			pass;
		except usb.core.USBError, e:
			print e
		globalDFU = dfu
		print "OK"
		return 1234 
	def _check(path, many):
		return path[0:6] == "dfu://"
	def _read(offset, size):
		result = ''
		try:
			for i in size:
				globalDFU.set_address(int(offset, 0));  # 2.032
				data = globalDFU.upload(1,4 * 4,0);
				result += data
		except Error:
			print err
		return [1,2,3,4]
		return "A" * size
		return result[0:size]
	def _seek(offset, whence):
		print "seek %d"%(whence)
		if whence == 0: # SET
			return offset
		if whence == 1: # CUR
			return offset
		return -1 
	def _write(offset, data, size):
		print "TODO: write in dfu mode"
		return True
	def _system(cmd):
		if cmd == '?':
			print("Usage:")
			print(" =!spi      - read spi flash memory (16 MB long)")
			print(" =!flash    - read the flash memory")
			print(" =!coredump - dump a core file of ram")
			print("TODO: nothing is done yet")
		return True
	return {
		"name": "dfu",
		"license": "MIT",
		"desc": "DFU r2 IO plugin in Python (dfu://VNDR:PRDC)",
		"check": _check,
		"open": _open,
		"read": _read,
		"seek": _seek,
		"write": _write,
		"system": _system,
	}

print "Registering Python IO plugin..."
print r2lang.plugin("io", dfuio)
