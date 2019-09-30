# iOS pwndfu checkm8 io plugin for radare2
# ========================================
#
#  -- pancake @ nopcode.org
#
# Usage:
#   r2 -I test-py-io.py pwndfu://
#
# The r2lang.plugin function exposes a way to register new plugins
# into the RCore instance. This API is only available from RLang.
# You must call with with '#!python test.py' or 'r2 -i test.py ..'

import r2lang
from dfuexec import *

FAKESIZE = 512

device = None

def pyio(a):
	def _open(path, rw, perm):
		global device
		device = dfu.acquire_device()
		serial_number = device.serial_number
		dfu.release_device(device)
		device = PwnedDFUDevice()
		print("MyPyIO Opening %s"%(path))
		return 1234 
	def _check(path, many):
		print("python-check %s"%(path))
		return path[0:9] == "pwndfu://"
	def _read(offset, length):
		global device
		res = device.read_memory(address, length)
		print("python-read")
		return res
	def _seek(offset, whence):
		print("python-seek")
		if whence == 0: # SET
			return offset
		if whence == 1: # CUR
			return offset
		if whence == 2: # END
			return ROM_SIZE
		return ROM_SIZE
	def _write(offset, data, length):
		print("TODO: python-write")
		return True
	def _system(cmd):
		print("pwndfu://%s"%(cmd))
		return True
	return {
		"name": "pwndfu",
		"license": "GPL",
		"desc": "pwndfu IO plugin (pwndfu://3)",
		"check": _check,
		"open": _open,
		"read": _read,
		"seek": _seek,
		"write": _write,
		"system": _system,
	}

print("Registering Python IO plugin...")
print(r2lang.plugin("io", pyio))
