#!/usr/bin/env python3
# use cmsis-svd python api to load the SVD peripheral and memory layout into r2
# --pancake @ 2020-2023

import json
import sys
import math
import os.path
import importlib
from cmsis_svd.parser import SVDParser

argc = len(sys.argv)

args_ok = False
if argc == 2 and os.path.isfile(sys.argv[1]):
	args_ok = True
	
if argc == 3:
	args_ok = True

if not args_ok:
	try:
		if argc == 1:
			vendors = importlib.resources.listdir("cmsis_svd", "data")
			print('\n'.join(vendors))
		elif argc == 2:
			svds = importlib.resources.listdir("cmsis_svd", "data/%s"%(sys.argv[1]))
			print('\n'.join(svds))
		else:
			raise Exception('')
	except:
		print('Usage: .!r2svd [mcu] [svd]')
		sys.exit(1)
	sys.exit(0)

def filter_name(n):
	n = n.replace(';', '.')
	n = n.replace('@', '')
	n = n.replace(' ', '')
	n = n.replace('"', '')
	n = n.replace('/', '')
	n = n.replace('(', '')
	n = n.replace('\n', '')
	n = n.replace(')', '')
	return n

def filter_message(n):
	n = n.replace('\n', '')
	n = n.replace('  ', ' ')
	return n

svdfile = sys.argv[1]
if os.path.isfile(svdfile):
	parser = SVDParser.for_xml_file(svdfile)
else:
	mcu = sys.argv[1] # Freescale
	svd = sys.argv[2] # MK20D7.svd
	parser = SVDParser.for_packaged_svd(mcu, svd)

supports_call = False
try:
	import r2pipe
	r2 = r2pipe.open("-")
	supports_call = int(r2.cmd("?Vn")) >= 50800
except Exception as e:
	pass

def print_flag(name, size, addr):
	if supports_call:
		print("\"\"f %s %d 0x%x"%(filter_name(name), size, addr))
	else:
		print("f %s %d 0x%x"%(filter_name(name), size, addr))

def print_comment(msg, addr):
	if supports_call:
		print("\"\"@0x%x\"\"CC %s"%(addr, filter_message(msg)))
	else:
		print("CC %s @ 0x%x"%(filter_name(msg), addr))

svd_dict = parser.get_device().to_dict()
for p in svd_dict['peripherals']:
	addr = p['base_address']
	try:
		size = p['address_block']['size'] / 8
	except:
		size = 4
	print_comment(p['description'], addr)
	print_flag(p['name'], size, addr)
	s = ""
	for r in p['registers']:
		offs = int(r['address_offset'])
		at = int(addr) + math.floor(offs / 8)
		bt = (offs % 8)
		s += " " + r['name']
		if at != addr:
			fname = "%s.%s"%(p["name"], r["name"])
			print_flag(fname, size, at)
	print_comment(s, addr)

# print(json.dumps(svd_dict, sort_keys=True, indent=4, separators=(',', ': ')))
