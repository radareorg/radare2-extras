#!/usr/bin/env python3
# use cmsis-svd python api to load the SVD peripheral and memory layout into r2
# --pancake @ 2020-2024

import json
import base64
import sys
import math
import os.path
import importlib

script_dir = os.path.dirname(os.path.realpath(__file__))
newpypath = script_dir + "/cmsis-svd/python"
sys.path.append(newpypath)

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
	r2 = r2pipe.open("malloc://1")
	supports_call = int(r2.cmd("?Vn")) >= 50800
except Exception as e:
	pass

def print_flag(name, size, addr):
	if supports_call:
		print("'f %s %d 0x%x"%(filter_name(name), size, addr))
	else:
		print("f %s %d 0x%x"%(filter_name(name), size, addr))

def print_bitfield(addr, size, fmt):
	if supports_call:
		print("'@0x%x'Cr %d pfb %s"%(addr,size,fmt))

def print_comment(msg, addr):
	if supports_call:
		print("'@0x%x'CC %s"%(addr, filter_message(msg)))
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
	pname = p['name']
	print_flag(f"peripheral.{pname}", size, addr)
	s = ""
	cmt = []
	bfsize = 0
	for r in p['registers']:
		fmt = ""
		nam = ""
		bfsize = r['size'] / 8
		rname = r['name']
		if 'description' in r:
			c = r['description']
			cmt.append(f"{pname}.{rname}: {c}")
		offs = int(r['address_offset'])
		at = int(addr) + offs # math.floor(offs / 8)
		bt = (offs % 8)
		if at != addr:
			fname = "reg.%s.%s"%(pname, rname)
			print_flag(fname, size, at)
			if len(cmt) > 0:
				c = base64.b64encode(bytes("\n".join(cmt), "utf-8"))
				print_comment("base64:" + c.decode("utf-8"), at)
				cmt = []
		for f in r['fields']:
			fname = f['name']
			of = f['bit_offset']
			wi = f['bit_width']
			nam = f"{nam} {fname}"
			fmt = f"{fmt}{wi}b"
			# TODO. bit offset ignored. we are assuming fields are sorted properly
		print_bitfield(at, bfsize, f"{fmt}{nam}")
		fmt=""
		nam=""

# print(json.dumps(svd_dict, sort_keys=True, indent=4, separators=(',', ': ')))
