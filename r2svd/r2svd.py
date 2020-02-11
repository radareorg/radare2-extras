#!/usr/bin/env python3
# use cmsis-svd python api to load the SVD peripheral and memory layout into r2
# --pancake @ 2020

import json
import sys
import math
import pkg_resources
from cmsis_svd.parser import SVDParser

argc = len(sys.argv)
if argc != 3:
	try:
		if argc == 1:
			vendors = pkg_resources.resource_listdir("cmsis_svd", "data")
			print('\n'.join(vendors))
		elif argc == 2:
			svds = pkg_resources.resource_listdir("cmsis_svd", "data/%s"%(sys.argv[1]))
			print('\n'.join(svds))
		else:
			raise Exception('')
	except:
		print('Usage: .!r2svd [mcu] [svd]')
		sys.exit(1)
	sys.exit(0)


mcu = sys.argv[1] # Freescale
svd = sys.argv[2] # MK20D7.svd

parser = SVDParser.for_packaged_svd(mcu, svd)
svd_dict = parser.get_device().to_dict()
for p in svd_dict['peripherals']:
	addr = p['base_address']
	size = p['address_block']['size'] / 8
	print("CC %s @ 0x%x"%(p['description'], addr))
	print("f %s %d 0x%x"%(p['name'], size, addr))
	s = ""
	for r in p['registers']:
		offs = int(r['address_offset'])
		at = int(addr) + math.floor(offs / 8)
		bt = (offs % 8)
		s += " " + r['name']
		if at != addr:
			print("f %s.%s %d 0x%x"%(p['name'], r['name'], size, at))
		# print("   0x%x %d %s"%(at, bt, r['name']))
	print("CC (%s) @ 0x%x"%(s, addr))

# print(json.dumps(svd_dict, sort_keys=True, indent=4, separators=(',', ': ')))
