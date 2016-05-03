#!/usr/bin/env python
#
# r2bly : The Binarly extension for Radare2
#
#  Author: pancake <@nopcode.org>
#  License: MIT
#

import os
import sys
import r2pipe
import signal
import base64

try:
    from BinarlyAPIv1 import BinarlyAPI, hex_pattern, ascii_pattern, wide_pattern, build_query
except ImportError:
    print("Error importing BinarlyAPI. You can find it here https://github.com/binarlyhq/binarly-sdk")
    sys.exit(1)

def signal_handler(signal, frame):
        print '^C'
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

APIKEY_FILENAME = 'apikey.txt'
APIKEY_PATH = os.path.join(os.path.dirname(__file__), APIKEY_FILENAME)

def get_api_key():
	with open(APIKEY_PATH, 'r') as fhandle:
		return fhandle.readline().strip()
	return None

APIKEY  = get_api_key()
PROJECT = "r2binarly"
usehttp = False

if not APIKEY:
	print "No apikey.txt"
	sys.exit(1)

def query_hex(xxxx, limit):
	query = []
	query.append(hex_pattern(xxxx))
	result = bly.search(query, limit=limit, exact=False)
	if result.has_key('error'):
		print ("Error" + result['error']['message'])
		return
	return result

def get_metadata(xxxx):
	m = {}
	meta = bly.get_metadata(xxxx)
	try:
		#print meta
		M = meta[xxxx]['version_info']
		m['fn'] = M['original_file_name']
		m['fd'] = M['file_description']
	except:
		m['fn'] = ""
		m['fd'] = ""
		pass #raise
	return m 

def get_bytes(a, l):
	return r2p.cmd("p8 %s@%s"%(l,a)).strip()

def query_all_imports(limit, wide):
	query = []
	imps = r2p.cmdj("iij")
	for i in imps:
		n = i['name']
		pos = n.find('.dll_')
		if pos != -1:
			n = n[pos + 5:]
		print n
		if wide:
			query.append(wide_pattern(n))
		else:
			query.append(ascii_pattern(n))
	result = bly.search(query, limit=limit, exact=True)
	if result.has_key('error'):
		print ("Error" + result['error']['message'])
		return
	return result

def query_all_functions(limit, maxlen, every):
	query = []
	fcns = r2p.cmdj("aflj")
	for f in fcns:
		if f['size'] > maxlen:
			print "skip"
			continue
		b = get_bytes(f['offset'], f['size'])
		print "0x%x  %5d  %20s  %s"%(f['offset'], f['size'], f['name'], b)
		query.append(hex_pattern(b))
		if every:
			result = bly.search(query, limit=limit, exact=True)
			if result.has_key('error'):
				print ("Error" + result['error']['message'])
			else:
				show_results(result)
			query = []
	if every:
		return None
	result = bly.search(query, limit=limit, exact=True)
	if result.has_key('error'):
		print ("Error" + result['error']['message'])
		return
	return result

def query_all_strings(minlen, limit):
	query = []
	strs = r2p.cmdj("izj")
	for s in strs:
		if s['length'] > minlen:
			msg = base64.b64decode(s['string'])
			print msg
			if s['type'] == 'ascii':
				query.append(ascii_pattern(msg))
			elif s['type'] == 'wide':
				query.append(wide_pattern(msg))
			else:
				print "Unknown/unhandled string type %s"%(s['type'])
	result = bly.search(query, limit=limit, exact=False)
	if result.has_key('error'):
		print ("Error" + result['error']['message'])
		return
	return result

def show_results(res):
	for r in res['stats']:
		print("# %20s %s"%(r, res['stats'][r]))
	for r in res['results']:
		sys.stdout.write("%s  %8d  %s"%(r['sha1'], r['size'], r['label']))
		m = get_metadata(r['sha1'])
		print "  %s %s %s"%(m['fn'], ' '*(20 - len(m['fn'])), m['fd'])

bly = BinarlyAPI(api_key=APIKEY, use_http=usehttp, project=PROJECT)
r2p = r2pipe.open('#!pipe')

def halp():
	print "Usage: r2bly [op] [...]"
	print "  Binarly extension for radare2 delivered by pancake."
	print "Operations:"
	print "  fcn      - find all functions smaller than X"
	print "  hex (..) - find files matching given hexpairs"
	print "  imp      - find files matching all imports"
	print "  sha [..] - identify current file or given hash by using the sha1"
	print "  str      - find which files contain all long strings"
	print "  key      - set api key"
	print "Radare2:"
	print "  \"$r2bly=#!pipe python test.py\""
	print "  $r2bly str"

if len(sys.argv) < 2:
	halp()
	sys.exit(1)

op = sys.argv[1]
res = None

if op == 'str':
	res = query_all_strings(20, 10)
elif op == 'sha':
	msg = ""
	if len(sys.argv) < 3:
		fn = r2p.cmd('i~^file[1]')
		msg = r2p.syscmd("rahash2 -qa sha1 "+fn).split(' ')[0]
	else:
		msg = sys.argv[2]
	print "sha1 %s"%(msg)
	m = get_metadata(msg)
	if not m['fd'] and not m['fn']:
		print "unknown"
	else:
		print "%s  %s"%(m['fn'], m['fd'])
	sys.exit(0)
elif op == 'imp':
	res = query_all_imports(10, False)
elif op == 'fcn':
	res = query_all_functions(10, 100, True)
elif op == 'hex':
	res = query_hex(sys.argv[2], 10)
elif op == 'key':
	if len(sys.argv) < 3:
		print APIKEY
		res = sys.stdin.readline().strip()
	else:
		res = sys.argv[2]
	if res:
		with open(APIKEY_PATH, 'w') as fd:
			fd.write("%s\n"%(res))
	sys.exit(0)
else:
	halp()

if res:
	show_results(res)
