#! /usr/bin/env python
# r2w daemon
# pancake <nopcode.org>

import os
import sys
from SocketServer import ForkingMixIn, ThreadingMixIn
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from r2w import escape
from runpy import run_module
from urlparse import urlparse
from cgi import parse_qs #, parse_header, parse_multipart
import cgi
from r2.libr import RCore

port = 8080
wwwroot = "www"
http = {} # global storage
core = RCore()
core.loadlibs()
core.cmd0("e scr.color=false")
# FILE
#core.file_open("/bin/ls", False)
# DEBUG
file = core.file_open("dbg:///bin/ls", False)
core.cmd0("e cfg.debug=true")
core.cmd0("e io.ffio=true")
#core.cmd0("dpf")
core.cmd0("dr")
core.cmd0("? esp")

import r2.r_cons
r2.r_cons.r_cons_flush()

#core.dbg.use("native")
#core._cmd("e scr.html=true", 0)

class ForkingTCPServer(ForkingMixIn, HTTPServer): pass
class ThreadingTCPServer(ThreadingMixIn, HTTPServer): pass

def print_exception(type=None, value=None, tb=None, limit=None):
	if type is None:
		type, value, tb = sys.exc_info()
	import traceback
	ret = "<html><body><h2>Traceback (most recent call last):<h2 />"
	ret += "<pre>"
	list = traceback.format_tb(tb, limit) + \
		traceback.format_exception_only(type, value)
	ret += "%s: %s<br/>\n" % (
		escape("\n".join(list[:-1])),
		escape(list[-1]),
		)
	ret +="</body></html>"
	del tb
	return ret

class HttpHandler(BaseHTTPRequestHandler):
	# TODO: whitelist out there
	def client_not_allowed(self, addr):
		return False
		if addr == "127.0.0.1":
			return False
		print "Client not allowed %s\n"%addr
		return True 

	def serve(self):
		output = ""
		uri = self.path
		tmp = uri.find ('?')
		args = parse_qs(urlparse(uri)[4])

		#from ipdb import set_trace;set_trace()
		if tmp != -1:
			uri = uri[0:tmp]
			for a in uri[tmp:-1].split("&"):
				sep = a.find ("=")
				if sep != -1:
					print "%s)(%s"%(a[0:sep],a[sep:-1])
					args[a[0:sep]]=a[sep:-1]
		
		file = wwwroot + "/" + uri
		if self.client_not_allowed (self.client_address[0]):
			self.wfile.write ("HTTP/1.0 503 Not allowed\r\n\r\nYou are not whitelisted")
			return
		content = ""
		try:
			ctype,pdict = cgi.parse_header(self.headers.getheader('content-type'))
			print "CTYPE IS ",ctype
			if ctype == 'multipart/form-data':
				query = cgi.parse_multipart(self.rfile, pdict)
				content = query.get('upfile')
		except:
			pass
		print "Request from %s:%d"%self.client_address+"  "+uri
		if uri[-1] == '/' or os.path.isdir(file):
			file = file + "/index.py"
		if os.path.isfile(file+".py"):
			file = file + ".py"
		if file.find("py") != -1:
			modname = file.replace(".py", "")
			cwd = modname[0:modname.rfind('/')]+"/"
			modname = modname.replace("/", ".")
			while modname.find("..") != -1:
				modname = modname.replace("..",".")
			globals = {
				"output": output,
				"http": http,
				"uri": uri,
				"args": args,
				"cwd": cwd,
				"core": core,
				"headers": self.headers,
				"content": content
			}
			try:
				a = run_module(modname, init_globals=globals)
				output = a["output"]
			except:
				output = print_exception()
		else:
			try:
				f = open (file, "r")
				output = f.read ()
				f.close ()
			except:
				output = "404"
		if output == "404":
			self.wfile.write ("HTTP/1.0 404 Not found\r\n\r\n")
		else:
			self.wfile.write ("HTTP/1.0 200 OK\r\n\r\n")
			self.wfile.write (output)

	def do_POST (self):
		self.serve ()

	def do_GET (self):
		self.serve ()

#httpd = ThreadingTCPServer(('', port), HttpHandler)
#httpd = ForkingTCPServer(('', port), HttpHandler)
httpd = HTTPServer(('', port), HttpHandler)
print "http://127.0.0.1:%d/ : Serving directory '%s/www'" % (port, os.getcwd())

try:
	httpd.serve_forever()
except KeyboardInterrupt:
	print 'Server killed on user request (keyboard interrupt).'
