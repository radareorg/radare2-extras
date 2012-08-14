# r2w helper api

r2w_title = "<a href=/>r2w</a>: python libr web frontend"

def r2w_header(title=r2w_title):
	return """
<html><head><title>r2w</title></head><body>
<div style="width:100%%"><h2>%s</h2></div>
<hr size=1 width="100%%" />
"""%(title)

def r2w_footer():
	return """
<hr size=1 width=100% />
<tt>--pancake</tt>
</body></html>
"""

def get_arg(args, name, default):
	try:
		value = args[name][0]
	except:
		value = default
	return value

def get_var(args, name, default):
	try:
		value = args[name]
	except:
		value = default
	return value

def slurp(file):
	try:
		f = open (file, "r")
		output = f.read()
		f.close()
		return output
	except:
		return ""

def escape(s, quote=None):
	'''Replace special characters "&", "<" and ">" to HTML-safe sequences.
	If the optional flag quote is true, the quotation mark character (")
	is also translated.'''
	s = s.replace("&", "&amp;") # Must be done first!
	s = s.replace("<", "&lt;")
	s = s.replace(">", "&gt;")
	if quote:
		s = s.replace('"', "&quot;")
	return s

def filter(str, arr):
	try:
		str = str.replace("&0", arr[0])
		str = str.replace("&1", arr[1])
		str = str.replace("&2", arr[2])
		str = str.replace("&3", arr[3])
	except:
		pass
	return str

def filter_many(str,arr):
	try:
		for a in arr:
			str = str.replace(a[0], a[1])
	except:
		pass
	return str

def filter_tags(str,arr):
	for a in arr:
		a[0] ="<!--("+a[0]+")-->"
	return filter_many(str,arr)

class Mvc():
	def to_string(self):
		str = filter(self.view[0], self.model[0])
		for m in self.model[1]:
			str += filter(self.view[1], m)
		str += filter(self.view[2], self.model[2])
		return str

	def __init__(self,model=[],view=[],control=to_string):
		self.model = model
		self.view = view
		self.control = control

class Menu(Mvc):
	def __init__(self):
		Mvc.__init__(self)
		self.view = [
			"( &0\n",
			" <a href=\"&1\">&0</a>\n",

			")"
		]

class MenuPopup(Mvc):
	def __init__(self):
		Mvc.__init__(self)
		self.view = [
			"( &0\n",
			" <a href=\"#\" onclick=\"$('#&1').click()\">&0</a>\n",

			")"
		]

class MenuList(Mvc):
	def __init__(self):
		Mvc.__init__(self)
		self.view = [
			"( &0 )\n",
			"<div id='line'>&0</div>\n",
			"<hr size=1 width=100% />"
		]

# MVC DEMO #
def main():
	#mainmenu = MVC()
	mainmenu = Menu()
	mainmenu.model = [
		[ "food" ],
		[
			[ "open", "/q/open" ],
			[ "save", "/q/save" ],
			[ "export", "/q/export" ],
		],
		[],
	]
	#mainmenu.view = [
	#	"<div><h2>&0</h2>\n",
	#	" (<a href=\"&1\">&0</a>)\n",
	#	"</div>"
	#]
	print mainmenu.to_string()
#main()
