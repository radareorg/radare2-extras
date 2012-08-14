from r2.r_bin import *

try:
	code = ""
	b=RBin ()
	b.load ("/bin/ls", None)
	baddr = b.get_baddr ()
	for i in b.get_imports ():
		code += "offset=0x%08x va=0x%08x name=%s</br>" % (
				i.offset, baddr+i.rva, i.name)
except:
	code = ""

output = """
<html>
<tt>
<h2><a href="/">r2w</a> : RBin demo</h2>

%s
"""%(code)
