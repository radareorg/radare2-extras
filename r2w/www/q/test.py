from r2w import *
from r2.r_bin import *

foo=get_arg(args, 'q', '')
output="<div class='work-zone'>"
output+="<h2>"+foo+"</h2>\n"
if foo == "Imports":
	# TODO: Use it from RCore or GTFO
	b=RBin ()
	b.load ("/bin/ls", None)
	baddr = b.get_baddr ()
	for i in b.get_imports ():
		#output += "<a href='#'>%s</a><br />\n"%(i.name)
		output += """<a id="jsCall%s" onclick="javascript:loadhex('imp.%s');" class="js_calls" href='#'>%s</a><br />\n"""%(i.name, i.name,i.name)
		#i.offset, baddr+i.rva, i.name)
elif foo == "Sections":
	# TODO: Use it from RCore or GTFO
	b=RBin ()
	b.load ("/bin/ls", None)
	baddr = b.get_baddr ()
	for i in b.get_sections():
		output += """<a id="jsCall%s" onclick="javascript:loadhex('section.%s');" class="js_calls" href='#'>%s</a><br />\n"""%(i.name,i.name,i.name)
elif foo == "File":
	b=RBin ()
	b.load ("/bin/ls", None)
	info = b.get_info()
	output += "<b>File</b>: /bin/ls<br />\n"
	output += "<b>Type</b>: %s<br />\n"%info.type
	output += "<b>Class</b>: %s<br />\n"%info.rclass
	output += "<b>Arch</b>: %s<br />\n"%info.arch
	output += "<b>Mach</b>: %s<br />\n"%info.machine
	output += "<b>OS</b>: %s<br />\n"%info.os
	output += "<b>SubSystem</b>: %s<br />\n"%info.subsystem
	if info.big_endian == 0:
		output += "<b>Endian</b>: little<br />\n"
	else:
		output += "<b>Endian</b>: big<br />\n"
elif foo == "Symbols":
	# TODO: Use it from RCore or GTFO
	b=RBin ()
	b.load ("/bin/ls", None)
	baddr = b.get_baddr ()
	for i in b.get_symbols ():
		#output += "<a href='#'>%s</a><br />\n"%(i.name)
		output += """<a id="jsCall%s" onclick="javascript:loadhex('imp.%s');" class="js_calls" href='#'>%s</a><br />\n"""%(i.name, i.name,i.name)
		#i.offset, baddr+i.rva, i.name)
else:
	output+="Nothing here"
output+="</div>"
