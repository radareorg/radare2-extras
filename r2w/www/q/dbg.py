from r2w import *

core._cmd(".dr*", False)
def disasm():
	ret = core.cmd_str("pd 256@eip")
	out = ""
	for a in ret.split('\n'):
		out += "<div class=\"line\">%s</div>"%escape(a)
	return out

foo=get_arg(args, 'q', '')
off=get_arg(args, 'off', '')
if foo == "get":
	value = core.cmd_str("? %s"%off).split(' ')[0]
	output = "%s"%value
elif foo == "regs":
	output = "( regs <a href='#' onclick=\"$('#panel-regs').change()\">load</a> save ) <br />\n"
	output += core.cmd_str("dr").replace("\n","<br />")
elif foo == "stack":
	#core._cmd(".dr*", False)
	#core._cmd("b 512", False) # RACY!!
	if off == "":
		for a in core.cmd_str("px 256@esp").split('\n'):
			output+= "<div class='line'>%s</div>"%escape(a)
	else:
		for a in core.cmd_str("px 256@%s"%off).split('\n'):
			output+= "<div class='line'>%s</div>"%escape(a)
elif foo == "code":
	#output = "<script type='text/javascript' src='ui/etc/js/jquery-1.4.min.js'></script>"
	#output +="<script type='text/javascript' src='ui/etc/js/r2w.js'></script>"
	output = disasm()
elif foo == "step":
	print "STEP"
	core.cmd_str("ds")
else:
	output = "NOP"
