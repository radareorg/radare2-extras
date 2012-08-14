from r2w import *

cmd = get_arg(args, "action", "")
if cmd == "step":
	core.cmd_str("ds")
elif cmd == "continue":
	core.cmd_str("dc")
core.cmd_str(".dr*")
regs = core.cmd_str("dr")
stak = core.cmd_str("px 64@esp")
def disasm(addr):
	return core.cmd_str("pd 80@%s"%addr)

delta = get_arg(args, "delta", "")
if delta == "":
	delta = 0
else:
	try:
		delta = int(delta)
	except:
		delta = 0
code = disasm("eip+%d"%delta)

def drawlines(code):
	out = ""
	for line in code.split("\n"):
		try:
			parts = line.split("0x");
			foo=parts[1] # exceptions are fun
			foo=parts[0]
			foo = foo.replace('>','<img src=/img/line-arrow-right.gif>')
			foo = foo.replace('  ','<img src=/img/line-empty.gif><img src=/img/line-empty.gif>')
			foo = foo.replace('--','<img src=/img/line-horitzontal2.gif><img src=/img/line-horitzontal2.gif>')
			foo = foo.replace('==','<img src=/img/line-horitzontal.gif><img src=/img/line-horitzontal.gif>')
			foo = foo.replace(' .',' <img src=/img/line-corner-down.gif>')
			foo = foo.replace('`','<img src=/img/line-corner-up.gif>')
			foo = foo.replace('|','<img src=/img/line-vertical.gif>')
			out += foo + "<br />"
		except:
			pass
	return out 

draw = drawlines(code)

#r2w_header("Debugger demo") + """
output = """
<html><body><tt>
<h2><a href="/">r2w</a> : Assembler demo</h2>
<a href="?delta=%d">[up]</a>
<a href="?delta=%d">[down]</a>
<a href="?action=step">[step]</a>
<!-- <a href="?action=continue">[continue]</a> -->
<br />
<table>
<tr><td style='background-color:#f0f0f0' valign="top"><pre>%s</pre></td>
    <td style='background-color:#e0f0e0' rowspan=2 valign=top>
    <pre>%s</pre><hr size=1 />%s
</td></tr>
<tr><td valign=top><pre>%s</pre></td></tr>
</table>
</tt>
"""%(delta-40,delta+40,stak, regs, draw, code) + r2w_footer()
