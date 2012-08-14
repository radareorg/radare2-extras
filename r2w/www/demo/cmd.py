from r2w import get_arg

cmd = get_arg(args, "cmd", "")
if cmd != "":
	out = core.cmd_str(cmd)
else: out = ""

output = """
<html><body><tt>
<h2><a href="/">r2w</a> : Assembler demo</h2>
<form method="get" action="?">
Command:
  <input value="%s" name="cmd">
<input type=submit>
</form>
<br /><pre>%s</pre>
</tt></body></html>
"""%(cmd, out)
