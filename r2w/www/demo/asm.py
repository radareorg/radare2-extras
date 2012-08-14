from r2.r_asm import RAsm

try:
	arch = args["arch"][0]
	code = args["code"][0]
	# TODO: we should open this once
	a=RAsm()
	a.use (arch)
	bytes = a.massemble(code).buf_hex

except:
	code = ""
	bytes = ""
	arch = "x86.olly"

output = """
<html>
<tt>
<h2><a href="/">r2w</a> : Assembler demo</h2>

<form method="get" action="?">
Architecture:
  <select name="arch">
    <option >x86.olly</option>
    <option >java</option>
    <option >x86</option>
  </select>
<br />
Opcode:
  <input value="%s" name="code">
<input type=submit>
</form>

<br />Host: %s
<br />bytes: %s
</tt>
</html>
"""%(code, headers.get("Host"), bytes)
