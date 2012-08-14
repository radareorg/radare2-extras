from r2.r_hash import RHash, Size_MD5

try:
	msg = args["msg"][0]
	# TODO: we should open this once
	h = RHash(False)
	ret = h.do_md4 (msg, len(msg)-1)
	result = ""
	for i in range(0, Size_MD5):
		result += "%02x"%ord(ret[i])
except:
	msg = ""
	result = ""

output = """
<html>
<tt>
<h2><a href="/">r2w</a> : Assembler demo</h2>

<form method="get" action="?">
Message:
  <input value="%s" name="msg">
<input type=submit>
</form>

<br />MD5: %s
</tt>
</html>
"""%(msg, result)
