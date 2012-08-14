from r2w import *

output = r2w_header() + """
<form enctype="multipart/form-data" action="?" method="POST">
<input type=file name=upfile />
<br />
"""

if content != "":
	output += "File contents: %s"%content
else:
	output += "No file uploaded."

output +="""
<input type=submit value=Upload />
</form>
""" + r2w_footer()
