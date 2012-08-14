from r2w import *

num = get_var(http, "num", 0)
http["num"] = num

output = r2w_header() + """
&nbsp; <img src=img/go-next.png> <a href="demo/hash">Hash</a><br />
&nbsp; <img src=img/go-next.png> <a href="demo/asm.py">Assembler</a><br />
&nbsp; <img src=img/go-next.png> <a href="demo/bin.py">Bin</a><br />
&nbsp; <img src=img/go-next.png> <a href="demo/cmd.py">Core commands</a><br />
&nbsp; <img src=img/go-next.png> <a href="demo/dbg.py">Debugger</a><br />
""" + r2w_footer()
