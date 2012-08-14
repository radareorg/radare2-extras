from r2w import *

num = get_var(http, "num", 0)
http["num"] = num

output = r2w_header() + """
&nbsp; <img src=img/go-next.png> <a href="ui">New project</a><br />
&nbsp; <img src=img/go-next.png> <a href="">Open project</a><br />
&nbsp; <img src=img/go-next.png> <a href="demos">Demos</a><br />
&nbsp; <img src=img/go-next.png> <a href="upload">Upload</a><br />
""" + r2w_footer()
