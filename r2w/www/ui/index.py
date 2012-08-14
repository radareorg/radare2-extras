from r2w import *

print "loadng esp"
esp=core.cmd_str("? esp").split(' ')[0]
menu = MenuPopup ()
menu.model = [
		[ "menu" ],
		[
			[ "new", "toggle-popup" ],
			[ "save", "toggle-popup-save" ],
			[ "export", "toggle-popup-export" ],
			[ "options", "toggle-popup-options" ],
		],
		[],
	]

page = [
	[ "menu", menu.to_string() ]
]
output = slurp(cwd+"index.html")
output = output.replace("<!--(esp)-->", esp)
output = filter_tags(output,page)
