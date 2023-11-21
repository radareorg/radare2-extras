project('bin-gguf', 'c', license : 'MIT', meson_version : '>=1.00', version : '0.1.0')

r2_plugdir = run_command('r2', '-H', 'R2_USER_PLUGINS', check: true).stdout().strip()

sources = [ 'src/bin_gguf.c' ]
lib = library('bingguf', sources,
	dependencies : [
		dependency('r_bin')
	],
	install_dir: r2_plugdir,
	install: true
)
