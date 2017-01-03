all:
	cargo build --release
	mkdir -p ~/.config/radare2/plugins
	cp -f target/release/libasm_6502_rs.dylib ~/.config/radare2/plugins/

uninstall:
	rm -f ~/.config/radare2/plugins/libasm_6502_rs.dylib

clean:
	cargo clean
