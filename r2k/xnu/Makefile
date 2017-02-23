#CC=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -x c
KEXTDIR=r2k.kext/Contents/
BIN=$(KEXTDIR)/MacOS/r2k
PLIST=$(KEXTDIR)/Info.plist

#CFLAGS+=-framework Kernel
CFLAGS+=-I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.12.sdk/System/Library/Frameworks/Kernel.framework/PrivateHeaders -I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.12.sdk/System/Library/Frameworks/Kernel.framework/Headers

# Kernel stuff
CFLAGS+=-nostdinc
CFLAGS+=-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.12.sdk
CFLAGS+=-DKERNEL
CFLAGS+=-DKERNEL_PRIVATE
CFLAGS+=-DDRIVER_PRIVATE
CFLAGS+=-DAPPLE

# Linking things
LDFLAGS+=-static
LDFLAGS+=-Xlinker -kext
LDFLAGS+=-nostdlib
LDFLAGS+=-lkmod
LDFLAGS+=-lcc_kext 

CFLAGS+=-arch x86_64
CFLAGS+=-mmacosx-version-min=10.8

# Required for C++
#CXXFLAGS+=-fapple-kext
#LDFLAGS+=-lkmodc++
#LDFLAGS+=-stdlib=libc++

all: $(KEXTDIR) $(PLIST)
	$(CC) -o $(BIN) $(CFLAGS) $(LDFLAGS) main.c
	codesign -s CD71EBC2BC289A6B9FD3C2D5C9F0ED9234955224 $(BIN)

foo:
	kextlibs -xml r2k.kext

$(PLIST): $(KEXTDIR)
	cp -f Info.plist $(PLIST)
	#builtin-infoPlistUtility Info.plist -expandbuildsettings -platform macosx -o $(PLIST)

$(KEXTDIR):
	mkdir -p $(KEXTDIR)/MacOS

clean:
	sudo rm -rf r2k.kext

try:

install:
	sudo chmod -R 755 r2k.kext
	sudo chown -R root:wheel r2k.kext
	sudo kextload r2k.kext || sudo kextutil -n -print-diagnostics r2k.kext

uninstall:
	sudo kextunload r2k
