all:

bea-sync:
	rm -rf bea
	rm -rf b
	git clone https://github.com/BeaEngine/beaengine b
	mkdir bea
	cp -rf b/src/BeaEngine.c bea
	cp -rf b/headers/Includes bea
	cp -rf b/headers/BeaEngine.h bea
	cp -rf b/include bea
	mkdir -p bea/src/
	cp -rf b/src/Includes bea/src
	cp -f b/src/COPYING* bea
	git add bea
	rm -rf b

sync: bea-sync
