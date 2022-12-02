all: node_modules
	tsc test.ts
	gcc hello.c -o hello
	# r2 -c 'af' -c '$$ai=. test.js' -i test.js hello
	r2 -c 'af' -c '$$ai=. test.js' hello

node_modules:
	mkdir -p node_modules
	npm i
