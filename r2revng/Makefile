all:
	docker build --platform linux/amd64 -t revng:0.1 .

demo: all
	gcc -o demo demo.c
	docker run --rm --platform linux/amd64 -i revng:0.1 /revng.sh < demo

shell:
	docker run --platform linux/amd64 -it revng:0.1 /usr/bin/bash

.PHONY: demo run all
