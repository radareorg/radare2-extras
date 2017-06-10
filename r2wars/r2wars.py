#!/usr/bin/env python

import r2pipe
import sys
import time


uidx = 0
user = []

r2 = r2pipe.open('malloc://4096')
#r2 = r2pipe.open('/bin/ls')
r2.cmd("e asm.arch=x86")
r2.cmd("e asm.bits=32")
r2.cmd("e scr.color=true")
r2.cmd("aei")
r2.cmd("aeim")
addr = 0
for a in sys.argv[1:]:
	src = r2.syscmd("rasm2 -f %s"%(a)).strip()
	if src == "":
		print("Invalid source")
		sys.exit(1)
	r2.cmd("wx %s @ %s"%(src, addr))
	print("wx %s @ %s"%(src, addr))
	r2.cmd("aer PC =%s"%(addr))
	r2.cmd("aer SP =SP+%s"%(addr))
	initRegs = r2.cmd("aeR")
	user.append (initRegs)
	addr += 100 # must be random
	print a

if len(user) < 2:
	print("You need at least 2 users")
	sys.exit(1)


r2.cmd("e cmd.esil.todo=f theend=1")
r2.cmd("e cmd.esil.trap=f theend=1")
r2.cmd("e cmd.esil.intr=f theend=1")
r2.cmd("e cmd.esil.ioer=f theend=1")
r2.cmd("f theend=0")

print r2.cmd("b 1024")

def showMemory():
	print r2.cmd("?eg 0 0")
	#print r2.cmd("e hex.cols=32")
	#res = r2.cmd("px 200 @ 0") + "\n"
	res = r2.cmd("prc 200 @ 0") + "\n"
	res += r2.cmd("aer")
	print "\x1b[2J %s"%(uidx)
	print res
	#print r2.cmd("e hex.cols=16")

def stepIn():
	global uidx
	print r2.cmd("pi 1 @r:PC")
	r2.cmd("aes")
	user[uidx] = r2.cmd("aerR").replace("\n", ";")

def loadUserCode():
	print "LOAD"

def switchUser():
	global uidx
	uidx = uidx + 1
	if uidx >= len(user):
		uidx = 0
	r2.cmd(user[uidx])

def shell():
	while True: print(r2.cmd(raw_input()))

while True:
	te = r2.cmd("?v 1+theend").strip()
	print "TE %s %s"%(uidx, te)
	if te != "" and te != "0x1":
		print ("USER %s DIE at %s"%(uidx, te))
		del user[uidx]
		if len(user) < 2:
			print ("LAST USER WON")
			break
		#shell()
	showMemory()
	stepIn()
	switchUser()
	time.sleep(0.2)
