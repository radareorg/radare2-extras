#!/usr/bin/env python

import re
import curses
import r2pipe
import sys
import time
import random


ctr = 0
uidx = 0
user = []
name = []
wins = []
size = []
orig = []
stdscr = None

memsize = 1024
maxprogsize = 64
r2 = r2pipe.open('malloc://%d'%(memsize))
#r2 = r2pipe.open('/bin/ls')
r2.cmd("e asm.arch=x86")
r2.cmd("e asm.bits=32")
r2.cmd("e scr.color=true")
r2.cmd("aei")
r2.cmd("aeim")

def get_random_offsets():
	while True:
		rand = []
		addr = random.randint(0, memsize - maxprogsize)
		for a in sys.argv[1:]:
			rand.append(addr)
			addr = addr + random.randint(maxprogsize, maxprogsize + 300)
			if addr + maxprogsize > memsize:
				print "ERROR: Not enough memory"
				continue # sys.exit(1)
		random.shuffle(rand)
		break
	return rand

def userScreen(c):
	global user, uidx, name, orig
	r2.cmd(user[uidx])
	#print r2.cmd("?eg 0 0")
	#print r2.cmd("e hex.cols=32")
	#res = r2.cmd("pxa 200 @ 0") + "\n"
	res = ''
	res += "USER %s\n"%(name[uidx])
	res += r2.cmd("aer") + "\n"
	res += r2.cmd("%s %d @ 0"%(c, memsize)) + "\n"
	res += r2.cmd("pxw 32 @r:SP") + "\n"
	res += r2.cmd("pD %d @ %s"%(size[uidx], orig[uidx]))
	#print("(((%s)))"%(user[uidx]))
	return res
	#print r2.cmd("e hex.cols=16")

def stepIn():
	global user, uidx
	#print r2.cmd("pi 1 @r:PC")
	r2.cmd("aes")
	user[uidx] = r2.cmd("aerR").replace("\n", ";")
	#print("USER %s ENDUSER"%(user[uidx]))

def loadUserCode():
	print "LOAD"

def switchUser():
	global user, uidx
	uidx = uidx + 1
	if uidx >= len(user):
		uidx = 0
	r2.cmd(user[uidx])

def shell():
	while True: print(r2.cmd(raw_input()))

def r2wars_plain():
	global ctr, user, uidx
	ctr = 0
	while True:
		res = "\x1b[2J\x1b[0;0H"
		print(res + userScreen("prc"))
		stepIn()
		if checkDead():
			who = removeUser()
			if who != None:
				print("\n\nThe winner is %s\n\n"%(who))
				break
		switchUser()
		time.sleep(0.2)

def checkDead():
	global uidx, ctr
	te = r2.cmd("?v 1+theend").strip()
	ctr = ctr + 1
	#print "TE %s %s"%(uidx, te)
	if te != "" and te != "0x1":
		print ("USER %s DIED at %s"%(uidx, te))
		return True
	return False

def removeUser():
	global user, uidx, ctr
	who = name[uidx]
	print("\n\rUSER %s HAS DIED"%(who))
	sys.stdout.flush()
	time.sleep(2)
	del user[uidx]
	del name[uidx]
	del wins[uidx]
	del orig[uidx]
	del size[uidx]
	uidx = uidx - 1
	if uidx < 0 or uidx >= len(user):
		uidx = 0
	if len(user) < 2:
		return name[uidx]
	#shell()
	return None
	
def r2wars_curses():
	global stdscr, user, uidx
	r2.cmd("e scr.color=false")
	r2.cmd("e scr.utf8=false")
	stdscr = curses.initscr()
	#curses.start_color();
	curses.noecho()
	(h, w) = stdscr.getmaxyx()
	
	x = 0
	for a in user:
		w2 = w / len(user)
		wins.append(curses.newwin(h, w2, 0, x))
		x = x + w2
	who = ""
	while True:
		stdscr.refresh()
		(h, w) = stdscr.getmaxyx()
		uc = userScreen("prc")
		ansi_escape = re.compile(r'\x1b[^m]*m')
		uc = str(ansi_escape.sub('', uc))
		uc = uc.replace("\r", "")
		n = 100
		ucs = uc.split("\n")

		a = wins[uidx]
		# relayout
		x = 0
		w2 = w / len(user)
		for w in wins:
			try:
				w.resize(1, 1)
				w.mvwin(0, x)
				w.resize(h, w2)
			except:
				pass
			x = x + w2
		a.clear()
		try:
			for u in ucs:
				a.addstr(str(u[:w2] + "\n"))
		except:
			pass
		a.refresh()
		stepIn()
		if checkDead():
			who = removeUser()
			if who != None:
				break
		switchUser()
		stdscr.refresh()
		time.sleep(0.01)
	curses.endwin()
	if who:
		nextName = who + ".0"
		rs = "agn %s\n"%(who)
		rs += "agn %s\n"%(nextName)
		rs += "age %s %s\n"%(who, nextName)
		for x in sys.argv[1:]:
			rs += "agn %s\n"%(x)
			if x != who:
				rs += "age %s %s\n"%(who, x)
		print rs
		print("The Winner Is: %s"%(who))


if __name__ == '__main__':
	idx = 0
	offsets = get_random_offsets()
	for a in sys.argv[1:]:
		try:
			n = name.index(a)
			print(n)
			print("Cant have two players with the same script")
			sys.exit(1)
		except:
			pass
		addr = offsets[idx]
		idx = idx + 1
		src = r2.syscmd("rasm2 -f %s"%(a)).strip()
		if src == "":
			print("Invalid source")
			sys.exit(1)
		r2.cmd("wx %s @ %s"%(src, addr))
		#print("wx %s @ %s"%(src, addr))
		r2.cmd("aer PC=%s"%(addr))
		r2.cmd("aer SP=SP+%s"%(addr))
		initRegs = r2.cmd("aerR").replace("\n", ";")
		name.append(a)
		orig.append(addr)
		size.append(len(src) / 2)
		user.append(initRegs)
	if len(user) < 2:
		print("You need at least 2 users")
		sys.exit(1)
	r2.cmd("e cmd.esil.todo=f theend=1")
	r2.cmd("e cmd.esil.trap=f theend=1")
	r2.cmd("e cmd.esil.intr=f theend=1")
	r2.cmd("e cmd.esil.ioer=f theend=1")
	r2.cmd("f theend=0")

	print r2.cmd("b %d"%(memsize))
	r2wars_curses()
	#r2wars_plain()

