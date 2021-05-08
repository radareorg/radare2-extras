import r2pipe

r2 = r2pipe.open("pongo://")
h=r2.cmd("e asm.arch=arm")
h=r2.cmd("e asm.bits=64")

# print(r2.cmd("=!help"))

entrypoint = 0x100000000
r2.cmd("s " + str(entrypoint))
dis = r2.cmd("pd 10")
print("pongoOS entrypoint:")
print(dis)
