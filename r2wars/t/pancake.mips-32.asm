.arch mips
.bits 32
  bal here
here:
  move t0, ra
rep:
  subu t0, t0, 8
  sw t0, 0(t0)
  j rep
