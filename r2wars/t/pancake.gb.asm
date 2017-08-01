.arch gb
  call test
test:
  pop bc
  ld hl, 8
  ld sp, bc
rep:
  push bc
  add hl, sp
  jr rep
