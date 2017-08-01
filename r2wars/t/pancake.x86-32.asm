call rest
rest:
  pop esp
rep:
  add esp, 64
  pusha
  jmp rep
