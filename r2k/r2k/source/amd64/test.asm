.CODE 
PUBLIC DisableMemoryProtection
PUBLIC EnableMemoryProtection
DisableMemoryProtection PROC
	push rax
	mov  rax, CR0
	and  rax, 0FFFEFFFFh
	mov  CR0, rax
	pop  rax
	ret
DisableMemoryProtection ENDP
EnableMemoryProtection PROC
	push rax
	mov  rax, CR0
	;or   eax, (NOT 0FFFEFFFFh)
	mov  CR0, rax
	pop  rax
	ret
EnableMemoryProtection ENDP
END
