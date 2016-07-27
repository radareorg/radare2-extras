include callconv.inc
.686p
.XMM
_TEXT    SEGMENT DWORD PUBLIC 'CODE'
    ASSUME  DS:FLAT, ES:FLAT, SS:NOTHING, FS:NOTHING, GS:NOTHING

cPublicProc _Test, 0
    mov eax, 1
    mov cr4, eax
    stdRET _Test
stdENDP _Test

cPublicProc _DisableMemoryProtection, 0
	push eax
    mov  eax, CR0
    and  eax, 0FFFEFFFFh
    mov  CR0, eax
    pop  eax
    stdRET _DisableMemoryProtection
stdENDP _DisableMemoryProtection

cPublicProc _EnableMemoryProtection, 0
	push eax
    mov  eax, CR0
    or   eax, NOT 0FFFEFFFFh
    mov  CR0, eax
    pop  eax
    stdRET _EnableMemoryProtection
stdENDP _EnableMemoryProtection


_TEXT    ENDS

END
