; http://muruganad.com/8086/8086-assembly-language-program-to-play-sound-using-pc-speaker.html

mov al, 182
out 0x43, al  ; 
mov ax, 4560  ; for middle C.
out 0x42, al  ; Output low byte.
mov al, ah    ; Output high byte.
out 0x42, al 
in al, 0x61   ; port 61h
or al, 3      ; Set bits 1 and 0.
out 0x61, al  ; Send new value.
mov bx, 25    ; Pause for duration of note.
.pause1:
mov     cx, 300
.pause2:
dec cx
jne .pause2
dec bx
jne .pause1
in  al, 0x61  ; Turn off note (get value from
and al, 0xfc  ; 11111100b   ; Reset bits 1 and 0.
out 0x61, al  ; Send new value.
