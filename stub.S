pusha
nop
nop
nop
call 0x2c
mov ecx,DWORD PTR[ebp-0x16]
mov ebx,ebp
sub ebx,DWORD PTR[ebp-0x1e]
mov dl,BYTE PTR[ebx]
xor    dl,BYTE PTR [ebp-0x12]
mov    BYTE PTR [ebx],dl 
dec ecx
inc ebx
cmp cx,0x0
jnz -0x12
mov    ecx,DWORD PTR [ebp-0x1a]
add    ecx,0x2c
neg ecx
mov DWORD PTR [ebp+0x28],ecx
popa
nop
jmp 0xdeadbeef
mov ebp,[esp]
ret
nop
