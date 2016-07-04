SECTION .text
global  _get_unpackersize
global  _get_unpackerptr
 _get_unpackersize:
    mov eax, unpacker_end - unpacker_start
    ret
_get_unpackerptr:
    mov eax, unpacker_start
	ret

unpacker_start:
push ebp
mov ebp,esp
sub esp,30h ; <- Allocating local variable space

pushad ; <- Save our registers onto the stack

xor eax,eax
inc eax
mov edi,[ebp+10h] ; <- Function accessing parameter (pvWorkMem)
mov [ebp-14h],eax ; <- Function zeroing local variable
mov [ebp-1Ch],eax ; <- Etc...
mov [ebp-18h],eax
mov [ebp-28h],eax
mov eax,400h
xor edx,edx
mov ecx,30736h
rep stosd
mov eax,[ebp+0Ch]
push 5
mov [ebp-8],eax
mov [ebp-10h],edx
mov [ebp-1],dl
mov [ebp-0Ch],edx
mov [ebp+0Ch],edx
or eax,0FFFFFFFFh
pop ecx
@loc_401041:
mov esi,[ebp-8]
mov edx,[ebp+0Ch]
movzx esi,byte[esi]
shl edx,8
or edx,esi
inc dword[ebp-8]
dec ecx
mov [ebp+0Ch],edx
jnz @loc_401041
@loc_401058:
mov esi,[ebp-10h]
mov ecx,[ebp-0Ch]
mov edx,[ebp+10h]
and esi,3
shl ecx,4
add ecx,esi
cmp eax,1000000h
lea edi,[edx+ecx*4]
jnb @loc_40108A
mov edx,[ebp-8]
mov ecx,[ebp+0Ch]
movzx edx,byte[edx]
shl ecx,8
or ecx,edx
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],ecx
@loc_40108A:
mov ecx,[edi]
mov ebx,eax
shr ebx,0Bh
imul ebx,ecx
cmp [ebp+0Ch],ebx
jnb @loc_401207
mov esi,800h
sub esi,ecx
shr esi,5
add esi,ecx
movzx ecx,byte[ebp-1]
imul ecx,0C00h
xor edx,edx
mov [edi],esi
mov esi,[ebp+10h]
inc edx
cmp dword[ebp-0Ch],7
lea ecx,[ecx+esi+1CD8h]
mov eax,ebx
mov [ebp-20h],ecx
jl @loc_401170
mov ecx,[ebp-10h]
sub ecx,[ebp-14h]
mov esi,[ebp+8]
movzx ecx,byte[ecx+esi]
mov [ebp-24h],ecx
@loc_4010E1:
shl dword[ebp-24h],1
mov esi,[ebp-24h]
mov edi,[ebp-20h]
and esi,100h
cmp eax,1000000h
lea ecx,[esi+edx]
lea ecx,[edi+ecx*4+400h]
mov [ebp-2Ch],ecx
jnb @loc_40111B
mov ebx,[ebp-8]
mov edi,[ebp+0Ch]
movzx ebx,byte[ebx]
shl edi,8
or edi,ebx
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],edi
@loc_40111B:
mov ecx,[ecx]
mov edi,eax
shr edi,0Bh
imul edi,ecx
cmp [ebp+0Ch],edi
jnb @loc_401149
mov eax,edi
mov edi,800h
sub edi,ecx
shr edi,5
add edi,ecx
mov ecx,[ebp-2Ch]
add edx,edx
test esi,esi
mov [ecx],edi
jnz @loc_4011C9
jmp @loc_401162
@loc_401149:
sub [ebp+0Ch],edi
sub eax,edi
mov edi,ecx
shr edi,5
sub ecx,edi
test esi,esi
mov edi,[ebp-2Ch]
mov [edi],ecx
lea edx,[edx+edx+1]
jz @loc_4011C9
@loc_401162:
cmp edx,100h
jl @loc_4010E1
jmp @loc_4011D1
@loc_401170:
cmp eax,1000000h
mov ecx,[ebp-20h]
lea edi,[ecx+edx*4]
jnb @loc_401194
mov esi,[ebp-8]
mov ecx,[ebp+0Ch]
movzx esi,byte[esi]
shl ecx,8
or ecx,esi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],ecx
@loc_401194:
mov ecx,[edi]
mov esi,eax
shr esi,0Bh
imul esi,ecx
cmp [ebp+0Ch],esi
jnb @loc_4011B7
mov eax,esi
mov esi,800h
sub esi,ecx
shr esi,5
add esi,ecx
mov [edi],esi
add edx,edx
jmp @loc_4011C9
@loc_4011B7:
sub [ebp+0Ch],esi
sub eax,esi
mov esi,ecx
shr esi,5
sub ecx,esi
mov [edi],ecx
lea edx,[edx+edx+1]
@loc_4011C9:
cmp edx,100h
jl @loc_401170
@loc_4011D1:
mov esi,[ebp-10h]
mov ecx,[ebp+8]
inc dword[ebp-10h]
cmp dword[ebp-0Ch],4
mov [ebp-1],dl
mov [esi+ecx],dl
jge @loc_4011EF
and dword[ebp-0Ch],0
jmp @loc_401058
@loc_4011EF:
cmp dword[ebp-0Ch],0Ah
jge @loc_4011FE
sub dword[ebp-0Ch],3
jmp @loc_401058
@loc_4011FE:
sub dword[ebp-0Ch],6
jmp @loc_401058
@loc_401207:
sub [ebp+0Ch],ebx
mov edx,ecx
shr edx,5
sub ecx,edx
mov edx,[ebp-0Ch]
sub eax,ebx
cmp eax,1000000h
mov [edi],ecx
mov ecx,[ebp+10h]
lea edx,[ecx+edx*4+300h]
jnb @loc_401240
mov edi,[ebp-8]
mov ecx,[ebp+0Ch]
movzx edi,byte[edi]
shl ecx,8
or ecx,edi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],ecx
@loc_401240:
mov ecx,[edx]
mov edi,eax
shr edi,0Bh
imul edi,ecx
cmp [ebp+0Ch],edi
jnb @loc_401292
mov eax,edi
mov edi,800h
sub edi,ecx
shr edi,5
add edi,ecx
cmp dword[ebp-0Ch],7
mov ecx,[ebp-18h]
mov [ebp-28h],ecx
mov ecx,[ebp-1Ch]
mov [ebp-18h],ecx
mov ecx,[ebp-14h]
mov [edx],edi
mov [ebp-1Ch],ecx
jge @loc_40127D
and dword[ebp-0Ch],0
jmp @loc_401284
@loc_40127D:
mov dword[ebp-0Ch],3
@loc_401284:
mov ecx,[ebp+10h]
add ecx,0CC8h
jmp @loc_40147B
@loc_401292:
sub [ebp+0Ch],edi
sub eax,edi
mov edi,ecx
shr edi,5
sub ecx,edi
cmp eax,1000000h
mov [edx],ecx
mov ecx,[ebp-0Ch]
mov edx,[ebp+10h]
lea edi,[edx+ecx*4+330h]
jnb @loc_4012CB
mov edx,[ebp-8]
mov ecx,[ebp+0Ch]
movzx edx,byte[edx]
shl ecx,8
or ecx,edx
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],ecx
@loc_4012CB:
mov ecx,[edi]
mov edx,eax
shr edx,0Bh
imul edx,ecx
cmp [ebp+0Ch],edx
jnb @loc_40137F
mov ebx,800h
sub ebx,ecx
shr ebx,5
add ebx,ecx
mov ecx,[ebp-0Ch]
add ecx,0Fh
shl ecx,4
mov [edi],ebx
mov edi,[ebp+10h]
add ecx,esi
cmp edx,1000000h
mov eax,edx
lea edi,[edi+ecx*4]
jnb @loc_401320
mov ecx,[ebp+0Ch]
shl edx,8
mov eax,edx
mov edx,[ebp-8]
movzx edx,byte[edx]
shl ecx,8
or ecx,edx
inc dword[ebp-8]
mov [ebp+0Ch],ecx
@loc_401320:
mov ecx,[edi]
mov edx,eax
shr edx,0Bh
imul edx,ecx
cmp [ebp+0Ch],edx
jnb @loc_40136C
mov esi,[ebp-10h]
mov eax,edx
mov edx,800h
sub edx,ecx
shr edx,5
add edx,ecx
xor ecx,ecx
cmp dword[ebp-0Ch],7
mov [edi],edx
mov edx,[ebp+8]
setnl cl
lea ecx,[ecx+ecx+9]
mov [ebp-0Ch],ecx
mov ecx,[ebp-10h]
sub ecx,[ebp-14h]
inc dword[ebp-10h]
mov cl,[ecx+edx]
mov [ebp-1],cl
mov [esi+edx],cl
jmp @loc_401058
@loc_40136C:
sub [ebp+0Ch],edx
sub eax,edx
mov edx,ecx
shr edx,5
sub ecx,edx
mov [edi],ecx
jmp @loc_40145F
@loc_40137F:
sub [ebp+0Ch],edx
sub eax,edx
mov edx,ecx
shr edx,5
sub ecx,edx
cmp eax,1000000h
mov edx,[ebp+10h]
mov [edi],ecx
mov ecx,[ebp-0Ch]
lea edx,[edx+ecx*4+360h]
jnb @loc_4013B8
mov edi,[ebp-8]
mov ecx,[ebp+0Ch]
movzx edi,byte[edi]
shl ecx,8
or ecx,edi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],ecx
@loc_4013B8:
mov ecx,[edx]
mov edi,eax
shr edi,0Bh
imul edi,ecx
cmp [ebp+0Ch],edi
jnb @loc_4013DC
mov eax,edi
mov edi,800h
sub edi,ecx
shr edi,5
add edi,ecx
mov ecx,[ebp-1Ch]
mov [edx],edi
jmp @loc_401456
@loc_4013DC:
sub [ebp+0Ch],edi
sub eax,edi
mov edi,ecx
shr edi,5
sub ecx,edi
cmp eax,1000000h
mov [edx],ecx
mov ecx,[ebp-0Ch]
mov edx,[ebp+10h]
lea edx,[edx+ecx*4+390h]
jnb @loc_401415
mov edi,[ebp-8]
mov ecx,[ebp+0Ch]
movzx edi,byte[edi]
shl ecx,8
or ecx,edi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],ecx
@loc_401415:
mov ecx,[edx]
mov edi,eax
shr edi,0Bh
imul edi,ecx
cmp [ebp+0Ch],edi
jnb @loc_401439
mov eax,edi
mov edi,800h
sub edi,ecx
shr edi,5
add edi,ecx
mov ecx,[ebp-18h]
mov [edx],edi
jmp @loc_401450
@loc_401439:
sub [ebp+0Ch],edi
sub eax,edi
mov edi,ecx
shr edi,5
sub ecx,edi
mov [edx],ecx
mov edx,[ebp-18h]
mov ecx,[ebp-28h]
mov [ebp-28h],edx
@loc_401450:
mov edx,[ebp-1Ch]
mov [ebp-18h],edx
@loc_401456:
mov edx,[ebp-14h]
mov [ebp-1Ch],edx
mov [ebp-14h],ecx
@loc_40145F:
xor ecx,ecx
cmp dword[ebp-0Ch],7
setnl cl
dec ecx
and ecx,0FFFFFFFDh
add ecx,0Bh
mov [ebp-0Ch],ecx
mov ecx,[ebp+10h]
add ecx,14D0h
@loc_40147B:
cmp eax,1000000h
jnb @loc_401499
mov edi,[ebp-8]
mov edx,[ebp+0Ch]
movzx edi,byte[edi]
shl edx,8
or edx,edi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],edx
@loc_401499:
mov edx,[ecx]
mov edi,eax
shr edi,0Bh
imul edi,edx
cmp [ebp+0Ch],edi
jnb @loc_4014C5
mov eax,edi
mov edi,800h
sub edi,edx
shr edi,5
add edi,edx
shl esi,5
and dword[ebp-24h],0
mov [ecx],edi
lea ecx,[esi+ecx+8]
jmp @loc_401523
@loc_4014C5:
sub [ebp+0Ch],edi
sub eax,edi
mov edi,edx
shr edi,5
sub edx,edi
cmp eax,1000000h
mov [ecx],edx
jnb @loc_4014F1
mov edi,[ebp-8]
mov edx,[ebp+0Ch]
movzx edi,byte[edi]
shl edx,8
or edx,edi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],edx
@loc_4014F1:
mov edx,[ecx+4]
mov edi,eax
shr edi,0Bh
imul edi,edx
cmp [ebp+0Ch],edi
jnb @loc_40152C
mov eax,edi
mov edi,800h
sub edi,edx
shr edi,5
add edi,edx
shl esi,5
mov [ecx+4],edi
lea ecx,[esi+ecx+208h]
mov dword[ebp-24h],8
@loc_401523:
mov dword[ebp-20h],3
jmp @loc_40154F
@loc_40152C:
sub [ebp+0Ch],edi
mov esi,edx
shr esi,5
sub edx,esi
sub eax,edi
mov [ecx+4],edx
add ecx,408h
mov dword[ebp-24h],10h
mov dword[ebp-20h],8
@loc_40154F:
mov edx,[ebp-20h]
xor ebx,ebx
mov [ebp-2Ch],edx
inc ebx
@loc_401558:
cmp eax,1000000h
jnb @loc_401576
mov esi,[ebp-8]
mov edx,[ebp+0Ch]
movzx esi,byte[esi]
shl edx,8
or edx,esi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],edx
@loc_401576:
mov edx,[ecx+ebx*4]
mov esi,eax
shr esi,0Bh
imul esi,edx
cmp [ebp+0Ch],esi
jnb @loc_40159B
mov eax,esi
mov esi,800h
sub esi,edx
shr esi,5
add esi,edx
mov [ecx+ebx*4],esi
add ebx,ebx
jmp @loc_4015AE
@loc_40159B:
sub [ebp+0Ch],esi
sub eax,esi
mov esi,edx
shr esi,5
sub edx,esi
mov [ecx+ebx*4],edx
lea ebx,[ebx+ebx+1]
@loc_4015AE:
dec dword[ebp-2Ch]
jnz @loc_401558
mov ecx,[ebp-20h]
xor edx,edx
inc edx
mov esi,edx
shl esi,cl
mov ecx,[ebp-24h]
sub ecx,esi
add ebx,ecx
cmp dword[ebp-0Ch],4
mov [ebp-30h],ebx
jge @loc_401765
add dword[ebp-0Ch],7
cmp ebx,4
jge @loc_4015DE
mov ecx,ebx
jmp @loc_4015E1
@loc_4015DE:
push 3
pop ecx
@loc_4015E1:
mov esi,[ebp+10h]
shl ecx,8
lea edi,[ecx+esi+6C0h]
mov dword[ebp-2Ch],6
@loc_4015F5:
cmp eax,1000000h
jnb @loc_401613
mov esi,[ebp-8]
mov ecx,[ebp+0Ch]
movzx esi,byte[esi]
shl ecx,8
or ecx,esi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],ecx
@loc_401613:
mov ecx,[edi+edx*4]
mov esi,eax
shr esi,0Bh
imul esi,ecx
cmp [ebp+0Ch],esi
jnb @loc_401638
mov eax,esi
mov esi,800h
sub esi,ecx
shr esi,5
add esi,ecx
mov [edi+edx*4],esi
add edx,edx
jmp @loc_40164B
@loc_401638:
sub [ebp+0Ch],esi
sub eax,esi
mov esi,ecx
shr esi,5
sub ecx,esi
mov [edi+edx*4],ecx
lea edx,[edx+edx+1]
@loc_40164B:
dec dword[ebp-2Ch]
jnz @loc_4015F5
sub edx,40h
cmp edx,4
mov edi,edx
jl @loc_401736
mov ecx,edx
sar ecx,1
and edi,1
dec ecx
or edi,2
cmp edx,0Eh
mov [ebp-14h],ecx
jge @loc_401683
shl edi,cl
mov ecx,edi
sub ecx,edx
mov edx,[ebp+10h]
lea ebx,[edx+ecx*4+0ABCh]
jmp @loc_4016C9
@loc_401683:
sub ecx,4
@loc_401686:
cmp eax,1000000h
jnb @loc_4016A4
mov esi,[ebp-8]
mov edx,[ebp+0Ch]
movzx esi,byte[esi]
shl edx,8
or edx,esi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],edx
@loc_4016A4:
shr eax,1
add edi,edi
cmp [ebp+0Ch],eax
jb @loc_4016B3
sub [ebp+0Ch],eax
or edi,1
@loc_4016B3:
dec ecx
jnz @loc_401686
mov ebx,[ebp+10h]
add ebx,0C88h
shl edi,4
mov dword[ebp-14h],4
@loc_4016C9:
xor ecx,ecx
inc ecx
mov [ebp-20h],ebx
mov [ebp-24h],ecx
@loc_4016D2:
cmp eax,1000000h
jnb @loc_4016F0
mov esi,[ebp-8]
mov edx,[ebp+0Ch]
movzx esi,byte[esi]
shl edx,8
or edx,esi
shl eax,8
inc dword[ebp-8]
mov [ebp+0Ch],edx
@loc_4016F0:
mov edx,[ebx+ecx*4]
mov esi,eax
shr esi,0Bh
imul esi,edx
cmp [ebp+0Ch],esi
jnb @loc_401715
mov eax,esi
mov esi,800h
sub esi,edx
shr esi,5
add esi,edx
mov [ebx+ecx*4],esi
add ecx,ecx
jmp @loc_40172E
@loc_401715:
sub [ebp+0Ch],esi
mov ebx,[ebp-20h]
sub eax,esi
mov esi,edx
shr esi,5
sub edx,esi
or edi,[ebp-24h]
mov [ebx+ecx*4],edx
lea ecx,[ecx+ecx+1]
@loc_40172E:
shl dword[ebp-24h],1
dec dword[ebp-14h]
jnz @loc_4016D2
@loc_401736:
inc edi
mov [ebp-14h],edi
jz @loc_40176A
mov ebx,[ebp-30h]
@loc_40173F:
mov ecx,[ebp-10h]
inc ebx
sub ecx,edi
inc ebx
add ecx,[ebp+8]
@loc_401749:
mov dl,[ecx]
mov esi,[ebp-10h]
mov edi,[ebp+8]
dec ebx
inc dword[ebp-10h]
inc ecx
test ebx,ebx
mov [ebp-1],dl
mov [esi+edi],dl
jnz @loc_401749
jmp @loc_401058
@loc_401765:
mov edi,[ebp-14h]
jmp @loc_40173F
@loc_40176A:
popad
mov eax,[ebp-10h]
leave
retn 0Ch
unpacker_end:
retn
