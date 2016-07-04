.686p
.model flat, stdcall
option casemap:none

.code

option prologue:none
option epilogue:none

get_frdepackersize proc export
    mov eax, unpacker_end - KKrunchyDepacker
    ret
get_frdepackersize endp

get_frdepackerptr proc export
    mov eax, KKrunchyDepacker
    ret
get_frdepackerptr endp

unpacker_start:

KKrunchyDepacker:     

        PUSH EBP                             ; CCADepackerA
        PUSH ESI
        PUSH EDI
        PUSH EBX
        MOV ESI,DWORD PTR SS:[ESP+018h]
        SUB ESP,0CA0h
        MOV EBP,ESP
        LODS DWORD PTR DS:[ESI]
        MOV DWORD PTR SS:[EBP],ESI
        BSWAP EAX
        MOV DWORD PTR SS:[EBP+4],EAX
        OR DWORD PTR SS:[EBP+8],0FFFFFFFFh
        MOV DWORD PTR SS:[EBP+0Ch],5
        MOV DWORD PTR SS:[EBP+010h],0
        LEA EDI,DWORD PTR SS:[EBP+014h]
        MOV ECX,0323h
        XOR EAX,EAX
        MOV AH,4
        REP STOS DWORD PTR ES:[EDI]
        MOV EDI,DWORD PTR SS:[ESP+0CB4h]

@mudff_00401040:

        XOR ECX,ECX
        INC ECX
        DEC DWORD PTR SS:[EBP+0Ch]

@mudff_00401046:

        LEA EBX,DWORD PTR SS:[EBP+ECX*4+0A0h]
        CALL @mudff_004010F2
        ADC CL,CL
        JNB @mudff_00401046
        INC DWORD PTR SS:[EBP+0Ch]
        XCHG EAX,ECX
        STOS BYTE PTR ES:[EDI]
        OR ECX,0FFFFFFFFh

@mudff_0040105E:

        LEA EBX,DWORD PTR SS:[EBP+ECX*4+018h]
        CALL @mudff_004010F2
        JE @mudff_00401040
        JECXZ @mudff_00401085
        LEA EBX,DWORD PTR SS:[EBP+01Ch]
        CALL @mudff_004010F2
        JE @mudff_00401085
        LEA EBX,DWORD PTR SS:[EBP+08A0h]
        CALL @mudff_00401143
        MOV EAX,DWORD PTR SS:[EBP+010h]
        JMP @mudff_004010CF

@mudff_00401085:

        LEA EBX,DWORD PTR SS:[EBP+04A0h]
        CALL @mudff_00401143
        DEC ECX
        DEC ECX
        JS @mudff_004010DC
        LEA EBX,DWORD PTR SS:[EBP+020h]
        JE @mudff_0040109C
        ADD EBX,040h

@mudff_0040109C:

        XOR EDX,EDX
        INC EDX

@mudff_0040109F:

        PUSH EBX
        LEA EBX,DWORD PTR DS:[EBX+EDX*4]
        CALL @mudff_004010F2
        POP EBX
        ADC EDX,EDX
        LEA ECX,DWORD PTR DS:[EAX+ECX*2]
        TEST DL,010h
        JE @mudff_0040109F
        LEA EAX,DWORD PTR DS:[ECX+1]
        LEA EBX,DWORD PTR SS:[EBP+08A0h]
        CALL @mudff_00401143
        CMP EAX,0800h
        SBB ECX,-1
        CMP EAX,060h
        SBB ECX,-1

@mudff_004010CF:

        MOV DWORD PTR SS:[EBP+010h],EAX
        PUSH ESI
        MOV ESI,EDI
        SUB ESI,EAX
        REP MOVS BYTE PTR ES:[EDI],BYTE PTR DS:[ESI]
        POP ESI
        JMP @mudff_0040105E

@mudff_004010DC:

        MOV EAX,EDI
        SUB EAX,DWORD PTR SS:[ESP+0CB4h]
        ADD ESP,0CA0h
        POP EBX
        POP EDI
        POP ESI
        POP EBP
        RETN 8                               ;<= Procedure End


@mudff_004010F2:                             ;<= Procedure Start

        PUSH ECX
        MOV EAX,DWORD PTR SS:[EBP+8]
        SHR EAX,0Bh
        IMUL EAX,DWORD PTR DS:[EBX]
        CMP EAX,DWORD PTR SS:[EBP+4]
        MOV ECX,DWORD PTR SS:[EBP+0Ch]
        JBE @mudff_00401116
        MOV DWORD PTR SS:[EBP+8],EAX
        MOV EAX,0800h
        SUB EAX,DWORD PTR DS:[EBX]
        SHR EAX,CL
        ADD DWORD PTR DS:[EBX],EAX
        XOR EAX,EAX
        JMP @mudff_00401125

@mudff_00401116:

        SUB DWORD PTR SS:[EBP+4],EAX
        SUB DWORD PTR SS:[EBP+8],EAX
        MOV EAX,DWORD PTR DS:[EBX]
        SHR EAX,CL
        SUB DWORD PTR DS:[EBX],EAX
        OR EAX,0FFFFFFFFh

@mudff_00401125:

        TEST BYTE PTR SS:[EBP+0Bh],0FFh
        JNZ @mudff_0040113E
        MOV ECX,DWORD PTR SS:[EBP]
        INC DWORD PTR SS:[EBP]
        MOV CL,BYTE PTR DS:[ECX]
        SHL DWORD PTR SS:[EBP+8],8
        SHL DWORD PTR SS:[EBP+4],8
        MOV BYTE PTR SS:[EBP+4],CL

@mudff_0040113E:

        SHR EAX,01Fh
        POP ECX
        RETN                                 ;<= Procedure End


@mudff_00401143:                             ;<= Procedure Start

        PUSH EAX
        XOR ECX,ECX
        INC ECX
        MOV EDX,ECX

@mudff_00401149:

        PUSH EBX
        LEA EBX,DWORD PTR DS:[EBX+EDX*4]
        CALL @mudff_004010F2
        POP EBX
        ADC DL,DL
        PUSH EBX
        LEA EBX,DWORD PTR DS:[EBX+EDX*4]
        CALL @mudff_004010F2
        POP EBX
        ADC DL,DL
        LEA ECX,DWORD PTR DS:[EAX+ECX*2]
        TEST DL,2
        JNZ @mudff_00401149
        POP EAX
        RETN                                 ;<= Procedure End
unpacker_end:
end

