.686p
.model flat, stdcall
option casemap:none

.code

option prologue:none
option epilogue:none

get_lzmadepackersize proc export
    mov eax, unpacker_end - LzmaDecode
    ret
get_lzmadepackersize endp

get_lzmadepackerptr proc export
    mov eax, LzmaDecode
    ret
get_lzmadepackerptr endp



unpacker_start:


LzmaDecode:                                  ;<= Procedure Start

        PUSH EBP
        MOV EBP,ESP
        SUB ESP,020h
        PUSHAD
        XOR EAX,EAX
        AND DWORD PTR SS:[EBP-014h],EAX
        MOV BYTE PTR SS:[EBP-1],AL
        INC EAX
        MOV EDI,DWORD PTR SS:[EBP+8]
        MOV ESI,EAX
        MOV DWORD PTR SS:[EBP-0Ch],EAX
        MOV ECX,01839Bh
        MOV DWORD PTR SS:[EBP-8],EAX
        XOR EBX,EBX
        MOV DWORD PTR SS:[EBP-010h],EAX
        MOV EAX,04000400h
        REP STOS DWORD PTR ES:[EDI]
        MOV EDI,DWORD PTR SS:[EBP+0Ch]
        XOR ECX,ECX
        OR DWORD PTR SS:[EBP-01Ch],0FFFFFFFFh
        PUSH 5
        POP EDX

_00FD103C:

        MOVZX EAX,BYTE PTR DS:[EDI]
        SHL ECX,8
        OR ECX,EAX
        INC EDI
        DEC EDX
        JNZ _00FD103C
        MOV EDX,DWORD PTR SS:[EBP+8]
        MOV DWORD PTR SS:[EBP-018h],ECX
        MOV DWORD PTR SS:[EBP-020h],EDI
        MOV EDI,DWORD PTR SS:[EBP-014h]

_00FD105D:

        LEA EAX,DWORD PTR SS:[EBP-020h]
        MOV ECX,EDI
        PUSH EAX
        AND ECX,3
        MOV EAX,EBX
        SHL EAX,4
        ADD EAX,ECX
        MOV DWORD PTR SS:[EBP+0Ch],ECX
        LEA EAX,DWORD PTR DS:[EDX+EAX*2]
        PUSH EAX
        CALL RangeDecoderBitDecode
        TEST EAX,EAX
        JNZ _00FD10E2
        MOVZX EAX,BYTE PTR SS:[EBP-1]
        MOV ECX,DWORD PTR SS:[EBP+8]
        IMUL EAX,EAX,0600h
        ADD ECX,0E6Ch
        PUSH 7
        ADD ECX,EAX
        POP EAX
        CMP EBX,EAX
        JL _00FD10A9
        MOV EDX,DWORD PTR SS:[EBP+014h]
        MOV EAX,EDI
        SUB EAX,ESI
        PUSH 1
        MOVZX EAX,BYTE PTR DS:[EAX+EDX]
        PUSH EAX
        JMP _00FD10AD

_00FD10A9:

        PUSH 0
        PUSH 0

_00FD10AD:

        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH EAX
        PUSH ECX
        CALL LzmaLiteralDecodeMatch
        MOV ECX,DWORD PTR SS:[EBP+014h]
        MOV BYTE PTR SS:[EBP-1],AL
        MOV BYTE PTR DS:[EDI+ECX],AL
        INC EDI
        CMP EBX,4
        JGE _00FD10CD
        XOR EBX,EBX
        JMP _00FD12AA

_00FD10CD:

        CMP EBX,0Ah
        JGE _00FD10DA
        SUB EBX,3
        JMP _00FD12AA

_00FD10DA:

        SUB EBX,6
        JMP _00FD12AA

_00FD10E2:

        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH EAX
        MOV EAX,DWORD PTR SS:[EBP+8]
        ADD EAX,0180h
        LEA EAX,DWORD PTR DS:[EAX+EBX*2]
        PUSH EAX
        CALL RangeDecoderBitDecode
        CMP EAX,1
        JNZ _00FD11D3
        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH EAX
        MOV EAX,DWORD PTR SS:[EBP+8]
        LEA EAX,DWORD PTR DS:[EAX+EBX*2]
        ADD EAX,0198h
        PUSH EAX
        CALL RangeDecoderBitDecode
        TEST EAX,EAX
        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH EAX
        JNZ _00FD115C
        MOV ECX,DWORD PTR SS:[EBP+8]
        LEA EAX,DWORD PTR DS:[EBX+0Fh]
        SHL EAX,4
        ADD EAX,DWORD PTR SS:[EBP+0Ch]
        LEA EAX,DWORD PTR DS:[ECX+EAX*2]
        PUSH EAX
        CALL RangeDecoderBitDecode
        TEST EAX,EAX
        JNZ _00FD11A8
        PUSH 0Bh
        POP EAX
        PUSH 9
        POP ECX
        PUSH 7
        POP EDX
        CMP EBX,EDX
        CMOVL EAX,ECX
        MOV ECX,DWORD PTR SS:[EBP+014h]
        MOV EBX,EAX
        MOV EAX,EDI
        SUB EAX,ESI
        MOV AL,BYTE PTR DS:[EAX+ECX]
        MOV BYTE PTR DS:[EDI+ECX],AL
        INC EDI
        MOV BYTE PTR SS:[EBP-1],AL
        JMP _00FD12AA

_00FD115C:

        MOV EAX,DWORD PTR SS:[EBP+8]
        LEA EAX,DWORD PTR DS:[EAX+EBX*2]
        ADD EAX,01B0h
        PUSH EAX
        CALL RangeDecoderBitDecode
        TEST EAX,EAX
        JNZ _00FD1176
        MOV EAX,DWORD PTR SS:[EBP-0Ch]
        JMP _00FD11A3

_00FD1176:

        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH EAX
        MOV EAX,DWORD PTR SS:[EBP+8]
        LEA EAX,DWORD PTR DS:[EAX+EBX*2]
        ADD EAX,01C8h
        PUSH EAX
        CALL RangeDecoderBitDecode
        TEST EAX,EAX
        JNZ _00FD1194
        MOV EAX,DWORD PTR SS:[EBP-8]
        JMP _00FD119D

_00FD1194:

        MOV EAX,DWORD PTR SS:[EBP-010h]
        MOV ECX,DWORD PTR SS:[EBP-8]
        MOV DWORD PTR SS:[EBP-010h],ECX

_00FD119D:

        MOV ECX,DWORD PTR SS:[EBP-0Ch]
        MOV DWORD PTR SS:[EBP-8],ECX

_00FD11A3:

        MOV DWORD PTR SS:[EBP-0Ch],ESI
        MOV ESI,EAX

_00FD11A8:

        PUSH DWORD PTR SS:[EBP+0Ch]
        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH EAX
        MOV EAX,DWORD PTR SS:[EBP+8]
        ADD EAX,0A68h
        PUSH EAX
        CALL LzmaLenDecode
        PUSH 0Bh
        POP ECX
        PUSH 8
        MOV EDX,EAX
        CMP EBX,7
        POP EAX
        CMOVL ECX,EAX
        MOV DWORD PTR SS:[EBP-014h],ECX
        JMP _00FD128E

_00FD11D3:

        MOV EAX,DWORD PTR SS:[EBP-8]
        MOV DWORD PTR SS:[EBP-010h],EAX
        MOV EAX,DWORD PTR SS:[EBP-0Ch]
        PUSH 0Ah
        MOV DWORD PTR SS:[EBP-8],EAX
        POP EAX
        PUSH 7
        POP ECX
        PUSH DWORD PTR SS:[EBP+0Ch]
        CMP EBX,ECX
        MOV DWORD PTR SS:[EBP-0Ch],ESI
        MOV ESI,DWORD PTR SS:[EBP+8]
        CMOVL EAX,ECX
        MOV DWORD PTR SS:[EBP-014h],EAX
        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH EAX
        LEA EAX,DWORD PTR DS:[ESI+0664h]
        PUSH EAX
        CALL LzmaLenDecode
        MOV ECX,EAX
        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH 0
        PUSH EAX
        PUSH 6
        PUSH 3
        POP EAX
        CMP ECX,4
        MOV DWORD PTR SS:[EBP+0Ch],ECX
        CMOVL EAX,ECX
        SHL EAX,7
        ADD EAX,0360h
        ADD EAX,ESI
        PUSH EAX
        CALL RangeDecoderBitTreeDecode
        MOV EDX,EAX
        MOV ESI,EDX
        CMP EDX,4
        JL _00FD128A
        MOV ECX,EDX
        AND ESI,1
        SAR ECX,1
        OR ESI,2
        DEC ECX
        SHL ESI,CL
        CMP EDX,0Eh
        JGE _00FD1260
        PUSH 1
        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH EAX
        PUSH ECX
        MOV ECX,DWORD PTR SS:[EBP+8]
        MOV EAX,ESI
        SUB EAX,EDX
        ADD ECX,055Eh
        LEA EAX,DWORD PTR DS:[ECX+EAX*2]
        JMP _00FD1282

_00FD1260:

        LEA EAX,DWORD PTR DS:[ECX-4]
        PUSH EAX
        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH EAX
        CALL RangeDecoderDecodeDirectBits
        SHL EAX,4
        ADD ESI,EAX
        LEA EAX,DWORD PTR SS:[EBP-020h]
        PUSH 1
        PUSH EAX
        MOV EAX,DWORD PTR SS:[EBP+8]
        PUSH 4
        ADD EAX,0644h

_00FD1282:

        PUSH EAX
        CALL RangeDecoderBitTreeDecode
        ADD ESI,EAX

_00FD128A:

        MOV EDX,DWORD PTR SS:[EBP+0Ch]
        INC ESI

_00FD128E:

        MOV ECX,DWORD PTR SS:[EBP+014h]
        MOV EAX,EDI
        SUB EAX,ESI
        ADD EDX,2
        ADD EAX,ECX

_00FD129A:

        MOV BL,BYTE PTR DS:[EAX]
        MOV BYTE PTR DS:[EDI+ECX],BL
        INC EDI
        INC EAX
        MOV BYTE PTR SS:[EBP-1],BL
        DEC EDX
        JNZ _00FD129A
        MOV EBX,DWORD PTR SS:[EBP-014h]

_00FD12AA:

        MOV EDX,DWORD PTR SS:[EBP+8]
        CMP EDI,DWORD PTR SS:[EBP+018h]
        JB _00FD105D

_00FD12B6:

        POPAD
        MOV ESP,EBP
        POP EBP
        RETN 014h                            ;<= Procedure End


LzmaLenDecode:                               ;<= Procedure Start

        PUSH EBP
        MOV EBP,ESP
        PUSH ESI
        MOV ESI,DWORD PTR SS:[EBP+0Ch]
        PUSH EDI
        MOV EDI,DWORD PTR SS:[EBP+8]
        PUSH ESI
        PUSH EDI
        CALL RangeDecoderBitDecode
        TEST EAX,EAX
        JNZ _00FD12EC
        PUSH EAX
        MOV EAX,DWORD PTR SS:[EBP+010h]
        SHL EAX,4
        PUSH ESI
        ADD EAX,4
        PUSH 3
        ADD EAX,EDI
        PUSH EAX
        CALL RangeDecoderBitTreeDecode
        JMP _00FD1328

_00FD12EC:

        PUSH ESI
        LEA EAX,DWORD PTR DS:[EDI+2]
        PUSH EAX
        CALL RangeDecoderBitDecode
        PUSH 0
        PUSH ESI
        TEST EAX,EAX
        JNZ _00FD1317
        MOV EAX,DWORD PTR SS:[EBP+010h]
        SHL EAX,4
        ADD EAX,0104h
        PUSH 3
        ADD EAX,EDI
        PUSH EAX
        CALL RangeDecoderBitTreeDecode
        ADD EAX,8
        JMP _00FD1328

_00FD1317:

        PUSH 8
        LEA EAX,DWORD PTR DS:[EDI+0204h]
        PUSH EAX
        CALL RangeDecoderBitTreeDecode
        ADD EAX,010h

_00FD1328:

        POP EDI
        POP ESI
        POP EBP
        RETN 0Ch                             ;<= Procedure End


LzmaLiteralDecodeMatch:                      ;<= Procedure Start

        PUSH EBP                             ; LzmaLiteralDecodeMatch
        MOV EBP,ESP
        PUSH EBX
        XOR EBX,EBX
        PUSH ESI
        INC EBX
        CMP DWORD PTR SS:[EBP+014h],0
        PUSH EDI
        MOV EDI,DWORD PTR SS:[EBP+8]
        JE @mudff_00EC535B

@mudff_00EC5327:

        MOV AL,BYTE PTR SS:[EBP+010h]
        PUSH DWORD PTR SS:[EBP+0Ch]
        MOVZX ESI,AL
        ADD AL,AL
        SHR ESI,7
        MOV BYTE PTR SS:[EBP+010h],AL
        LEA EAX,DWORD PTR DS:[ESI+1]
        SHL EAX,8
        ADD EAX,EBX
        LEA EAX,DWORD PTR DS:[EDI+EAX*2]
        PUSH EAX
        CALL RangeDecoderBitDecode
        ADD EBX,EBX
        OR EBX,EAX
        CMP ESI,EAX
        JNZ @mudff_00EC536E
        CMP EBX,0100h
        JL @mudff_00EC5327
        JMP @mudff_00EC5376

@mudff_00EC535B:

        PUSH DWORD PTR SS:[EBP+0Ch]
        LEA ESI,DWORD PTR DS:[EBX+EBX]
        LEA EAX,DWORD PTR DS:[ESI+EDI]
        PUSH EAX
        CALL RangeDecoderBitDecode
        MOV EBX,EAX
        OR EBX,ESI

@mudff_00EC536E:

        CMP EBX,0100h
        JL @mudff_00EC535B

@mudff_00EC5376:

        POP EDI
        POP ESI
        MOV AL,BL
        POP EBX
        POP EBP
        RETN 010h                            ;<= Procedure End


RangeDecoderBitDecode:                       ;<= Procedure Start

        PUSH EBP
        MOV EBP,ESP
        MOV EDX,DWORD PTR SS:[EBP+8]
        PUSH EBX
        MOV EBX,DWORD PTR SS:[EBP+0Ch]
        PUSH ESI
        MOVZX ECX,WORD PTR DS:[EDX]
        PUSH EDI
        MOV EDI,DWORD PTR DS:[EBX+4]
        MOV EAX,EDI
        MOV ESI,DWORD PTR DS:[EBX+8]
        SHR EAX,0Bh
        IMUL EAX,ECX
        CMP ESI,EAX
        JNB _00FD13E0
        MOV EDI,EAX
        MOV EAX,0800h
        SUB EAX,ECX
        SAR EAX,5
        ADD EAX,ECX
        MOV WORD PTR DS:[EDX],AX
        XOR EAX,EAX
        JMP _00FD13F4

_00FD13E0:

        SUB EDI,EAX
        SUB ESI,EAX
        MOV AX,CX
        SHR AX,5
        SUB CX,AX
        XOR EAX,EAX
        MOV WORD PTR DS:[EDX],CX
        INC EAX

_00FD13F4:

        CMP EDI,01000000h
        JNB _00FD140E
        MOV EDX,DWORD PTR DS:[EBX]
        SHL ESI,8
        SHL EDI,8
        MOVZX ECX,BYTE PTR DS:[EDX]
        OR ESI,ECX
        LEA ECX,DWORD PTR DS:[EDX+1]
        MOV DWORD PTR DS:[EBX],ECX

_00FD140E:

        MOV DWORD PTR DS:[EBX+4],EDI
        POP EDI
        MOV DWORD PTR DS:[EBX+8],ESI
        POP ESI
        POP EBX
        POP EBP
        RETN 8                               ;<= Procedure End


RangeDecoderBitTreeDecode:                   ;<= Procedure Start

        PUSH EBP
        MOV EBP,ESP
        PUSH ECX
        PUSH EBX
        PUSH EDI
        XOR EDI,EDI
        XOR EBX,EBX
        INC EDI
        MOV EDX,EDI
        MOV EDI,EBX
        PUSH ESI

_00FD1430:

        PUSH DWORD PTR SS:[EBP+010h]
        MOV EAX,DWORD PTR SS:[EBP+8]
        LEA ESI,DWORD PTR DS:[EDX+EDX]
        ADD EAX,ESI
        PUSH EAX
        CALL RangeDecoderBitDecode
        MOV ECX,EDI
        LEA EDX,DWORD PTR DS:[ESI+EAX]
        SHL EAX,CL
        OR EBX,EAX
        INC EDI
        CMP EDI,DWORD PTR SS:[EBP+0Ch]
        JL _00FD1430
        XOR EDI,EDI
        INC EDI
        POP ESI
        CMP DWORD PTR SS:[EBP+014h],0
        JE _00FD145E
        MOV EAX,EBX
        JMP _00FD1467

_00FD145E:

        MOV ECX,DWORD PTR SS:[EBP+0Ch]
        SHL EDI,CL
        SUB EDX,EDI
        MOV EAX,EDX

_00FD1467:

        POP EDI
        POP EBX
        MOV ESP,EBP
        POP EBP
        RETN 010h                            ;<= Procedure End


RangeDecoderDecodeDirectBits:                ;<= Procedure Start

        PUSH EBP
        MOV EBP,ESP
        MOV EAX,DWORD PTR SS:[EBP+0Ch]
        PUSH EBX
        MOV EBX,DWORD PTR SS:[EBP+8]
        PUSH ESI
        PUSH EDI
        XOR EDI,EDI
        MOV EDX,DWORD PTR DS:[EBX+4]
        MOV ESI,DWORD PTR DS:[EBX+8]
        TEST EAX,EAX
        JE _00FD14B7

_00FD1487:

        SHR EDX,1
        ADD EDI,EDI
        CMP ESI,EDX
        JB _00FD1494
        SUB ESI,EDX
        OR EDI,1

_00FD1494:

        CMP EDX,01000000h
        JNB _00FD14B1
        MOV ECX,DWORD PTR DS:[EBX]
        SHL ESI,8
        SHL EDX,8
        MOVZX EAX,BYTE PTR DS:[ECX]
        OR ESI,EAX
        LEA EAX,DWORD PTR DS:[ECX+1]
        MOV DWORD PTR DS:[EBX],EAX
        MOV EAX,DWORD PTR SS:[EBP+0Ch]

_00FD14B1:

        DEC EAX
        MOV DWORD PTR SS:[EBP+0Ch],EAX
        JNZ _00FD1487

_00FD14B7:

        MOV EAX,EDI
        MOV DWORD PTR DS:[EBX+8],ESI
        POP EDI
        POP ESI
        MOV DWORD PTR DS:[EBX+4],EDX
        POP EBX
        POP EBP
        RETN 8                               ;<= Procedure End

unpacker_end:
end