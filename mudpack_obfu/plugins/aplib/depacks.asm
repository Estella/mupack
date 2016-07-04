;;
;; aPLib compression library  -  the smaller the better :)
;;
;; TASM / MASM / WASM safe assembler depacker
;;
;; Copyright (c) 1998-2008 by Joergen Ibsen / Jibz
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

.386p
.MODEL flat
.CODE


option prologue:none
option epilogue:none

get_unpackersize proc export
    mov eax, depacker_end - depacker
    ret
get_unpackersize endp

get_unpackerptr proc export
    mov eax, depacker
    ret
get_unpackerptr endp

depacker:
@aplib_55A91160:                             ;<= Procedure Start

        PUSH EBP
        MOV EBP,ESP
        SUB ESP,018h
        MOV ECX,DWORD PTR SS:[EBP-010h]
        PUSH EBX
        PUSH ESI
        MOV ESI,DWORD PTR SS:[EBP+0Ch]
        MOV AL,BYTE PTR DS:[ESI]
        PUSH EDI
        MOV EDI,DWORD PTR SS:[EBP+8]
        XOR EBX,EBX
        MOV BYTE PTR DS:[EDI],AL
        INC EDI
        XOR EDX,EDX
        MOV DWORD PTR SS:[EBP-8],EBX
        MOV DWORD PTR SS:[EBP-014h],EDI
        INC ESI

@aplib_55A91182:

        MOV EAX,EDX
        DEC EDX
        TEST EAX,EAX
        JNZ @aplib_55A91190
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EAX+7]

@aplib_55A91190:

        MOV EAX,ECX
        SHR EAX,7
        ADD ECX,ECX
        AND EAX,1
        JE @aplib_55A913CB
        MOV EAX,EDX
        DEC EDX
        TEST EAX,EAX
        JNZ @aplib_55A911AE
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EAX+7]

@aplib_55A911AE:

        MOV EAX,ECX
        SHR EAX,7
        ADD ECX,ECX
        AND EAX,1
        JE @aplib_55A91278
        MOV EAX,EDX
        DEC EDX
        TEST EAX,EAX
        JNZ @aplib_55A911CC
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EAX+7]

@aplib_55A911CC:

        MOV EAX,ECX
        SHR EAX,7
        ADD ECX,ECX
        AND EAX,1
        JE @aplib_55A91222
        XOR EBX,EBX
        LEA EAX,DWORD PTR DS:[EBX+4]
        LEA ECX,DWORD PTR DS:[ECX]

@aplib_55A911E0:

        MOV EDI,EDX
        DEC EDX
        TEST EDI,EDI
        JNZ @aplib_55A911EE
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EDI+7]

@aplib_55A911EE:

        MOV EDI,ECX
        SHR EDI,7
        AND EDI,1
        ADD ECX,ECX
        DEC EAX
        LEA EBX,DWORD PTR DS:[EDI+EBX*2]
        JNZ @aplib_55A911E0
        TEST EBX,EBX
        JE @aplib_55A91213
        MOV EDI,DWORD PTR SS:[EBP-014h]
        MOV EAX,EDI
        SUB EAX,EBX
        MOV AL,BYTE PTR DS:[EAX]
        MOV BYTE PTR DS:[EDI],AL
        INC EDI
        JMP @aplib_55A913D4

@aplib_55A91213:

        MOV EAX,DWORD PTR SS:[EBP-014h]
        MOV BYTE PTR DS:[EAX],0
        INC EAX
        MOV DWORD PTR SS:[EBP-014h],EAX
        JMP @aplib_55A913D7

@aplib_55A91222:

        MOVZX EAX,BYTE PTR DS:[ESI]
        MOV EDI,EAX
        AND EDI,1
        INC ESI
        ADD EDI,2
        SHR EAX,1
        MOV DWORD PTR SS:[EBP-4],EAX
        JE @aplib_55A91264
        TEST EDI,EDI
        JE @aplib_55A9126B
        MOV EBX,DWORD PTR SS:[EBP-014h]
        SUB EBX,EAX
        MOV DWORD PTR SS:[EBP+0Ch],EBX

@aplib_55A91241:

        MOV BL,BYTE PTR DS:[EBX]
        MOV EAX,DWORD PTR SS:[EBP-014h]
        MOV BYTE PTR DS:[EAX],BL
        MOV EBX,DWORD PTR SS:[EBP+0Ch]
        INC EAX
        INC EBX
        DEC EDI
        MOV DWORD PTR SS:[EBP-014h],EAX
        MOV DWORD PTR SS:[EBP+0Ch],EBX
        JNZ @aplib_55A91241
        MOV EAX,DWORD PTR SS:[EBP-4]
        MOV DWORD PTR SS:[EBP-4],EAX
        LEA EBX,DWORD PTR DS:[EDI+1]
        JMP @aplib_55A913D9

@aplib_55A91264:

        MOV DWORD PTR SS:[EBP-8],1

@aplib_55A9126B:

        MOV DWORD PTR SS:[EBP-4],EAX
        MOV EBX,1
        JMP @aplib_55A913D9

@aplib_55A91278:

        MOV EAX,1
        LEA ECX,DWORD PTR DS:[ECX]

@aplib_55A91280:

        MOV EDI,EDX
        DEC EDX
        TEST EDI,EDI
        JNZ @aplib_55A9128E
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EDI+7]

@aplib_55A9128E:

        MOV EDI,ECX
        SHR EDI,7
        AND EDI,1
        LEA EAX,DWORD PTR DS:[EDI+EAX*2]
        MOV EDI,EDX
        ADD ECX,ECX
        DEC EDX
        TEST EDI,EDI
        JNZ @aplib_55A912A9
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EDI+7]

@aplib_55A912A9:

        MOV EDI,ECX
        SHR EDI,7
        ADD ECX,ECX
        AND EDI,1
        JNZ @aplib_55A91280
        TEST EBX,EBX
        JNZ @aplib_55A9132D
        CMP EAX,2
        JNZ @aplib_55A91328
        LEA EAX,DWORD PTR DS:[EDI+1]

@aplib_55A912C1:

        MOV EDI,EDX
        DEC EDX
        TEST EDI,EDI
        JNZ @aplib_55A912CF
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EDI+7]

@aplib_55A912CF:

        MOV EDI,ECX
        SHR EDI,7
        AND EDI,1
        LEA EAX,DWORD PTR DS:[EDI+EAX*2]
        MOV EDI,EDX
        ADD ECX,ECX
        DEC EDX
        TEST EDI,EDI
        JNZ @aplib_55A912EA
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EDI+7]

@aplib_55A912EA:

        MOV EDI,ECX
        SHR EDI,7
        ADD ECX,ECX
        AND EDI,1
        JNZ @aplib_55A912C1
        MOV DWORD PTR SS:[EBP+0Ch],EAX
        TEST EAX,EAX
        JE @aplib_55A913C4
        MOV EAX,DWORD PTR SS:[EBP-014h]
        MOV EDI,EAX
        SUB EDI,DWORD PTR SS:[EBP-4]
        LEA ESP,DWORD PTR SS:[ESP]

@aplib_55A91310:

        MOV BL,BYTE PTR DS:[EDI]
        MOV BYTE PTR DS:[EAX],BL
        INC EAX
        INC EDI
        DEC DWORD PTR SS:[EBP+0Ch]
        JNZ @aplib_55A91310
        MOV DWORD PTR SS:[EBP-014h],EAX
        MOV EBX,1
        JMP @aplib_55A913D9

@aplib_55A91328:

        LEA EDI,DWORD PTR DS:[EAX-3]
        JMP @aplib_55A91330

@aplib_55A9132D:

        LEA EDI,DWORD PTR DS:[EAX-2]

@aplib_55A91330:

        MOVZX EBX,BYTE PTR DS:[ESI]
        SHL EDI,8
        ADD EBX,EDI
        MOV DWORD PTR SS:[EBP-4],EBX
        INC ESI
        MOV EAX,1

@aplib_55A91341:

        MOV EDI,EDX
        DEC EDX
        TEST EDI,EDI
        JNZ @aplib_55A9134F
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EDI+7]

@aplib_55A9134F:

        MOV EDI,ECX
        SHR EDI,7
        AND EDI,1
        LEA EAX,DWORD PTR DS:[EDI+EAX*2]
        MOV EDI,EDX
        ADD ECX,ECX
        DEC EDX
        TEST EDI,EDI
        JNZ @aplib_55A9136A
        MOVZX ECX,BYTE PTR DS:[ESI]
        INC ESI
        LEA EDX,DWORD PTR DS:[EDI+7]

@aplib_55A9136A:

        MOV EDI,ECX
        SHR EDI,7
        ADD ECX,ECX
        AND EDI,1
        JNZ @aplib_55A91341
        MOV DWORD PTR SS:[EBP+0Ch],EAX
        CMP EBX,07D00h
        JB @aplib_55A91385
        INC EAX
        MOV DWORD PTR SS:[EBP+0Ch],EAX

@aplib_55A91385:

        CMP EBX,0500h
        JB @aplib_55A91391
        INC EAX
        MOV DWORD PTR SS:[EBP+0Ch],EAX

@aplib_55A91391:

        CMP EBX,080h
        JNB @aplib_55A9139F
        ADD EAX,2
        MOV DWORD PTR SS:[EBP+0Ch],EAX

@aplib_55A9139F:

        TEST EAX,EAX
        JE @aplib_55A913C1
        MOV EAX,DWORD PTR SS:[EBP-014h]
        MOV EDI,EAX
        SUB EDI,EBX
        LEA EBX,DWORD PTR DS:[EBX]

@aplib_55A913B0:

        MOV BL,BYTE PTR DS:[EDI]
        MOV BYTE PTR DS:[EAX],BL
        INC EAX
        INC EDI
        DEC DWORD PTR SS:[EBP+0Ch]
        JNZ @aplib_55A913B0
        MOV EBX,DWORD PTR SS:[EBP-4]
        MOV DWORD PTR SS:[EBP-014h],EAX

@aplib_55A913C1:

        MOV DWORD PTR SS:[EBP-4],EBX

@aplib_55A913C4:

        MOV EBX,1
        JMP @aplib_55A913D9

@aplib_55A913CB:

        MOV AL,BYTE PTR DS:[ESI]
        MOV EDI,DWORD PTR SS:[EBP-014h]
        MOV BYTE PTR DS:[EDI],AL
        INC EDI
        INC ESI

@aplib_55A913D4:

        MOV DWORD PTR SS:[EBP-014h],EDI

@aplib_55A913D7:

        XOR EBX,EBX

@aplib_55A913D9:

        CMP DWORD PTR SS:[EBP-8],0
        JE @aplib_55A91182
        MOV EAX,DWORD PTR SS:[EBP-014h]
        SUB EAX,DWORD PTR SS:[EBP+8]
        POP EDI
        POP ESI
        POP EBX
        MOV ESP,EBP
        POP EBP
        RETN 0Ch                             ;<= Procedure End
                          



depacker_end:
    ret

END
