; Listing generated by Microsoft (R) Optimizing Compiler Version 19.41.34123.0 

include listing.inc


PUBLIC	?kernel32_str@@3PA_WA				; kernel32_str
PUBLIC	?load_lib_str@@3PADA				; load_lib_str
CONST	SEGMENT
$SG90582 DB	'CloseHandle', 00H
CONST	ENDS
_TEXT	SEGMENT
?load_lib_str@@3PADA DB 'LoadLibraryA', 00H		; load_lib_str
	ORG $+3
?kernel32_str@@3PA_WA DB 'k', 00H, 'e', 00H, 'r', 00H, 'n', 00H, 'e', 00H
	DB	'l', 00H, '3', 00H, '2', 00H, '.', 00H, 'd', 00H, 'l', 00H, 'l'
	DB	00H, 00H, 00H				; kernel32_str
_TEXT	ENDS
PUBLIC	?get_module_by_name@@YAPEAXPEA_W@Z		; get_module_by_name
PUBLIC	?get_func_by_name@@YAPEAXPEAXPEAD@Z		; get_func_by_name
PUBLIC	main
EXTRN	__imp_CloseHandle:PROC

;	COMDAT voltbl
voltbl	SEGMENT
_volmd	DB	014H
voltbl	ENDS

; Function compile flags: /Odtp
_TEXT	SEGMENT


; https://github.com/mattifestation/PIC_Bindshell/blob/master/PIC_Bindshell/AdjustStack.asm

; AlignRSP is a simple call stub that ensures that the stack is 16-byte aligned prior
; to calling the entry point of the payload. This is necessary because 64-bit functions
; in Windows assume that they were called with 16-byte stack alignment. When amd64
; shellcode is executed, you can't be assured that you stack is 16-byte aligned. For example,
; if your shellcode lands with 8-byte stack alignment, any call to a Win32 function will likely
; crash upon calling any ASM instruction that utilizes XMM registers (which require 16-byte)
; alignment.

AlignRSP PROC
    push rsi ; Preserve RSI since we're stomping on it
    mov rsi, rsp ; Save the value of RSP so it can be restored
    and rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
    sub rsp, 020h ; Allocate homing space for ExecutePayload
    call main ; Call the entry point of the payload
    mov rsp, rsi ; Restore the original value of RSP
    pop rsi ; Restore RSI
    ret ; Return to caller
AlignRSP ENDP

rf_name$ = 64
user32_dll_name$ = 80
cf_name$ = 96
message_box_name$ = 112
load_lib_name$ = 128
kr32_dll_name$ = 144
get_proc_name$ = 160
fileName$ = 176
mb_to_wc_name$ = 192
close_handle_name$ = 216
msg_title$ = 232
_GetProcAddress$ = 248
base$ = 256
kernel32_dll_name$ = 264
msg_content$ = 296
file_was_read$ = 328
wide_len$ = 332
k32_dll$ = 336
get_proc$ = 344
hFile$ = 352
_MessageBoxW$ = 360
_CreateFileA$ = 368
_ReadFile$ = 376
load_lib$ = 384
_LoadLibraryA$ = 392
close_handle_addr$ = 400
_MultiByteToWideChar$ = 408
_CloseHandle$ = 416
bufferSize$ = 424
bytesRead$ = 428
u32_dll$ = 432
buffer$ = 448
wide_buffer$ = 512
main	PROC
; File C:\Users\6lady\source\shel0101\shell3124\c-shellcode.cpp
; Line 13
$LN13:
	push	rdi
	sub	rsp, 640				; 00000280H
; Line 15
	mov	eax, 107				; 0000006bH
	mov	WORD PTR kernel32_dll_name$[rsp], ax
	mov	eax, 101				; 00000065H
	mov	WORD PTR kernel32_dll_name$[rsp+2], ax
	mov	eax, 114				; 00000072H
	mov	WORD PTR kernel32_dll_name$[rsp+4], ax
	mov	eax, 110				; 0000006eH
	mov	WORD PTR kernel32_dll_name$[rsp+6], ax
	mov	eax, 101				; 00000065H
	mov	WORD PTR kernel32_dll_name$[rsp+8], ax
	mov	eax, 108				; 0000006cH
	mov	WORD PTR kernel32_dll_name$[rsp+10], ax
	mov	eax, 51					; 00000033H
	mov	WORD PTR kernel32_dll_name$[rsp+12], ax
	mov	eax, 50					; 00000032H
	mov	WORD PTR kernel32_dll_name$[rsp+14], ax
	mov	eax, 46					; 0000002eH
	mov	WORD PTR kernel32_dll_name$[rsp+16], ax
	mov	eax, 100				; 00000064H
	mov	WORD PTR kernel32_dll_name$[rsp+18], ax
	mov	eax, 108				; 0000006cH
	mov	WORD PTR kernel32_dll_name$[rsp+20], ax
	mov	eax, 108				; 0000006cH
	mov	WORD PTR kernel32_dll_name$[rsp+22], ax
	xor	eax, eax
	mov	WORD PTR kernel32_dll_name$[rsp+24], ax
; Line 16
	mov	BYTE PTR load_lib_name$[rsp], 76	; 0000004cH
	mov	BYTE PTR load_lib_name$[rsp+1], 111	; 0000006fH
	mov	BYTE PTR load_lib_name$[rsp+2], 97	; 00000061H
	mov	BYTE PTR load_lib_name$[rsp+3], 100	; 00000064H
	mov	BYTE PTR load_lib_name$[rsp+4], 76	; 0000004cH
	mov	BYTE PTR load_lib_name$[rsp+5], 105	; 00000069H
	mov	BYTE PTR load_lib_name$[rsp+6], 98	; 00000062H
	mov	BYTE PTR load_lib_name$[rsp+7], 114	; 00000072H
	mov	BYTE PTR load_lib_name$[rsp+8], 97	; 00000061H
	mov	BYTE PTR load_lib_name$[rsp+9], 114	; 00000072H
	mov	BYTE PTR load_lib_name$[rsp+10], 121	; 00000079H
	mov	BYTE PTR load_lib_name$[rsp+11], 65	; 00000041H
	mov	BYTE PTR load_lib_name$[rsp+12], 0
; Line 17
	mov	BYTE PTR get_proc_name$[rsp], 71	; 00000047H
	mov	BYTE PTR get_proc_name$[rsp+1], 101	; 00000065H
	mov	BYTE PTR get_proc_name$[rsp+2], 116	; 00000074H
	mov	BYTE PTR get_proc_name$[rsp+3], 80	; 00000050H
	mov	BYTE PTR get_proc_name$[rsp+4], 114	; 00000072H
	mov	BYTE PTR get_proc_name$[rsp+5], 111	; 0000006fH
	mov	BYTE PTR get_proc_name$[rsp+6], 99	; 00000063H
	mov	BYTE PTR get_proc_name$[rsp+7], 65	; 00000041H
	mov	BYTE PTR get_proc_name$[rsp+8], 100	; 00000064H
	mov	BYTE PTR get_proc_name$[rsp+9], 100	; 00000064H
	mov	BYTE PTR get_proc_name$[rsp+10], 114	; 00000072H
	mov	BYTE PTR get_proc_name$[rsp+11], 101	; 00000065H
	mov	BYTE PTR get_proc_name$[rsp+12], 115	; 00000073H
	mov	BYTE PTR get_proc_name$[rsp+13], 115	; 00000073H
	mov	BYTE PTR get_proc_name$[rsp+14], 0
; Line 18
	mov	BYTE PTR kr32_dll_name$[rsp], 107	; 0000006bH
	mov	BYTE PTR kr32_dll_name$[rsp+1], 101	; 00000065H
	mov	BYTE PTR kr32_dll_name$[rsp+2], 114	; 00000072H
	mov	BYTE PTR kr32_dll_name$[rsp+3], 110	; 0000006eH
	mov	BYTE PTR kr32_dll_name$[rsp+4], 101	; 00000065H
	mov	BYTE PTR kr32_dll_name$[rsp+5], 108	; 0000006cH
	mov	BYTE PTR kr32_dll_name$[rsp+6], 51	; 00000033H
	mov	BYTE PTR kr32_dll_name$[rsp+7], 50	; 00000032H
	mov	BYTE PTR kr32_dll_name$[rsp+8], 46	; 0000002eH
	mov	BYTE PTR kr32_dll_name$[rsp+9], 100	; 00000064H
	mov	BYTE PTR kr32_dll_name$[rsp+10], 108	; 0000006cH
	mov	BYTE PTR kr32_dll_name$[rsp+11], 108	; 0000006cH
	mov	BYTE PTR kr32_dll_name$[rsp+12], 0
; Line 19
	mov	BYTE PTR user32_dll_name$[rsp], 117	; 00000075H
	mov	BYTE PTR user32_dll_name$[rsp+1], 115	; 00000073H
	mov	BYTE PTR user32_dll_name$[rsp+2], 101	; 00000065H
	mov	BYTE PTR user32_dll_name$[rsp+3], 114	; 00000072H
	mov	BYTE PTR user32_dll_name$[rsp+4], 51	; 00000033H
	mov	BYTE PTR user32_dll_name$[rsp+5], 50	; 00000032H
	mov	BYTE PTR user32_dll_name$[rsp+6], 46	; 0000002eH
	mov	BYTE PTR user32_dll_name$[rsp+7], 100	; 00000064H
	mov	BYTE PTR user32_dll_name$[rsp+8], 108	; 0000006cH
	mov	BYTE PTR user32_dll_name$[rsp+9], 108	; 0000006cH
	mov	BYTE PTR user32_dll_name$[rsp+10], 0
; Line 20
	mov	BYTE PTR message_box_name$[rsp], 77	; 0000004dH
	mov	BYTE PTR message_box_name$[rsp+1], 101	; 00000065H
	mov	BYTE PTR message_box_name$[rsp+2], 115	; 00000073H
	mov	BYTE PTR message_box_name$[rsp+3], 115	; 00000073H
	mov	BYTE PTR message_box_name$[rsp+4], 97	; 00000061H
	mov	BYTE PTR message_box_name$[rsp+5], 103	; 00000067H
	mov	BYTE PTR message_box_name$[rsp+6], 101	; 00000065H
	mov	BYTE PTR message_box_name$[rsp+7], 66	; 00000042H
	mov	BYTE PTR message_box_name$[rsp+8], 111	; 0000006fH
	mov	BYTE PTR message_box_name$[rsp+9], 120	; 00000078H
	mov	BYTE PTR message_box_name$[rsp+10], 87	; 00000057H
	mov	BYTE PTR message_box_name$[rsp+11], 0
; Line 21
	mov	BYTE PTR cf_name$[rsp], 67		; 00000043H
	mov	BYTE PTR cf_name$[rsp+1], 114		; 00000072H
	mov	BYTE PTR cf_name$[rsp+2], 101		; 00000065H
	mov	BYTE PTR cf_name$[rsp+3], 97		; 00000061H
	mov	BYTE PTR cf_name$[rsp+4], 116		; 00000074H
	mov	BYTE PTR cf_name$[rsp+5], 101		; 00000065H
	mov	BYTE PTR cf_name$[rsp+6], 70		; 00000046H
	mov	BYTE PTR cf_name$[rsp+7], 105		; 00000069H
	mov	BYTE PTR cf_name$[rsp+8], 108		; 0000006cH
	mov	BYTE PTR cf_name$[rsp+9], 101		; 00000065H
	mov	BYTE PTR cf_name$[rsp+10], 65		; 00000041H
	mov	BYTE PTR cf_name$[rsp+11], 0
; Line 22
	mov	BYTE PTR rf_name$[rsp], 82		; 00000052H
	mov	BYTE PTR rf_name$[rsp+1], 101		; 00000065H
	mov	BYTE PTR rf_name$[rsp+2], 97		; 00000061H
	mov	BYTE PTR rf_name$[rsp+3], 100		; 00000064H
	mov	BYTE PTR rf_name$[rsp+4], 70		; 00000046H
	mov	BYTE PTR rf_name$[rsp+5], 105		; 00000069H
	mov	BYTE PTR rf_name$[rsp+6], 108		; 0000006cH
	mov	BYTE PTR rf_name$[rsp+7], 101		; 00000065H
	mov	BYTE PTR rf_name$[rsp+8], 0
; Line 23
	mov	BYTE PTR close_handle_name$[rsp], 67	; 00000043H
	mov	BYTE PTR close_handle_name$[rsp+1], 108	; 0000006cH
	mov	BYTE PTR close_handle_name$[rsp+2], 111	; 0000006fH
	mov	BYTE PTR close_handle_name$[rsp+3], 115	; 00000073H
	mov	BYTE PTR close_handle_name$[rsp+4], 101	; 00000065H
	mov	BYTE PTR close_handle_name$[rsp+5], 72	; 00000048H
	mov	BYTE PTR close_handle_name$[rsp+6], 97	; 00000061H
	mov	BYTE PTR close_handle_name$[rsp+7], 110	; 0000006eH
	mov	BYTE PTR close_handle_name$[rsp+8], 100	; 00000064H
	mov	BYTE PTR close_handle_name$[rsp+9], 108	; 0000006cH
	mov	BYTE PTR close_handle_name$[rsp+10], 101 ; 00000065H
	mov	BYTE PTR close_handle_name$[rsp+11], 0
; Line 24
	mov	BYTE PTR mb_to_wc_name$[rsp], 77	; 0000004dH
	mov	BYTE PTR mb_to_wc_name$[rsp+1], 117	; 00000075H
	mov	BYTE PTR mb_to_wc_name$[rsp+2], 108	; 0000006cH
	mov	BYTE PTR mb_to_wc_name$[rsp+3], 116	; 00000074H
	mov	BYTE PTR mb_to_wc_name$[rsp+4], 105	; 00000069H
	mov	BYTE PTR mb_to_wc_name$[rsp+5], 66	; 00000042H
	mov	BYTE PTR mb_to_wc_name$[rsp+6], 121	; 00000079H
	mov	BYTE PTR mb_to_wc_name$[rsp+7], 116	; 00000074H
	mov	BYTE PTR mb_to_wc_name$[rsp+8], 101	; 00000065H
	mov	BYTE PTR mb_to_wc_name$[rsp+9], 84	; 00000054H
	mov	BYTE PTR mb_to_wc_name$[rsp+10], 111	; 0000006fH
	mov	BYTE PTR mb_to_wc_name$[rsp+11], 87	; 00000057H
	mov	BYTE PTR mb_to_wc_name$[rsp+12], 105	; 00000069H
	mov	BYTE PTR mb_to_wc_name$[rsp+13], 100	; 00000064H
	mov	BYTE PTR mb_to_wc_name$[rsp+14], 101	; 00000065H
	mov	BYTE PTR mb_to_wc_name$[rsp+15], 67	; 00000043H
	mov	BYTE PTR mb_to_wc_name$[rsp+16], 104	; 00000068H
	mov	BYTE PTR mb_to_wc_name$[rsp+17], 97	; 00000061H
	mov	BYTE PTR mb_to_wc_name$[rsp+18], 114	; 00000072H
	mov	BYTE PTR mb_to_wc_name$[rsp+19], 0
; Line 28
	mov	eax, 72					; 00000048H
	mov	WORD PTR msg_content$[rsp], ax
	mov	eax, 101				; 00000065H
	mov	WORD PTR msg_content$[rsp+2], ax
	mov	eax, 108				; 0000006cH
	mov	WORD PTR msg_content$[rsp+4], ax
	mov	eax, 108				; 0000006cH
	mov	WORD PTR msg_content$[rsp+6], ax
	mov	eax, 111				; 0000006fH
	mov	WORD PTR msg_content$[rsp+8], ax
	mov	eax, 32					; 00000020H
	mov	WORD PTR msg_content$[rsp+10], ax
	mov	eax, 87					; 00000057H
	mov	WORD PTR msg_content$[rsp+12], ax
	mov	eax, 111				; 0000006fH
	mov	WORD PTR msg_content$[rsp+14], ax
	mov	eax, 114				; 00000072H
	mov	WORD PTR msg_content$[rsp+16], ax
	mov	eax, 108				; 0000006cH
	mov	WORD PTR msg_content$[rsp+18], ax
	mov	eax, 100				; 00000064H
	mov	WORD PTR msg_content$[rsp+20], ax
	mov	eax, 33					; 00000021H
	mov	WORD PTR msg_content$[rsp+22], ax
	xor	eax, eax
	mov	WORD PTR msg_content$[rsp+24], ax
; Line 29
	mov	eax, 68					; 00000044H
	mov	WORD PTR msg_title$[rsp], ax
	mov	eax, 101				; 00000065H
	mov	WORD PTR msg_title$[rsp+2], ax
	mov	eax, 109				; 0000006dH
	mov	WORD PTR msg_title$[rsp+4], ax
	mov	eax, 111				; 0000006fH
	mov	WORD PTR msg_title$[rsp+6], ax
	mov	eax, 33					; 00000021H
	mov	WORD PTR msg_title$[rsp+8], ax
	xor	eax, eax
	mov	WORD PTR msg_title$[rsp+10], ax
; Line 30
	mov	BYTE PTR fileName$[rsp], 99		; 00000063H
	mov	BYTE PTR fileName$[rsp+1], 45		; 0000002dH
	mov	BYTE PTR fileName$[rsp+2], 115		; 00000073H
	mov	BYTE PTR fileName$[rsp+3], 104		; 00000068H
	mov	BYTE PTR fileName$[rsp+4], 101		; 00000065H
	mov	BYTE PTR fileName$[rsp+5], 108		; 0000006cH
	mov	BYTE PTR fileName$[rsp+6], 108		; 0000006cH
	mov	BYTE PTR fileName$[rsp+7], 99		; 00000063H
	mov	BYTE PTR fileName$[rsp+8], 111		; 0000006fH
	mov	BYTE PTR fileName$[rsp+9], 100		; 00000064H
	mov	BYTE PTR fileName$[rsp+10], 101		; 00000065H
	mov	BYTE PTR fileName$[rsp+11], 46		; 0000002eH
	mov	BYTE PTR fileName$[rsp+12], 101		; 00000065H
	mov	BYTE PTR fileName$[rsp+13], 120		; 00000078H
	mov	BYTE PTR fileName$[rsp+14], 101		; 00000065H
	mov	BYTE PTR fileName$[rsp+15], 0
; Line 32
	mov	DWORD PTR bufferSize$[rsp], 64		; 00000040H
; Line 33
	lea	rax, QWORD PTR buffer$[rsp]
	mov	rdi, rax
	xor	eax, eax
	mov	ecx, 64					; 00000040H
	rep stosb
; Line 39
	lea	rcx, QWORD PTR kernel32_dll_name$[rsp]
	call	?get_module_by_name@@YAPEAXPEA_W@Z	; get_module_by_name
	mov	QWORD PTR base$[rsp], rax
; Line 40
	cmp	QWORD PTR base$[rsp], 0
	jne	SHORT $LN2@main
; Line 41
	mov	eax, 1
	jmp	$LN1@main
$LN2@main:
; Line 45
	lea	rdx, QWORD PTR load_lib_name$[rsp]
	mov	rcx, QWORD PTR base$[rsp]
	call	?get_func_by_name@@YAPEAXPEAXPEAD@Z	; get_func_by_name
	mov	QWORD PTR load_lib$[rsp], rax
; Line 46
	cmp	QWORD PTR load_lib$[rsp], 0
	jne	SHORT $LN3@main
; Line 47
	mov	eax, 2
	jmp	$LN1@main
$LN3@main:
; Line 51
	lea	rdx, QWORD PTR get_proc_name$[rsp]
	mov	rcx, QWORD PTR base$[rsp]
	call	?get_func_by_name@@YAPEAXPEAXPEAD@Z	; get_func_by_name
	mov	QWORD PTR get_proc$[rsp], rax
; Line 52
	cmp	QWORD PTR get_proc$[rsp], 0
	jne	SHORT $LN4@main
; Line 53
	mov	eax, 3
	jmp	$LN1@main
$LN4@main:
; Line 59
	mov	rax, QWORD PTR load_lib$[rsp]
	mov	QWORD PTR _LoadLibraryA$[rsp], rax
; Line 61
	mov	rax, QWORD PTR get_proc$[rsp]
	mov	QWORD PTR _GetProcAddress$[rsp], rax
; Line 64
	lea	rcx, QWORD PTR user32_dll_name$[rsp]
	call	QWORD PTR _LoadLibraryA$[rsp]
	mov	QWORD PTR u32_dll$[rsp], rax
; Line 66
	lea	rcx, QWORD PTR kr32_dll_name$[rsp]
	call	QWORD PTR _LoadLibraryA$[rsp]
	mov	QWORD PTR k32_dll$[rsp], rax
; Line 76
	lea	rdx, QWORD PTR cf_name$[rsp]
	mov	rcx, QWORD PTR k32_dll$[rsp]
	call	QWORD PTR _GetProcAddress$[rsp]
	mov	QWORD PTR _CreateFileA$[rsp], rax
; Line 86
	cmp	QWORD PTR _CreateFileA$[rsp], -1
	jne	SHORT $LN5@main
	mov	eax, 3
	jmp	$LN1@main
$LN5@main:
; Line 96
	lea	rdx, QWORD PTR rf_name$[rsp]
	mov	rcx, QWORD PTR k32_dll$[rsp]
	call	QWORD PTR _GetProcAddress$[rsp]
	mov	QWORD PTR _ReadFile$[rsp], rax
; Line 103
	cmp	QWORD PTR _ReadFile$[rsp], 0
	jne	SHORT $LN6@main
	mov	eax, 4
	jmp	$LN1@main
$LN6@main:
; Line 110
	lea	rdx, QWORD PTR message_box_name$[rsp]
	mov	rcx, QWORD PTR u32_dll$[rsp]
	call	QWORD PTR _GetProcAddress$[rsp]
	mov	QWORD PTR _MessageBoxW$[rsp], rax
; Line 116
	cmp	QWORD PTR _MessageBoxW$[rsp], 0
	jne	SHORT $LN7@main
	mov	eax, 5
	jmp	$LN1@main
$LN7@main:
; Line 126
	lea	rdx, QWORD PTR mb_to_wc_name$[rsp]
	mov	rcx, QWORD PTR k32_dll$[rsp]
	call	QWORD PTR _GetProcAddress$[rsp]
	mov	QWORD PTR _MultiByteToWideChar$[rsp], rax
; Line 136
	lea	rdx, OFFSET $SG90582
	mov	rcx, QWORD PTR base$[rsp]
	call	QWORD PTR get_proc$[rsp]
	mov	QWORD PTR close_handle_addr$[rsp], rax
; Line 137
	cmp	QWORD PTR close_handle_addr$[rsp], 0
	jne	SHORT $LN8@main
; Line 138
	mov	eax, 4
	jmp	$LN1@main
$LN8@main:
; Line 142
	mov	rax, QWORD PTR close_handle_addr$[rsp]
	mov	QWORD PTR _CloseHandle$[rsp], rax
; Line 146
	xor	r9d, r9d
	lea	r8, QWORD PTR msg_title$[rsp]
	lea	rdx, QWORD PTR msg_content$[rsp]
	xor	ecx, ecx
	call	QWORD PTR _MessageBoxW$[rsp]
; Line 148
	mov	QWORD PTR [rsp+48], 0
	mov	DWORD PTR [rsp+40], 128			; 00000080H
	mov	DWORD PTR [rsp+32], 2
	xor	r9d, r9d
	xor	r8d, r8d
	mov	edx, 1073741824				; 40000000H
	lea	rcx, QWORD PTR fileName$[rsp]
	call	QWORD PTR _CreateFileA$[rsp]
	mov	QWORD PTR hFile$[rsp], rax
; Line 156
	mov	QWORD PTR [rsp+32], 0
	lea	r9, QWORD PTR bytesRead$[rsp]
	mov	r8d, 63					; 0000003fH
	lea	rdx, QWORD PTR buffer$[rsp]
	mov	rcx, QWORD PTR hFile$[rsp]
	call	QWORD PTR _ReadFile$[rsp]
	mov	DWORD PTR file_was_read$[rsp], eax
; Line 157
	cmp	DWORD PTR file_was_read$[rsp], 0
	jne	SHORT $LN9@main
; Line 158
	mov	rcx, QWORD PTR hFile$[rsp]
	call	QWORD PTR __imp_CloseHandle
; Line 159
	mov	eax, 6
	jmp	SHORT $LN1@main
$LN9@main:
; Line 163
	mov	DWORD PTR [rsp+40], 64			; 00000040H
	lea	rax, QWORD PTR wide_buffer$[rsp]
	mov	QWORD PTR [rsp+32], rax
	mov	r9d, -1
	lea	r8, QWORD PTR buffer$[rsp]
	xor	edx, edx
	xor	ecx, ecx
	call	QWORD PTR _MultiByteToWideChar$[rsp]
	mov	DWORD PTR wide_len$[rsp], eax
; Line 172
	cmp	DWORD PTR wide_len$[rsp], 0
	jne	SHORT $LN10@main
; Line 173
	mov	eax, 8
	jmp	SHORT $LN1@main
$LN10@main:
; Line 176
	mov	rcx, QWORD PTR hFile$[rsp]
	call	QWORD PTR _CloseHandle$[rsp]
	test	eax, eax
	jne	SHORT $LN11@main
; Line 177
	mov	eax, 5
	jmp	SHORT $LN1@main
$LN11@main:
; Line 180
	xor	r9d, r9d
	lea	r8, QWORD PTR msg_title$[rsp]
	lea	rdx, QWORD PTR wide_buffer$[rsp]
	xor	ecx, ecx
	call	QWORD PTR _MessageBoxW$[rsp]
; Line 182
	xor	eax, eax
$LN1@main:
; Line 183
	add	rsp, 640				; 00000280H
	pop	rdi
	ret	0
main	ENDP
_TEXT	ENDS
; Function compile flags: /Odtp
;	COMDAT ?get_func_by_name@@YAPEAXPEAXPEAD@Z
_TEXT	SEGMENT
k$1 = 0
i$2 = 8
exp$ = 16
expAddr$ = 24
funcNamesListRVA$ = 28
namesOrdsListRVA$ = 32
funcsListRVA$ = 36
curr_name$3 = 40
idh$ = 48
exportsDir$ = 56
nt_headers$ = 64
namesCount$ = 72
nameIndex$4 = 80
nameRVA$5 = 88
funcRVA$6 = 96
module$ = 128
func_name$ = 136
?get_func_by_name@@YAPEAXPEAXPEAD@Z PROC		; get_func_by_name, COMDAT
; File C:\Users\6lady\source\shel0101\shell3124\peb-lookup.h
; Line 104
$LN13:
	mov	QWORD PTR [rsp+16], rdx
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 120				; 00000078H
; Line 105
	mov	rax, QWORD PTR module$[rsp]
	mov	QWORD PTR idh$[rsp], rax
; Line 106
	mov	rax, QWORD PTR idh$[rsp]
	movzx	eax, WORD PTR [rax]
	cmp	eax, 23117				; 00005a4dH
	je	SHORT $LN8@get_func_b
; Line 107
	xor	eax, eax
	jmp	$LN1@get_func_b
$LN8@get_func_b:
; Line 109
	mov	rax, QWORD PTR idh$[rsp]
	movsxd	rax, DWORD PTR [rax+60]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	QWORD PTR nt_headers$[rsp], rax
; Line 110
	mov	eax, 8
	imul	rax, rax, 0
	mov	rcx, QWORD PTR nt_headers$[rsp]
	lea	rax, QWORD PTR [rcx+rax+136]
	mov	QWORD PTR exportsDir$[rsp], rax
; Line 111
	mov	rax, QWORD PTR exportsDir$[rsp]
	cmp	DWORD PTR [rax], 0
	jne	SHORT $LN9@get_func_b
; Line 112
	xor	eax, eax
	jmp	$LN1@get_func_b
$LN9@get_func_b:
; Line 115
	mov	rax, QWORD PTR exportsDir$[rsp]
	mov	eax, DWORD PTR [rax]
	mov	DWORD PTR expAddr$[rsp], eax
; Line 116
	mov	eax, DWORD PTR expAddr$[rsp]
	add	rax, QWORD PTR module$[rsp]
	mov	QWORD PTR exp$[rsp], rax
; Line 117
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+24]
	mov	QWORD PTR namesCount$[rsp], rax
; Line 119
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+28]
	mov	DWORD PTR funcsListRVA$[rsp], eax
; Line 120
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+32]
	mov	DWORD PTR funcNamesListRVA$[rsp], eax
; Line 121
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+36]
	mov	DWORD PTR namesOrdsListRVA$[rsp], eax
; Line 124
	mov	QWORD PTR i$2[rsp], 0
	jmp	SHORT $LN4@get_func_b
$LN2@get_func_b:
	mov	rax, QWORD PTR i$2[rsp]
	inc	rax
	mov	QWORD PTR i$2[rsp], rax
$LN4@get_func_b:
	mov	rax, QWORD PTR namesCount$[rsp]
	cmp	QWORD PTR i$2[rsp], rax
	jae	$LN3@get_func_b
; Line 125
	mov	eax, DWORD PTR funcNamesListRVA$[rsp]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	rcx, QWORD PTR i$2[rsp]
	lea	rax, QWORD PTR [rax+rcx*4]
	mov	QWORD PTR nameRVA$5[rsp], rax
; Line 126
	mov	eax, DWORD PTR namesOrdsListRVA$[rsp]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	rcx, QWORD PTR i$2[rsp]
	lea	rax, QWORD PTR [rax+rcx*2]
	mov	QWORD PTR nameIndex$4[rsp], rax
; Line 127
	mov	eax, DWORD PTR funcsListRVA$[rsp]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	rcx, QWORD PTR nameIndex$4[rsp]
	movzx	ecx, WORD PTR [rcx]
	lea	rax, QWORD PTR [rax+rcx*4]
	mov	QWORD PTR funcRVA$6[rsp], rax
; Line 129
	mov	rax, QWORD PTR nameRVA$5[rsp]
	mov	eax, DWORD PTR [rax]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	QWORD PTR curr_name$3[rsp], rax
; Line 130
	mov	QWORD PTR k$1[rsp], 0
; Line 131
	mov	QWORD PTR k$1[rsp], 0
	jmp	SHORT $LN7@get_func_b
$LN5@get_func_b:
	mov	rax, QWORD PTR k$1[rsp]
	inc	rax
	mov	QWORD PTR k$1[rsp], rax
$LN7@get_func_b:
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR func_name$[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	je	SHORT $LN6@get_func_b
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR curr_name$3[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	je	SHORT $LN6@get_func_b
; Line 132
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR func_name$[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	mov	rcx, QWORD PTR k$1[rsp]
	mov	rdx, QWORD PTR curr_name$3[rsp]
	add	rdx, rcx
	mov	rcx, rdx
	movsx	ecx, BYTE PTR [rcx]
	cmp	eax, ecx
	je	SHORT $LN10@get_func_b
	jmp	SHORT $LN6@get_func_b
$LN10@get_func_b:
; Line 133
	jmp	SHORT $LN5@get_func_b
$LN6@get_func_b:
; Line 134
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR func_name$[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	jne	SHORT $LN11@get_func_b
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR curr_name$3[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	jne	SHORT $LN11@get_func_b
; Line 136
	mov	rax, QWORD PTR funcRVA$6[rsp]
	mov	eax, DWORD PTR [rax]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	jmp	SHORT $LN1@get_func_b
$LN11@get_func_b:
; Line 138
	jmp	$LN2@get_func_b
$LN3@get_func_b:
; Line 139
	xor	eax, eax
$LN1@get_func_b:
; Line 140
	add	rsp, 120				; 00000078H
	ret	0
?get_func_by_name@@YAPEAXPEAXPEAD@Z ENDP		; get_func_by_name
_TEXT	ENDS
; Function compile flags: /Odtp
;	COMDAT ?get_module_by_name@@YAPEAXPEA_W@Z
_TEXT	SEGMENT
i$1 = 0
tv136 = 8
tv155 = 10
c1$2 = 12
c2$3 = 16
curr_name$4 = 24
curr_module$ = 32
tv132 = 40
tv151 = 44
peb$ = 48
ldr$ = 56
Flink$ = 64
list$ = 72
module_name$ = 128
?get_module_by_name@@YAPEAXPEA_W@Z PROC			; get_module_by_name, COMDAT
; File C:\Users\6lady\source\shel0101\shell3124\peb-lookup.h
; Line 69
$LN16:
	mov	QWORD PTR [rsp+8], rcx
	push	rsi
	push	rdi
	sub	rsp, 104				; 00000068H
; Line 70
	mov	QWORD PTR peb$[rsp], 0
; Line 72
	mov	rax, QWORD PTR gs:[96]
	mov	QWORD PTR peb$[rsp], rax
; Line 76
	mov	rax, QWORD PTR peb$[rsp]
	mov	rax, QWORD PTR [rax+24]
	mov	QWORD PTR ldr$[rsp], rax
; Line 77
	lea	rax, QWORD PTR list$[rsp]
	mov	rcx, QWORD PTR ldr$[rsp]
	mov	rdi, rax
	lea	rsi, QWORD PTR [rcx+16]
	mov	ecx, 16
	rep movsb
; Line 79
	mov	rax, QWORD PTR list$[rsp]
	mov	QWORD PTR Flink$[rsp], rax
; Line 80
	mov	rax, QWORD PTR Flink$[rsp]
	mov	QWORD PTR curr_module$[rsp], rax
$LN15@get_module:
$LN2@get_module:
; Line 82
	cmp	QWORD PTR curr_module$[rsp], 0
	je	$LN3@get_module
	mov	rax, QWORD PTR curr_module$[rsp]
	cmp	QWORD PTR [rax+48], 0
	je	$LN3@get_module
; Line 83
	mov	rax, QWORD PTR curr_module$[rsp]
	cmp	QWORD PTR [rax+96], 0
	jne	SHORT $LN7@get_module
	jmp	SHORT $LN2@get_module
$LN7@get_module:
; Line 84
	mov	rax, QWORD PTR curr_module$[rsp]
	mov	rax, QWORD PTR [rax+96]
	mov	QWORD PTR curr_name$4[rsp], rax
; Line 86
	mov	QWORD PTR i$1[rsp], 0
; Line 87
	mov	QWORD PTR i$1[rsp], 0
	jmp	SHORT $LN6@get_module
$LN4@get_module:
	mov	rax, QWORD PTR i$1[rsp]
	inc	rax
	mov	QWORD PTR i$1[rsp], rax
$LN6@get_module:
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	je	$LN5@get_module
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	je	$LN5@get_module
; Line 89
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 90					; 0000005aH
	jg	SHORT $LN11@get_module
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 65					; 00000041H
	jl	SHORT $LN11@get_module
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	sub	eax, 65					; 00000041H
	add	eax, 97					; 00000061H
	mov	DWORD PTR tv132[rsp], eax
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	edx, WORD PTR tv132[rsp]
	mov	WORD PTR [rax+rcx*2], dx
	movzx	eax, WORD PTR tv132[rsp]
	mov	WORD PTR tv136[rsp], ax
	jmp	SHORT $LN12@get_module
$LN11@get_module:
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	mov	WORD PTR tv136[rsp], ax
$LN12@get_module:
	movzx	eax, WORD PTR tv136[rsp]
	mov	WORD PTR c1$2[rsp], ax
; Line 90
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 90					; 0000005aH
	jg	SHORT $LN13@get_module
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 65					; 00000041H
	jl	SHORT $LN13@get_module
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	sub	eax, 65					; 00000041H
	add	eax, 97					; 00000061H
	mov	DWORD PTR tv151[rsp], eax
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	edx, WORD PTR tv151[rsp]
	mov	WORD PTR [rax+rcx*2], dx
	movzx	eax, WORD PTR tv151[rsp]
	mov	WORD PTR tv155[rsp], ax
	jmp	SHORT $LN14@get_module
$LN13@get_module:
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	mov	WORD PTR tv155[rsp], ax
$LN14@get_module:
	movzx	eax, WORD PTR tv155[rsp]
	mov	WORD PTR c2$3[rsp], ax
; Line 91
	movzx	eax, WORD PTR c1$2[rsp]
	movzx	ecx, WORD PTR c2$3[rsp]
	cmp	eax, ecx
	je	SHORT $LN8@get_module
	jmp	SHORT $LN5@get_module
$LN8@get_module:
; Line 92
	jmp	$LN4@get_module
$LN5@get_module:
; Line 93
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	jne	SHORT $LN9@get_module
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	jne	SHORT $LN9@get_module
; Line 95
	mov	rax, QWORD PTR curr_module$[rsp]
	mov	rax, QWORD PTR [rax+48]
	jmp	SHORT $LN1@get_module
$LN9@get_module:
; Line 98
	mov	rax, QWORD PTR curr_module$[rsp]
	mov	rax, QWORD PTR [rax]
	mov	QWORD PTR curr_module$[rsp], rax
; Line 99
	jmp	$LN15@get_module
$LN3@get_module:
; Line 100
	xor	eax, eax
$LN1@get_module:
; Line 101
	add	rsp, 104				; 00000068H
	pop	rdi
	pop	rsi
	ret	0
?get_module_by_name@@YAPEAXPEA_W@Z ENDP			; get_module_by_name
_TEXT	ENDS
END
