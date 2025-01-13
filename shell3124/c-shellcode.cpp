#include <Windows.h>
#include "peb-lookup.h"

// Strings almacenados en la sección .text
#pragma code_seg(".text")

__declspec(allocate(".text"))
wchar_t kernel32_str[] = L"kernel32.dll";

__declspec(allocate(".text"))
char load_lib_str[] = "LoadLibraryA";
void* GetTextSection(HMODULE hModule, DWORD* sectionSize) {
    // Obtener el encabezado DOS
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL; // No es un archivo válido
    }

    // Obtener el encabezado NT
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL; // Encabezado NT inválido
    }

    // Obtener la tabla de secciones
    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);

    // Iterar por las secciones
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)sectionHeaders[i].Name, ".text", 5) == 0) {
            *sectionSize = sectionHeaders[i].Misc.VirtualSize;
            return (void*)((BYTE*)hModule + sectionHeaders[i].VirtualAddress);
        }
    }

    return NULL; // Sección .text no encontrada
}
int main() {
    // Stack based strings for libraries and functions the shellcode needs
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char kr32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char user32_dll_name[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
    char message_box_name[] = { 'M','e','s','s','a','g','e','B','o','x','W', 0 };
    char cf_name[] = { 'C','r','e','a','t','e','F','i','l','e','A', 0 };
    char rf_name[] = { 'R','e','a','d','F','i','l','e', 0};
    char close_handle_name[] = { 'C','l','o','s','e','H','a','n','d','l','e', 0 };
    char mb_to_wc_name[] = { 'M','u','l','t','i','B','y','t','e','T','o','W','i','d','e','C','h','a','r', 0 };

    
    // stack based strings to be passed to the messagebox win api
    wchar_t msg_content[] = { 'H','e','l','l','o', ' ', 'W','o','r','l','d','!', 0 };
    wchar_t msg_title[] = { 'D','e','m','o','!', 0 };
    char  fileName[] = { 'c', '-', 's','h','e','l','l','c','o','d','e','.','e','x','e', 0};
    // Read the file
    const DWORD bufferSize = 64;
    char buffer[bufferSize] = { 0 };
    DWORD bytesRead;
    wchar_t wide_buffer[bufferSize]; // Crear un buffer Unicode
    // String que contiene el nombre del archivo
    //char fileName[] = "example.txt";
      // resolve kernel32 image base
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

    // Declarar el puntero a la función ReadFile
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

    // Resolver la dirección de MultiByteToWideChar
    int (WINAPI * _MultiByteToWideChar)(
        _In_ UINT CodePage,
        _In_ DWORD dwFlags,
        _In_NLS_string_(cbMultiByte) LPCCH lpMultiByteStr,
        _In_ int cbMultiByte,
        _Out_writes_opt_(cchWideChar) LPWSTR lpWideCharStr,
        _In_ int cchWideChar
        ) = (int (WINAPI*)(
            UINT, DWORD, LPCCH, int, LPWSTR, int)) _GetProcAddress((HMODULE)k32_dll, mb_to_wc_name);
    // Resolver la dirección de CloseHandle
    BOOL(WINAPI * _CloseHandle)(HANDLE hObject);

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


    // Leer el archivo
    BOOL file_was_read = _ReadFile(hFile, buffer, bufferSize - 1, &bytesRead, NULL);
    if (!file_was_read) {
        _MessageBoxW(0, L"Error al leer el archivo", L"Error", MB_OK);

        return 6; // Error leyendo el archivo
    }
    // invoke the message box winapi
    _MessageBoxW(0, msg_content, msg_title, MB_OK);
    // Convertir el buffer de `char` a `wchar_t`
    int wide_len = _MultiByteToWideChar(
        CP_ACP,           // Página de código ANSI
        0,                // Sin banderas adicionales
        buffer,           // Cadena de origen en formato char
        -1,               // Longitud de la cadena (terminada en NULL)
        wide_buffer,      // Buffer de destino en formato wchar_t
        bufferSize        // Tamaño del buffer de destino
    );
    // invoke the message box winapi
    _MessageBoxW(0, msg_content, msg_title, MB_OK);

    _CloseHandle = (BOOL(WINAPI*)(HANDLE)) _GetProcAddress((HMODULE)k32_dll, close_handle_name);

    // print the dos header
    _MessageBoxW(0, wide_buffer, msg_title, MB_OK);

    if (wide_len == 0) {
        return 8; // Error al convertir
    }


    return 0;
}