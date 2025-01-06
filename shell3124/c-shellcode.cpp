#include <Windows.h>
#include "peb-lookup.h"

// Strings almacenados en la sección .text
#pragma code_seg(".text")

__declspec(allocate(".text"))
wchar_t kernel32_str[] = L"kernel32.dll";

__declspec(allocate(".text"))
char load_lib_str[] = "LoadLibraryA";

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
    // stack based strings to be passed to the messagebox win api
    wchar_t msg_content[] = { 'H','e','l','l','o', ' ', 'W','o','r','l','d','!', 0 };
    wchar_t msg_title[] = { 'D','e','m','o','!', 0 };
    char  fileName[] = { 'D','e','r','m','o','.','t','x','t', 0};
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
    //Definir CreateFileA
    HANDLE(WINAPI * _CreateFileA)(
        _In_ LPCSTR lpFileName,
        _In_ DWORD dwDesiredAccess,
        _In_ DWORD dwShareMode,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_ DWORD dwCreationDisposition,
        _In_ DWORD dwFlagsAndAttributes,
        _In_opt_ HANDLE hTemplateFile
        ) = (HANDLE(WINAPI*)(
            _In_ LPCSTR ,
            _In_ DWORD ,
            _In_ DWORD ,
            _In_opt_ LPSECURITY_ATTRIBUTES ,
            _In_ DWORD ,
            _In_ DWORD ,
            _In_opt_ HANDLE 
            )) _GetProcAddress((HMODULE)k32_dll, cf_name);

    if (_CreateFileA == INVALID_HANDLE_VALUE)return 3;

    // Declarar el puntero a la función ReadFile
    BOOL(WINAPI * _ReadFile)(
        _In_ HANDLE hFile,
        _Out_ LPVOID lpBuffer,
        _In_ DWORD nNumberOfBytesToRead,
        _Out_opt_ LPDWORD lpNumberOfBytesRead,
        _Inout_opt_ LPOVERLAPPED lpOverlapped
        ) = (BOOL (WINAPI*)(
            _In_ HANDLE,
            _Out_ LPVOID,
            _In_ DWORD,
            _Out_opt_ LPDWORD,
            _Inout_opt_ LPOVERLAPPED
            )) _GetProcAddress((HMODULE)k32_dll, rf_name);

    if (_ReadFile == FALSE) return 4;

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

    // invoke the message box winapi
    _MessageBoxW(0, msg_content, msg_title, MB_OK);

    _CreateFileA(fileName,// Nombre del archivo
        GENERIC_WRITE,// Permiso de escritura
        0,// No compartir
        NULL,// Seguridad predeterminada
        CREATE_ALWAYS,// Crear siempre (sobrescribe si existe)
        FILE_ATTRIBUTE_NORMAL,// Atributos normales
        NULL);

    return 0;
}