#ifndef DLL_INJECTOR_H
#define DLL_INJECTOR_H

#include <windows.h>
#include <tlhelp32.h>

/**
 * Structure to hold various pointers and flags related to a PE (Portable Executable) file.
 * This includes pointers to functions like GetProcAddress() and LoadLibraryA()
 */

typedef HMODULE (WINAPI *LoadLibraryAFunc)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI *GetProcAddressFunc)(HMODULE hModule, LPCSTR lpProcName);

typedef struct _DLL_INFO {
    GetProcAddressFunc get_process_addr;
    LoadLibraryAFunc load_library_a_addr;
    LPVOID base;
    BOOL base_relocation_required;
} DLL_INFO, *LDLL_INFO;

// prototypes
LPVOID load_dll_from_resource(const char *dll_path, int resourceID);
LPVOID read_dll_from_file(char *FileName);
HANDLE find_process_and_get_handle(char *process_name);

#endif // DLL_INJECTOR_H