#ifndef DLL_INJECTOR_H
#define DLL_INJECTOR_H

#include <windows.h>
#include <tlhelp32.h>

/**
 * Structure to hold various pointers and flags related to a PE (Portable Executable) file.
 * This includes pointers to functions like GetProcAddress() and LoadLibraryA()
 */
typedef struct _DLL_INFO {
    LPVOID get_process_addr;
    LPVOID load_library_a_addr;
    LPVOID base;
    BOOL base_relocation_required;
} DLL_INFO, *LDLL_INFO;

// prototypes
LPVOID load_dll_from_resource(const char *dll_path, int resourceID);
LPVOID read_dll_from_file(char *FileName);
HANDLE find_process_and_get_handle(char *process_name);
int launch_reflective_processes(char *process_name);

// to allow DLL builds
#ifdef BUILD_DLL
__declspec(dllexport) void runMain();
#endif

#endif // DLL_INJECTOR_H