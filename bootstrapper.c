#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "dll_injector.h"


void start_of_injectable_code() {
}

void perform_base_relocation(LDLL_INFO dll_info, PIMAGE_NT_HEADERS nt) {
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0) {
        PIMAGE_BASE_RELOCATION relocation_block = (PIMAGE_BASE_RELOCATION)((LPBYTE)dll_info->base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        ULONGLONG delta = (ULONGLONG)(dll_info->base - nt->OptionalHeader.ImageBase);
        while (relocation_block->VirtualAddress) {
            if (relocation_block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                int count = (relocation_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD list = (PWORD)(relocation_block + 1);
                for (int i = 0; i < count; i++) {
                    if (list[i] >> 12 == IMAGE_REL_BASED_DIR64) {
                        PULONGLONG ptr = (PULONGLONG)((LPBYTE)dll_info->base + (relocation_block->VirtualAddress + (list[i] & 0xFFF)));
                        *ptr += delta;
                    }
                }
            }
            relocation_block = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation_block + relocation_block->SizeOfBlock);
        }
    }
}

void load_imports(LDLL_INFO dll_info, PIMAGE_NT_HEADERS nt) {
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)dll_info->base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (import_desc->Name != 0) {
            LPCSTR module_name = (LPCSTR)((LPBYTE)dll_info->base + import_desc->Name);
            HMODULE module = (*dll_info->load_library_a_addr)(module_name);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((LPBYTE)dll_info->base + import_desc->FirstThunk);
            while (thunk->u1.AddressOfData != 0) {
                LPBYTE func_name = (LPBYTE)dll_info->base + thunk->u1.AddressOfData + 2;
                FARPROC func = (*dll_info->get_process_addr)(module, (LPCSTR)func_name);
                *(FARPROC *)&thunk->u1.Function = func;
                ++thunk;
            }
            ++import_desc;
        }
    }
}

void call_tls_callbacks(LDLL_INFO dll_info, PIMAGE_NT_HEADERS nt) {
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0) {
        PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY)((LPBYTE)dll_info->base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK *)tls_dir->AddressOfCallBacks;
        if (callback) {
            while (*callback) {
                (*callback)(dll_info->base, DLL_PROCESS_ATTACH, NULL);
                ++callback;
            }
        }
    }
}

void execute_entry_point(LDLL_INFO dll_info, PIMAGE_NT_HEADERS nt) {
    typedef BOOL (WINAPI *DLL_MAIN)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

    if (nt->OptionalHeader.AddressOfEntryPoint != 0) {
        DLL_MAIN entry_point = (DLL_MAIN)((LPBYTE)dll_info->base + nt->OptionalHeader.AddressOfEntryPoint);
        entry_point(dll_info->base, DLL_PROCESS_ATTACH, NULL);
    }
}

void realign_pe(LDLL_INFO dll_info) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_info->base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LPBYTE)dll_info->base + dos_header->e_lfanew);
    
    if (dll_info->base_relocation_required) {
        perform_base_relocation(dll_info, nt);
    }
    
    load_imports(dll_info, nt);
    
    call_tls_callbacks(dll_info, nt);
    
    execute_entry_point(dll_info, nt);
}

void end_of_injectable_code() {
}