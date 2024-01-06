#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "dll_injector.h"


void start_of_injectable_code() {
}

// Adjusts and realigns the PE file within the target process memory
void realign_pe(LDLL_INFO dll_info) {
    PIMAGE_DOS_HEADER dos_header            = NULL;
    PIMAGE_NT_HEADERS nt                    = NULL;
    LPVOID base                             = NULL;
    PIMAGE_IMPORT_DESCRIPTOR import         = NULL;
    PIMAGE_THUNK_DATA original_thunk        = NULL; 
    PIMAGE_THUNK_DATA first_thunk           = NULL;
    PIMAGE_BASE_RELOCATION relocation_block = NULL;
    PIMAGE_TLS_DIRECTORY tls                = NULL;
    PIMAGE_TLS_CALLBACK *callback           = NULL;

    // function pointers for dynamic loading
    BOOL (*dll_entry)(LPVOID, DWORD, LPVOID);
    LPVOID (*load_dll)(LPSTR);
    LPVOID (*get_proc)(LPVOID, LPSTR);

    // set base addresses and function pointers from DLL_INFO struct 
    base = dll_info->base; // base address of the DLL in the target process
    load_dll = dll_info->load_library_a_addr; // pointer to LoadLibraryA in the target process
    get_proc = dll_info->get_process_addr; // pointer to GetProcAddress in the target process

    // access the PE headers of the DLL in the target process
    dos_header = (PIMAGE_DOS_HEADER)base;
    nt = (PIMAGE_NT_HEADERS)(base + dos_header->e_lfanew);

    // address of the DLL's entry point
    dll_entry = base + nt->OptionalHeader.AddressOfEntryPoint;

    // check if base relocation is required (happens if the DLL is loaded at a different address than its preferred one)
    if (!dll_info->base_relocation_required) {
        goto load_import;
    }

// Base Relocation: Adjust addresses in the relocation table
base_relocation:
        // check if relocation table exists
        if (nt->OptionalHeader.DataDirectory[5].VirtualAddress == 0) { 
            // no relocation table found
            goto load_import;
        }

        ULONGLONG *relocation_address = NULL;

        // calculate the difference between the preferred and actual base addresses
        ULONGLONG base_addr_delta = (ULONGLONG)base - nt->OptionalHeader.ImageBase;
        relocation_block = (PIMAGE_BASE_RELOCATION)(base + nt->OptionalHeader.DataDirectory[5].VirtualAddress);
        
        // iterate over the relocation table and adjust addresses
        while (relocation_block->VirtualAddress) {
            LPVOID relocation_target = base + relocation_block->VirtualAddress;
            int nEntry = (relocation_block->SizeOfBlock - sizeof(PIMAGE_BASE_RELOCATION)) / 2;
            PWORD data = (PWORD)((LPVOID)relocation_block + sizeof(PIMAGE_BASE_RELOCATION));
            
            int i;
            for (i = 0; i < nEntry; i++, data++) {
                if ((*data) >> 12 == 10) { // type 10 indicates a 64-bit address
                    relocation_address = (PULONGLONG)(relocation_target + ((*data) &0xfff)); // address to be relocated
                    *relocation_address += base_addr_delta; // do the relocation
                }
            }

            relocation_block = (PIMAGE_BASE_RELOCATION)((LPVOID)relocation_block + relocation_block->SizeOfBlock);

        }

// Load imports: Adjust pointers to imported functions
load_import:
        // check if import table exists
        if (nt->OptionalHeader.DataDirectory[1].VirtualAddress == 0) {
            goto tls_callback;
        }

        // iterate over the import table and resolve addresses
        import = (PIMAGE_IMPORT_DESCRIPTOR)(base + nt->OptionalHeader.DataDirectory[1].VirtualAddress);
        while (import->Name) {
            LPVOID dll = (*load_dll)(base + import->Name);
            original_thunk = (PIMAGE_THUNK_DATA)(base + import->OriginalFirstThunk);
            first_thunk = (PIMAGE_THUNK_DATA)(base + import->FirstThunk);

            if (!import->OriginalFirstThunk) {
                original_thunk = first_thunk;
            }

            while(original_thunk->u1.AddressOfData) {
                if (original_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // import by ordinal
                    *(ULONGLONG *)first_thunk = (ULONGLONG)(*get_proc)(dll, (LPSTR)IMAGE_ORDINAL(original_thunk->u1.Ordinal));
                } else {
                    // import by name
                    PIMAGE_IMPORT_BY_NAME fnm = (PIMAGE_IMPORT_BY_NAME)(base + original_thunk->u1.AddressOfData);
                    *(PULONGLONG)first_thunk = (ULONGLONG)(*get_proc)(dll, fnm->Name);
                }
                original_thunk++;
                first_thunk++;
            }
            import++;
        }

// TLS Callbacks: Call TLS (Thread Local Storage) callbacks if any
tls_callback:
        if(nt->OptionalHeader.DataDirectory[9].VirtualAddress == 0) {
            goto execute_entry_point;
        }

        tls = (PIMAGE_TLS_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[9].VirtualAddress);

        if (tls->AddressOfCallBacks == 0) {
            goto execute_entry_point;
        }

        callback = (PIMAGE_TLS_CALLBACK *)(tls->AddressOfCallBacks);
        while(*callback) {
            (*callback)(base, DLL_PROCESS_ATTACH, NULL); // call the TLS callback
            callback++;
        }

// Execute Entry Point: Call the DLL's entry
execute_entry_point:
        (*dll_entry)(base, DLL_PROCESS_ATTACH, NULL);
}


void end_of_injectable_code() {
}