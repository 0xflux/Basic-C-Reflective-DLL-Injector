#ifndef BOOTSTRAPPER_H
#define BOOTSTRAPPER_H

#include <windows.h>
#include "dll_injector.h"

// Function markers for bootstrapper code boundaries
void start_of_injectable_code();
void end_of_injectable_code();
void perform_base_relocation(LDLL_INFO dll_info, PIMAGE_NT_HEADERS nt);
void load_imports(LDLL_INFO dll_info, PIMAGE_NT_HEADERS nt);
void call_tls_callbacks(LDLL_INFO dll_info, PIMAGE_NT_HEADERS nt);
void execute_entry_point(LDLL_INFO dll_info, PIMAGE_NT_HEADERS nt);
void realign_pe(LDLL_INFO dll_info);

#endif