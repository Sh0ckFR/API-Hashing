#include "stdafx.hpp"

namespace api {
	WCHAR* toLower(WCHAR *str) {
		WCHAR* start = str;
		while (*str) {
			if (*str <= L'Z' && *str >= 'A') {
				*str += 32;
			}
			str += 1;
		}
		return start;
	}

	// djb2 renamed 
	unsigned long djn1l(unsigned char* str) {
		unsigned long hash = APIHASHING_KEY;
		int c;

		while ((c = *str++))
			hash = ((hash << 5) + hash) + c;

		return hash;
	}

	// unicode_djb2 renamed
	unsigned long djn1lUnicode(const wchar_t* str)
	{
		unsigned long hash = APIHASHING_KEY;
		DWORD val;

		while (*str != 0) {
			val = (DWORD)*str++;
			hash = ((hash << 5) + hash) + val;
		}

		return hash;
	}

	// getDllBase
	uint64_t getBase(unsigned long dll_hash) {
		_PPEB ptr_peb = NULL;
		PPEB_LDR_DATA ptr_ldr_data = NULL;
		PLDR_DATA_TABLE_ENTRY ptr_module_entry = NULL, ptr_start_module = NULL;
		PUNICODE_STR dll_name = NULL;

		#ifdef _WIN64 // Check if the compilation is for x64 architecture
			ptr_peb = (_PPEB)__readgsqword(0x60);
		#else // x86 architecture
			ptr_peb = (_PPEB)__readfsdword(0x30);
		#endif

		ptr_ldr_data = ptr_peb->pLdr;
		ptr_module_entry = ptr_start_module = (PLDR_DATA_TABLE_ENTRY)ptr_ldr_data->InMemoryOrderModuleList.Flink;

		do {
			dll_name = &ptr_module_entry->BaseDllName;

			if (dll_name->pBuffer == NULL)
				return 0;

			if (djn1lUnicode(toLower(dll_name->pBuffer)) == dll_hash)
				return (uint64_t)ptr_module_entry->DllBase;

			ptr_module_entry = (PLDR_DATA_TABLE_ENTRY)ptr_module_entry->InMemoryOrderModuleList.Flink;
		} while (ptr_module_entry != ptr_start_module);

		return 0;
	}

	// parseHdrForPtr
	uint64_t parseToPtr(uint64_t dll_base, unsigned long function_hash) {
		PIMAGE_NT_HEADERS nt_hdrs = NULL;
		PIMAGE_DATA_DIRECTORY data_dir= NULL;
		PIMAGE_EXPORT_DIRECTORY export_dir= NULL;

		uint32_t* ptr_exportadrtable = 0x00;
		uint32_t* ptr_namepointertable = 0x00;
		uint16_t* ptr_ordinaltable = 0x00;

		uint32_t idx_functions = 0x00;

		unsigned char* ptr_function_name = NULL;

		nt_hdrs = (PIMAGE_NT_HEADERS)(dll_base + (uint64_t)((PIMAGE_DOS_HEADER)(size_t)dll_base)->e_lfanew);
		data_dir = (PIMAGE_DATA_DIRECTORY)&nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		export_dir = (PIMAGE_EXPORT_DIRECTORY)(dll_base + (uint64_t)data_dir->VirtualAddress);

		ptr_exportadrtable = (uint32_t*)(dll_base + (uint64_t)export_dir->AddressOfFunctions);
		ptr_namepointertable = (uint32_t*)(dll_base + (uint64_t)export_dir->AddressOfNames);
		ptr_ordinaltable = (uint16_t*)(dll_base + (uint64_t)export_dir->AddressOfNameOrdinals);

		for(idx_functions = 0; idx_functions < export_dir->NumberOfNames; idx_functions++){
			ptr_function_name = (unsigned char*)dll_base + (ptr_namepointertable[idx_functions]);
			if (djn1l(ptr_function_name) == function_hash) {
				WORD nameord = ptr_ordinaltable[idx_functions];
				DWORD rva = ptr_exportadrtable[nameord];
				return dll_base + rva;
			}
		}

		return 0;
	}

	// loadDll
	uint64_t loadMod(unsigned long dll_hash) {
		uint64_t kernel32_base = 0x00;
		uint64_t fptr_loadLibary = 0x00;
		uint64_t ptr_loaded_dll = 0x00;

		kernel32_base = getBase(H_KERNEL32);
		if (kernel32_base == 0x00)
			return 0;

		fptr_loadLibary = parseToPtr(kernel32_base, H_LOADLIBRARYA);
		if (fptr_loadLibary == 0x00)
			return 0;

		if (dll_hash == H_USER32) {
			char dll_name[] = { 'U', 's', 'e', 'r', '3' ,'2' ,'.', 'd', 'l', 'l', 0x00 };
			ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
		}  else if (dll_hash == H_WININET) {
			char dll_name[] = { 'W', 'i', 'n', 'i', 'n', 'e', 't', '.', 'd','l','l', 0x00 };
			ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
		} else if (dll_hash == H_ADVAPI32) {
			char dll_name[] = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0x00 };
			ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
		} else if (dll_hash == H_NTDLL) {
			char dll_name[] = { 'N', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x00 };
			ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
		}

		return ptr_loaded_dll;
	}

	// getFunctionPtr
	uint64_t getFuncApi(unsigned long dll_hash, unsigned long function_hash) {
		uint64_t dll_base = getBase(dll_hash);
		if (dll_base == 0) {
			dll_base = loadMod(dll_hash);
			if (dll_base == 0)
				return 0;
		}

		return parseToPtr(dll_base, function_hash);
	}
}
