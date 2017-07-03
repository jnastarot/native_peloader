#pragma once
#include <winternl.h>

#define memcpy(x,y,z) for(int i = 0; i < z;i++) {*(BYTE*)((long long)x + i) = *(BYTE*)((long long)y + i);}
#define memset(x,y,z)  for(int i = 0; i < z;i++) {*(BYTE*)((long long)x + i) = y;}

#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#define GET_HEADER_DICTIONARY(headers, idx)	&headers->OptionalHeader.DataDirectory[idx]

typedef HMODULE(*CustomLoadLibraryFunc)(LPCSTR);
typedef FARPROC(*CustomGetProcAddressFunc)(HMODULE, LPCSTR);
typedef void(*CustomFreeLibraryFunc)(HMODULE);
typedef LPVOID(*CustomVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(*CustomIsBadReadPtr)(CONST VOID *lp, UINT_PTR ucb);

typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

#pragma pack(push, 1)
typedef struct _comp {
	WORD xor_seed;
	WORD sub_seed;
	DWORD original_size;
	DWORD compressed_size;
	BYTE compressed_buffer[1];
}*_pcomp;
#pragma pack(pop)
typedef NTSTATUS(WINAPI *  _ZwAllocateVirtualMemory)(HANDLE ProcessHandle,PVOID *BaseAddress,ULONG_PTR ZeroBits,PSIZE_T RegionSize,ULONG AllocationType,ULONG Protect);
/*5A 77 41 6C 6C 6F 63 61 74 65 56 69 72 74 75 61 6C 4D 65 6D 6F 72 79*/
typedef NTSTATUS(WINAPI *  _ZwFreeVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
/*5A 77 46 72 65 65 56 69 72 74 75 61 6C 4D 65 6D 6F 72 79*/
typedef NTSTATUS(WINAPI *  _LdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, HMODULE *ModuleHandle);
/*4C 64 72 4C 6F 61 64 44 6C 6C*/
typedef NTSTATUS(WINAPI *  _LdrGetProcedureAddress)(HMODULE ModuleHandle,PANSI_STRING FunctionName,WORD Oridinal,PVOID *FunctionAddress);
/*4C 64 72 47 65 74 50 72 6F 63 65 64 75 72 65 41 64 64 72 65 73 73*/
typedef NTSTATUS(WINAPI *_RtlDecompressBuffer)(USHORT CompressionFormat,PUCHAR UncompressedBuffer,ULONG UncompressedBufferSize,PUCHAR CompressedBuffer,ULONG CompressedBufferSize,PULONG FinalUncompressedSize);
/*52 74 6C 44 65 63 6F 6D 70 72 65 73 73 42 75 66 66 65 72*/
typedef NTSTATUS(WINAPI * _RtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, PANSI_STRING   SourceString, BOOLEAN AllocateDestinationString);
/*52 74 6C 41 6E 73 69 53 74 72 69 6E 67 54 6F 55 6E 69 63 6F 64 65 53 74 72 69 6E 67*/
typedef VOID(	 WINAPI * _RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
/*52 74 6C 46 72 65 65 55 6E 69 63 6F 64 65 53 74 72 69 6E 67*/
#ifdef _M_IX86
typedef struct _ModuleInfoNode {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	HMODULE BaseAddress;
	unsigned long entryPoint;
	unsigned int size;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	unsigned long flags;
	unsigned short LoadCount;
	unsigned short TlsIndex;
	LIST_ENTRY HashTable;
	unsigned long timestamp;
} ModuleInfoNode, *pModuleInfoNode;

typedef struct _ProcessModuleInfo {
	unsigned int size;
	unsigned int initialized;
	HANDLE SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} ProcessModuleInfo, *pProcessModuleInfo;
#else
typedef struct _ModuleInfoNode {

	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;

} ModuleInfoNode, *pModuleInfoNode;

typedef struct _ProcessModuleInfo {
	/*000*/  ULONG Length;
	/*004*/  BOOLEAN Initialized;
	/*008*/  PVOID SsHandle;
	/*00C*/  LIST_ENTRY ModuleListLoadOrder;
	/*014*/  LIST_ENTRY ModuleListMemoryOrder;
	/*018*/  LIST_ENTRY ModuleListInitOrder;
	/*020*/
} ProcessModuleInfo, *pProcessModuleInfo;
#endif
