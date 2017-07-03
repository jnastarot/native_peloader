// NativeLoader.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"

#include "structures.h"

#include "test_loader.h"
#include "native_loader.h"





int main()
{
	
	char str[512] = "ClearDll.dll.comp";
	OFSTRUCT ofs;
	HANDLE hFile = (HANDLE)OpenFile(str, &ofs, OF_READ);
	if (hFile != (HANDLE)-1) {
		int FileSize = GetFileSize(hFile, 0);
		LPVOID comp_format = (LPVOID)new BYTE[FileSize];
		DWORD npd = 0;
		DWORD qwe;
	//	VirtualProtect(loader, sizeof(loader), PAGE_EXECUTE_READWRITE, &qwe);
		ReadFile(hFile, comp_format, FileSize, &npd, 0);

		MemoryLoad((_comp*)comp_format);
	//	MemoryLoad(comp_format);
	}
	

    return 0;
}

