// NLCompressor.cpp: определяет точку входа для приложения.
//
#include <Windows.h>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>


#pragma pack(push,1)
typedef struct _comp {
	WORD xor_seed;
	WORD sub_seed;
	DWORD original_size;
	DWORD compressed_size;
	BYTE compressed_buffer[1];
}*_pcomp;
#pragma pack(pop)


#include "CompressData.h"
#include "UnCompressData.h"

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,LPWSTR lpCmdLine, int nCmdShow){
	char buf[512];
	ZeroMemory(buf, 512);
	WideCharToMultiByte(CP_ACP, 0, lpCmdLine, -1, buf, 512, NULL, NULL);

	//Compress
	if (lstrlen(buf)) {
		OFSTRUCT ofs;
		HANDLE hFile = (HANDLE)OpenFile(buf, &ofs, OF_READ);
		if (hFile != (HANDLE)-1) {
			int FileSize = GetFileSize(hFile, 0);
			LPVOID pFile = new BYTE[FileSize];
			DWORD npd = 0;
			ReadFile(hFile, pFile, FileSize, &npd, 0);
			int TotalCompSize = 0;
			LPVOID pCompFile = Compress((char*)pFile, FileSize,FileSize+0x1000,(ULONG*)&TotalCompSize);
			lstrcat(buf, ".comp");
			HANDLE hcFile = (HANDLE)OpenFile(buf, &ofs, OF_CREATE | OF_WRITE);
			if (hcFile != (HANDLE)-1) {
				_pcomp comp_format = (_pcomp)new BYTE[12 + TotalCompSize];
				comp_format->xor_seed = (WORD)GetTickCount();
				comp_format->sub_seed = (comp_format->xor_seed / 2) + comp_format->xor_seed;
				comp_format->original_size = FileSize;
				comp_format->compressed_size = TotalCompSize;
				memcpy(comp_format->compressed_buffer, pCompFile, TotalCompSize);

				WORD xor_key = comp_format->xor_seed;
				for (int i = 0; i < TotalCompSize/2; i++) {
					((WORD*)comp_format)[2 + i] ^= xor_key;
					((WORD*)comp_format)[2 + i] -= comp_format->sub_seed;
				    xor_key+= i + 1234;
				}

				WriteFile(hcFile, comp_format, 12 + TotalCompSize, &npd, 0);
				CloseHandle(hcFile);
			}
			CloseHandle(hFile);
		}
		else {
			//Error
			MessageBoxA(0, "Cant open that file!", buf, 0);
		}
	}

	//Decompress
	/* 
	char str[512] = "NativeLoader.exe.comp";
	//Decompress
	if (lstrlen(str)) {
		OFSTRUCT ofs;
		HANDLE hFile = (HANDLE)OpenFile(str, &ofs, OF_READ);
		if (hFile != (HANDLE)-1) {
			int FileSize = GetFileSize(hFile, 0);
			_pcomp comp_format = (_pcomp)new BYTE[FileSize];
			DWORD npd = 0;
			ReadFile(hFile, comp_format, FileSize, &npd, 0);

			WORD xor_key = comp_format->xor_seed;

			for (int i = 0; i < 4; i++) {
				((WORD*)comp_format)[2 + i] += comp_format->sub_seed;
				((WORD*)comp_format)[2 + i] ^= xor_key;
				xor_key += i + 1234;
			}

			for (int i = 4; i < comp_format->compressed_size / 2; i++) {
				((WORD*)comp_format)[2 + i] += comp_format->sub_seed;
				((WORD*)comp_format)[2 + i] ^= xor_key;
				xor_key += i + 1234;
			}

			lstrcat(str, ".comp");
			HANDLE hcFile = (HANDLE)OpenFile(str, &ofs, OF_CREATE | OF_WRITE);
			if (hcFile != (HANDLE)-1) {
				ULONG uncomsize;
				LPVOID de_File = decompress_buffer((char*)comp_format->compressed_buffer, comp_format->compressed_size, comp_format->original_size, &uncomsize);
				WriteFile(hcFile, de_File,comp_format->original_size, &npd, 0);
				CloseHandle(hcFile);
			}
			CloseHandle(hFile);
		}

	}*/
	return 0;
}
