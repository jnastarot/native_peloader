#pragma once

typedef NTSTATUS(__stdcall *_RtlCompressBuffer)(
	USHORT CompressionFormatAndEngine,
	PUCHAR UncompressedBuffer,
	ULONG UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG CompressedBufferSize,
	ULONG UncompressedChunkSize,
	PULONG FinalCompressedSize,
	PVOID WorkSpace
	);

typedef NTSTATUS(__stdcall *_RtlDecompressBuffer)(
	USHORT CompressionFormat,
	PUCHAR UncompressedBuffer,
	ULONG UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG CompressedBufferSize,
	PULONG FinalUncompressedSize
	);

typedef NTSTATUS(__stdcall *_RtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormatAndEngine,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
	);

void * Compress(const char *buffer, const ULONG bufferLen, ULONG compBufferLen, ULONG *compBufferSize) {
	HMODULE ntdll = GetModuleHandle("ntdll.dll");
	_RtlCompressBuffer RtlCompressBuffer = (_RtlCompressBuffer)GetProcAddress(ntdll, "RtlCompressBuffer");
	_RtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize = (_RtlGetCompressionWorkSpaceSize)GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize");
	ULONG bufWorkspaceSize;  // Workspace Size
	ULONG fragWorkspaceSize; // Fragmented Workspace Size (Unused)
	NTSTATUS ret = RtlGetCompressionWorkSpaceSize(
		COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, // CompressionFormatAndEngine
		&bufWorkspaceSize,                                     // CompressBufferWorkSpaceSize
		&fragWorkspaceSize                                     // CompressFragmentWorkSpaceSize
	);
	VOID *workspace = (VOID *)LocalAlloc(LMEM_FIXED, bufWorkspaceSize);

	UCHAR *compBuffer = new UCHAR[compBufferLen];
	NTSTATUS result = RtlCompressBuffer(
		COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, // CompressionFormatAndEngine
		(UCHAR *)buffer,                                       // UncompressedBuffer
		bufferLen,                                             // UncompressedBufferSize
		compBuffer,                                            // CompressedBuffer
		compBufferLen,                                         // CompressedBufferSize
		4096,                                                  // UncompressedChunkSize
		compBufferSize,                                        // FinalCompressedSize
		workspace
	);
	LocalFree(workspace);
	return compBuffer;
}