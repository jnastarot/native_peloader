#pragma once

UCHAR *decompress_buffer(const char *buffer, const int bufferLen, const int uncompBufferLen, ULONG *uncompBufferSize)
{
	HMODULE ntdll = GetModuleHandle("ntdll.dll");
	_RtlDecompressBuffer RtlDecompressBuffer = (_RtlDecompressBuffer)GetProcAddress(ntdll, "RtlDecompressBuffer");

	UCHAR *uncompBuffer = new UCHAR[uncompBufferLen];
	NTSTATUS result = RtlDecompressBuffer(
		COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, // CompressionFormat
		uncompBuffer,                                          // UncompressedBuffer
		uncompBufferLen,                                       // UncompressedBufferSize
		(UCHAR *)buffer,                                       // CompressedBuffer
		bufferLen,                                             // CompressedBufferSize
		uncompBufferSize                                       // FinalUncompressedSize
	);

	return uncompBuffer;
}