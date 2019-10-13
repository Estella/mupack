#include "../stdafx.h"
#include <winnt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <imagehlp.h>//#include <Dbghelp.h>
#include "pack_x86.h"
#include "patternfind.h"
#include "../logger.h"
#include "../mudlib.h"
#include "Types.h"
#include "fr_pack/frpacker.hpp"
PE pe;
//Internal dll calls
const char *dlls[] = { "kernel32.dll" };
const char *thunks[] = { "VirtualAlloc", "VirtualFree", "VirtualProtect", "GetProcAddress", "GetModuleHandleA", "" };



#define Test86MSByte(b) ((b) == 0 || (b) == 0xFF)
//defined twice, i know but we use it in the PE stub.
size_t x86_codefilter_(uint8_t *data, size_t size)
{
	uint32_t state = 0;
	uint32_t ip = 0;
	int encoding = 1;
	const uint8_t kMaskToAllowedStatus[8] = { 1, 1, 1, 0, 1, 0, 0, 0 };
	const uint8_t kMaskToBitNumber[8] = { 0, 1, 2, 2, 3, 3, 3, 3 };
	size_t bufferPos = 0, prevPosT;
	uint32_t prevMask = state & 0x7;
	if (size < 5)
		return 0;
	ip += 5;
	prevPosT = (size_t)0 - 1;

	for (;;)
	{
		uint8_t *p = data + bufferPos;
		uint8_t *limit = data + size - 4;
		for (; p < limit; p++)
			if ((*p & 0xFE) == 0xE8)
				break;
		bufferPos = (size_t)(p - data);
		if (p >= limit)
			break;
		prevPosT = bufferPos - prevPosT;
		if (prevPosT > 3)
			prevMask = 0;
		else
		{
			prevMask = (prevMask << ((int)prevPosT - 1)) & 0x7;
			if (prevMask != 0)
			{
				uint8_t b = p[4 - kMaskToBitNumber[prevMask]];
				if (!kMaskToAllowedStatus[prevMask] || Test86MSByte(b))
				{
					prevPosT = bufferPos;
					prevMask = ((prevMask << 1) & 0x7) | 1;
					bufferPos++;
					continue;
				}
			}
		}
		prevPosT = bufferPos;

		if (Test86MSByte(p[4]))
		{
			uint32_t src = ((uint32_t)p[4] << 24) | ((uint32_t)p[3] << 16) | ((uint32_t)p[2] << 8) | ((uint32_t)p[1]);
			uint32_t dest;
			for (;;)
			{
				uint8_t b;
				int index;
				if (encoding)
					dest = (ip + (uint32_t)bufferPos) + src;
				else
					dest = src - (ip + (uint32_t)bufferPos);
				if (prevMask == 0)
					break;
				index = kMaskToBitNumber[prevMask] * 8;
				b = (uint8_t)(dest >> (24 - index));
				if (!Test86MSByte(b))
					break;
				src = dest ^ ((1 << (32 - index)) - 1);
			}
			p[4] = (uint8_t)(~(((dest >> 24) & 1) - 1));
			p[3] = (uint8_t)(dest >> 16);
			p[2] = (uint8_t)(dest >> 8);
			p[1] = (uint8_t)dest;
			bufferPos += 5;
		}
		else
		{
			prevMask = ((prevMask << 1) & 0x7) | 1;
			bufferPos++;
		}
	}
	prevPosT = bufferPos - prevPosT;
	state = ((prevPosT > 3) ? 0 : ((prevMask << ((int)prevPosT - 1)) & 0x7));
	return bufferPos;
}


const int MOD_ADLER = 65521;

DWORD adler32(unsigned char *data, size_t len) /* where data is the location of the data in physical memory and
											   len is the length of the data in bytes */
{
	DWORD a = 1, b = 0;
	size_t index;
	/* Process each byte of the data in order */
	for (index = 0; index < len; ++index)
	{
		a = (a + data[index]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}
	return (b << 16) | a;
}

int wsstrcpy(char *dest, const char *src)
{
	strcpy(dest, src);
	return strlen(dest);
}




int compress_file(TCHAR* argv)
{
	LogMessage* message = LogMessage::GetSingleton();
	compress_data_ compress_data;
	compress_functions_ compress_functions;
	compress_data = &compress_fr;
	compress_functions = &functions_fr;
	ZeroMemory(&pe, sizeof(PE));
	if (!pe_read(argv, &pe))
	{
		message->DoLogMessage(L"File packed unsuccessfully!", ERR_ERROR);
		return 1;
	}
	TCHAR outfile[MAX_PATH] = { 0 };
	TCHAR ext[MAX_PATH] = { 0 };
	TCHAR *dot = wcschr(argv, L'.');
	if (dot) lstrcpy(ext, dot);
	lstrcpy(outfile, argv);
	lstrcat(outfile, L".packed");
	lstrcat(outfile, ext);


	/* Initialize internal dll calls */
	DWORD pe_dlls_count = sizeof(dlls) / 4;
	pe.dlls = (char**)malloc((pe_dlls_count + 1) * 4);
	for (int i = 0; i < pe_dlls_count; i++)
	{
		pe.dlls[i] = (char*)malloc(strlen(dlls[i]) + 1);
		strcpy(pe.dlls[i], dlls[i]);
	}
	DWORD pe_thunks_count = sizeof(thunks) / 4;
	pe.thunks = (char**)malloc(pe_thunks_count * 4);
	for (int i = 0; i < pe_thunks_count; i++)
	{
		pe.thunks[i] = (char*)malloc(strlen(thunks[i]) + 1);
		strcpy(pe.thunks[i], thunks[i]);
	}

	/* Throw in a single import for each dll the original executable needs, except for kernel32 */
	PIMAGE_IMPORT_DESCRIPTOR Imports;
	PIMAGE_IMPORT_BY_NAME iNames;
	const char *name;
	DWORD dwThunk;
	DWORD *Thunk;
	const char *shortest_name;
	DWORD shortest_length;
	char ordinal_name[16];
	Imports = (PIMAGE_IMPORT_DESCRIPTOR)rvatoffset(pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, &pe);
	while (Imports->Name)
	{
		name = (const char *)rvatoffset(Imports->Name, &pe);
		if (stricmp(name, "kernel32") && stricmp(name, "kernel32.dll"))
		{
			shortest_length = ~0u;
			dwThunk = Imports->OriginalFirstThunk ? Imports->OriginalFirstThunk : Imports->FirstThunk;
			Thunk = (DWORD*)rvatoffset(dwThunk, &pe);
			dwThunk = Imports->FirstThunk;
			while (*Thunk)
			{
				if (*Thunk & IMAGE_ORDINAL_FLAG)
				{
					sprintf_s(ordinal_name, "@%u", LOWORD(*Thunk));
					shortest_name = ordinal_name;
					shortest_length = 0;
					break;
				}
				else
				{
					iNames = (IMAGE_IMPORT_BY_NAME*)rvatoffset(*Thunk, &pe);
					size_t name_length = strlen((const char*)iNames->Name);
					if (name_length < shortest_length)
					{
						shortest_length = name_length;
						shortest_name = (const char *)iNames->Name;
					}
				}
				dwThunk += sizeof(DWORD);
				Thunk++;
			}

			++pe_dlls_count;
			pe.dlls = (char **)realloc(pe.dlls, (pe_dlls_count + 1) * 4);
			pe_thunks_count += 2;
			pe.thunks = (char **)realloc(pe.thunks, pe_thunks_count * 4);

			pe.dlls[pe_dlls_count - 1] = (char *)malloc(strlen(name) + 1);
			strcpy(pe.dlls[pe_dlls_count - 1], name);

			pe.thunks[pe_thunks_count - 2] = (char *)malloc(strlen(shortest_name) + 1);
			strcpy(pe.thunks[pe_thunks_count - 2], shortest_name);
			pe.thunks[pe_thunks_count - 1] = (char *)malloc(1);
			pe.thunks[pe_thunks_count - 1][0] = '\0';
		}
		Imports++;
	}

	pe.dlls[pe_dlls_count] = (char *)malloc(1);
	pe.dlls[pe_dlls_count][0] = '\0';

	/* Calculate the space we need for dll calls */
	char **_dlls = pe.dlls;
	char **_thunks = pe.thunks;
	pe.sz_dllimports = sizeof(IMAGE_IMPORT_DESCRIPTOR); //zero import space
	while (*(*_dlls))
	{
		pe.sz_dllimports += sizeof(IMAGE_IMPORT_DESCRIPTOR); //import space
		pe.sz_dllimports += strlen(*_dlls); //import name space
		pe.sz_dllimports += sizeof(DWORD); //zero thunk space
		while (*(*_thunks))
		{
			if (*(*_thunks) == '@')
			{
				pe.sz_dllimports += sizeof(DWORD);
			}
			else
			{
				pe.sz_dllimports += sizeof(DWORD); //thunk space
				pe.sz_dllimports += sizeof(WORD) + strlen(*_thunks); //thunk hint + name space
			}
			_thunks++;
		}
		pe.sz_dllimports++;
		_thunks++;
		_dlls++;
	}

	pe.sz_dllexports = 0;

	if (pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
	{
		pe.sz_dllexports = pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		pe.new_exports = (unsigned char *)malloc(pe.sz_dllexports);

		PIMAGE_EXPORT_DIRECTORY _in = (PIMAGE_EXPORT_DIRECTORY)rvatoffset(pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &pe);
		PIMAGE_EXPORT_DIRECTORY _out = (PIMAGE_EXPORT_DIRECTORY)pe.new_exports;

		memcpy(_out, _in, pe.sz_dllexports);

		_out->Name = rvatoffset(_in->Name, &pe) - (DWORD)_in;
		_out->AddressOfFunctions = rvatoffset(_in->AddressOfFunctions, &pe) - (DWORD)_in;
		_out->AddressOfNames = rvatoffset(_in->AddressOfNames, &pe) - (DWORD)_in;
		_out->AddressOfNameOrdinals = rvatoffset(_in->AddressOfNameOrdinals, &pe) - (DWORD)_in;

		DWORD * address = (DWORD *)(rvatoffset(_in->AddressOfNames, &pe) - (DWORD)_in + (DWORD)_out);

		for (int i = 0; i < _in->NumberOfNames; i++)
		{
			*address = rvatoffset(*address, &pe) - (DWORD)_in;
			address++;
		}

		memset(_in, 0, pe.sz_dllexports);
	}

	//preserve TLS callbacks if they are there

	if (pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		pe.ptr_tlsdir = (PIMAGE_TLS_DIRECTORY32)malloc(sizeof(IMAGE_TLS_DIRECTORY32));
		memset(pe.ptr_tlsdir, 0, sizeof(IMAGE_TLS_DIRECTORY32));
		TCHAR data[256] = { 0 };
		DWORD *tls_callbackptr = 0;
		wsprintf(data, L"Found TLS directory at 0x%04X...", pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		message->DoLogMessage(data, ERR_INFO);
		IMAGE_TLS_DIRECTORY32 *ptr = (IMAGE_TLS_DIRECTORY32*)rvatoffset(pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, &pe);
		memcpy(pe.ptr_tlsdir, ptr, sizeof(IMAGE_TLS_DIRECTORY32));
		tls_callbackptr = (DWORD*)rvatoffset(pe.ptr_tlsdir->AddressOfCallBacks - pe.int_headers.OptionalHeader.ImageBase, &pe);
		pe.tls_callbacksnum = 0;
		while (*tls_callbackptr != 0)
		{
			pe.tls_callbacksnum++;
			tls_callbackptr += sizeof(DWORD);
		}
		if (pe.tls_callbacksnum)
		{
			pe.tls_callbacksnum = (sizeof(DWORD)*pe.tls_callbacksnum + 1);
		}
	}

	if (pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size)
	{
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
	}


	if (pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size)
	{
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	}


	DWORD diff = 0; //General section offset difference
	DWORD carray = 0; //Section compression tracker



	pe.compdata_struct = malloc(sizeof(DWORD));
	for (int i = 0; i < pe.int_headers.FileHeader.NumberOfSections; i++)
	{
		DWORD imageBase = pe.int_headers.OptionalHeader.ImageBase;
		DWORD codeStart = pe.int_headers.OptionalHeader.BaseOfCode;
		DWORD codeSize = pe.int_headers.OptionalHeader.SizeOfCode;
		TCHAR data[256] = { 0 };

		if (pe.m_sections[i].header.SizeOfRawData)
		{
			pe.m_sections[i].header.PointerToRawData -= diff;
			//Resources
			if (pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == pe.m_sections[i].header.VirtualAddress)
			{
				message->DoLogMessage(L"Compressing resources...", ERR_INFO);
				unsigned char* resources_backup = (unsigned char *)malloc(pe.m_sections[i].header.SizeOfRawData);
				memcpy(resources_backup, pe.m_sections[i].data, pe.m_sections[i].header.SizeOfRawData);
				PIMAGE_RESOURCE_DIRECTORY rescdir = (PIMAGE_RESOURCE_DIRECTORY)pe.m_sections[i].data, _rescdir;
				pe.resourcedir_address = (DWORD)pe.m_sections[i].data;
				DWORD baseresc;
				DWORD numentries = 0;
				pe.new_resource_section = (unsigned char *)malloc(pe.m_sections[i].header.SizeOfRawData);
				pe.new_resource_section_size = 0;
				pe.new_resource_data_size = 0;
				pe.new_resource_cdata_size = 0;
				PrepareNewResourceDirectory(rescdir, (DWORD)rescdir, 0, 0);
				pe.new_resource_section = (unsigned char *)realloc(pe.new_resource_section, pe.new_resource_section_size + pe.new_resource_data_size + pe.new_resource_cdata_size);
				baseresc = pe.new_resource_section_size + pe.new_resource_data_size;
				_rescdir = (PIMAGE_RESOURCE_DIRECTORY)pe.new_resource_section;
				pe.resource_section_virtual_address = pe.m_sections[i].header.VirtualAddress;
				ProcessResourceDirectory(rescdir, (DWORD)rescdir, _rescdir, (DWORD)_rescdir, 0, 0);
				//compress
				try {
					pe.m_sections[i].cdata = compress_data(pe.new_resource_section + baseresc, pe.new_resource_cdata_size, &pe.m_sections[i].csize);
					if (!pe.m_sections[i].cdata)
					{
						message->DoLogMessage(L"Failed to compress resource section!", ERR_WARNING);
						message->DoLogMessage(L"Resource section is left uncompressed...", ERR_WARNING);
						carray++;
						pe.sz_compdata_struct = sizeof(DWORD) + carray * sizeof(compdata);
						pe.compdata_struct = realloc(pe.compdata_struct, pe.sz_compdata_struct);
						((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].src = (LPVOID)(pe.m_sections[i].header.VirtualAddress);
						((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].clen = 0;
						((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData;
						((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].ulen = 0;
						((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].iscode = 0;

						DWORD aligned_size = align_(pe.m_sections[i].header.SizeOfRawData, pe.int_headers.OptionalHeader.FileAlignment);
						pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, aligned_size);
						memcpy(pe.m_sections[i].data, resources_backup, pe.m_sections[i].header.SizeOfRawData);
						memset(pe.m_sections[i].data + pe.m_sections[i].header.SizeOfRawData, 0, aligned_size - pe.m_sections[i].header.SizeOfRawData);
						diff += pe.m_sections[i].header.SizeOfRawData - aligned_size;
						pe.m_sections[i].header.SizeOfRawData = aligned_size;
						free(resources_backup);
						if (pe.m_sections[i].cdata)free(pe.m_sections[i].cdata);
						free(pe.new_resource_section);
						continue;
					}
				}
				catch (...) {
					message->DoLogMessage(L"Failed to compress resource section!", ERR_ERROR);
					message->DoLogMessage(L"File packed unsuccessfully!", ERR_ERROR);
					free(resources_backup);
					return 0;
				}

				carray++;
				pe.sz_compdata_struct = sizeof(DWORD) + carray * sizeof(compdata);
				pe.compdata_struct = realloc(pe.compdata_struct, pe.sz_compdata_struct);

				((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].src = (LPVOID)(pe.m_sections[i].header.VirtualAddress);
				((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].clen = pe.m_sections[i].csize;
				((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData;
				((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].ulen = baseresc;
				((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].iscode = 0;
				pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, pe.m_sections[i].csize + baseresc);
				pe.resourcedir_address = (DWORD)pe.m_sections[i].data;
				memcpy((LPVOID)((DWORD)pe.m_sections[i].data), pe.new_resource_section, baseresc);
				free(pe.new_resource_section);
				memcpy((LPVOID)((DWORD)pe.m_sections[i].data + baseresc), pe.m_sections[i].cdata, pe.m_sections[i].csize);
				DWORD aligned_size = align_(pe.m_sections[i].csize + baseresc, pe.int_headers.OptionalHeader.FileAlignment);
				pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, aligned_size);
				memset(pe.m_sections[i].data + pe.m_sections[i].csize + baseresc, 0, aligned_size - pe.m_sections[i].csize - baseresc);


				pe.m_sections[i].csize = aligned_size;
				diff += pe.m_sections[i].header.SizeOfRawData - pe.m_sections[i].csize;
				pe.m_sections[i].header.SizeOfRawData = pe.m_sections[i].csize;
				free(pe.m_sections[i].cdata);
				free(resources_backup);
			}
			else
			{

				bool iscode = false;
				if (codeStart >= pe.m_sections[i].header.VirtualAddress && codeStart < pe.m_sections[i].header.VirtualAddress + pe.m_sections[i].header.SizeOfRawData) iscode = true;
				if (iscode) {
					message->DoLogMessage(L"Compressing code section", ERR_INFO);
					x86_codefilter_(pe.m_sections[i].data, pe.m_sections[i].header.SizeOfRawData);


					try {

						pe.m_sections[i].cdata = compress_data(pe.m_sections[i].data, pe.m_sections[i].header.SizeOfRawData, &pe.m_sections[i].csize);
						if (!pe.m_sections[i].cdata)
						{
							message->DoLogMessage(L"Failed to compress code section!", ERR_ERROR);
							message->DoLogMessage(L"File packed unsuccessfully!", ERR_ERROR);
							return 0;
						}
					}
					catch (...) {
						message->DoLogMessage(L"Failed to compress code section!", ERR_ERROR);
						message->DoLogMessage(L"File packed unsuccessfully!", ERR_ERROR);
						return 0;
					}


					carray++;
					pe.sz_compdata_struct = sizeof(DWORD) + carray * sizeof(compdata);
					pe.compdata_struct = realloc(pe.compdata_struct, pe.sz_compdata_struct);
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].src = (LPVOID)(pe.m_sections[i].header.VirtualAddress);
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].clen = pe.m_sections[i].csize;
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData;
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].ulen = 0;
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].iscode = 1;
					wsprintf(data, L"Data compressed to 0x%04X bytes...", pe.m_sections[i].csize);
					message->DoLogMessage(data, ERR_INFO);


					pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, pe.m_sections[i].csize);
					memcpy(pe.m_sections[i].data, pe.m_sections[i].cdata, pe.m_sections[i].csize);
					DWORD aligned_size = align_(pe.m_sections[i].csize, pe.int_headers.OptionalHeader.FileAlignment);
					pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, aligned_size);
					memset(pe.m_sections[i].data + pe.m_sections[i].csize, 0, aligned_size - pe.m_sections[i].csize);


					pe.m_sections[i].csize = aligned_size;
					diff += pe.m_sections[i].header.SizeOfRawData - pe.m_sections[i].csize;
					pe.m_sections[i].header.SizeOfRawData = pe.m_sections[i].csize;
					free(pe.m_sections[i].cdata);
				}
				else
				{
					wsprintf(data, L"Compressing %s section at 0x%04X.........", pe.m_sections[i].header.Name, pe.m_sections[i].header.VirtualAddress);
					message->DoLogMessage(data, ERR_INFO);
					wsprintf(data, L"%s section is 0x%04X bytes.........", pe.m_sections[i].header.Name, pe.m_sections[i].header.SizeOfRawData);
					message->DoLogMessage(data, ERR_INFO);


					//freepascal hack
					if (strcmp(".CRT", (const char*)pe.m_sections[i].header.Name) == 0 && ((pe.m_sections[i].header.Characteristics
						&IMAGE_SCN_MEM_DISCARDABLE) == IMAGE_SCN_MEM_DISCARDABLE))
					{
						pe.m_sections[i].header.Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
					}

					try {
						pe.m_sections[i].cdata = compress_data(pe.m_sections[i].data, pe.m_sections[i].header.SizeOfRawData, &pe.m_sections[i].csize);
						if (!pe.m_sections[i].cdata)
						{
							wsprintf(data, L"Failed to pack %s section!", pe.m_sections[i].header.Name);
							message->DoLogMessage(data, ERR_ERROR);
							message->DoLogMessage(L"File packed unsuccessfully!", ERR_ERROR);
							return 0;
						}
					}
					catch (...) {
						wsprintf(data, L"Failed to pack %s section!", pe.m_sections[i].header.Name);
						message->DoLogMessage(data, ERR_ERROR);
						message->DoLogMessage(L"File packed unsuccessfully!", ERR_ERROR);
						return 0;
					}
					carray++;
					pe.sz_compdata_struct = sizeof(DWORD) + carray * sizeof(compdata);
					pe.compdata_struct = realloc(pe.compdata_struct, pe.sz_compdata_struct);
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].src = (LPVOID)(pe.m_sections[i].header.VirtualAddress);
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].clen = pe.m_sections[i].csize;
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData;
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].ulen = 0;
					((compdata*)((DWORD)pe.compdata_struct + sizeof(DWORD)))[carray - 1].iscode = 0;
					wsprintf(data, L"Data compressed to 0x%04X bytes...", pe.m_sections[i].csize);
					message->DoLogMessage(data, ERR_INFO);


					pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, pe.m_sections[i].csize);
					memcpy(pe.m_sections[i].data, pe.m_sections[i].cdata, pe.m_sections[i].csize);
					DWORD aligned_size = align_(pe.m_sections[i].csize, pe.int_headers.OptionalHeader.FileAlignment);
					pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, aligned_size);
					memset(pe.m_sections[i].data + pe.m_sections[i].csize, 0, aligned_size - pe.m_sections[i].csize);

					pe.m_sections[i].csize = aligned_size;
					diff += pe.m_sections[i].header.SizeOfRawData - pe.m_sections[i].csize;
					pe.m_sections[i].header.SizeOfRawData = pe.m_sections[i].csize;
					free(pe.m_sections[i].cdata);
				}

			}

		}
	}
	*((DWORD*)pe.compdata_struct) = carray;
	compress_functions(&pe);

	if (!pe_write(outfile, &pe))
	{
		message->DoLogMessage(L"File packed unsuccessfully!", ERR_ERROR);
		return 1;
	}
	message->DoLogMessage(L"File packed successfully!", ERR_SUCCESS);
	return 0;
}
