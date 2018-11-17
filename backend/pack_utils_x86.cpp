#include "../stdafx.h"
#include <winnt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <imagehlp.h>//#include <Dbghelp.h>
#include "pack_x86.h"
#include "patternfind.h"
#include "../logger.h"
#include "Types.h"
#include "fr_pack/frpacker.hpp"
PE pe;
//Internal dll calls
const char *dlls [] = {"kernel32.dll"};
const char *thunks [] = {"VirtualAlloc", "VirtualFree", "VirtualProtect", "GetProcAddress", "GetModuleHandleA", ""};


DWORD rvatoffset(DWORD Address);
DWORD VAToFile(DWORD dwVirtAddr);
DWORD rvatoffset2(DWORD dwVirtAddr);


#define Test86MSByte(b) ((b) == 0 || (b) == 0xFF)
SizeT x86_Convert(Byte *data, SizeT size)
{
	UInt32 state = 0;
	UInt32 ip = 0;
	int encoding = 1;
	const Byte kMaskToAllowedStatus[8] = { 1, 1, 1, 0, 1, 0, 0, 0 };
	const Byte kMaskToBitNumber[8] = { 0, 1, 2, 2, 3, 3, 3, 3 };
	SizeT bufferPos = 0, prevPosT;
	UInt32 prevMask = state & 0x7;
	if (size < 5)
		return 0;
	ip += 5;
	prevPosT = (SizeT)0 - 1;

	for (;;)
	{
		Byte *p = data + bufferPos;
		Byte *limit = data + size - 4;
		for (; p < limit; p++)
			if ((*p & 0xFE) == 0xE8)
				break;
		bufferPos = (SizeT)(p - data);
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
				Byte b = p[4 - kMaskToBitNumber[prevMask]];
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
			UInt32 src = ((UInt32)p[4] << 24) | ((UInt32)p[3] << 16) | ((UInt32)p[2] << 8) | ((UInt32)p[1]);
			UInt32 dest;
			for (;;)
			{
				Byte b;
				int index;
				if (encoding)
					dest = (ip + (UInt32)bufferPos) + src;
				else
					dest = src - (ip + (UInt32)bufferPos);
				if (prevMask == 0)
					break;
				index = kMaskToBitNumber[prevMask] * 8;
				b = (Byte)(dest >> (24 - index));
				if (!Test86MSByte(b))
					break;
				src = dest ^ ((1 << (32 - index)) - 1);
			}
			p[4] = (Byte)(~(((dest >> 24) & 1) - 1));
			p[3] = (Byte)(dest >> 16);
			p[2] = (Byte)(dest >> 8);
			p[1] = (Byte)dest;
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
	strcpy(dest,src);
	return strlen(dest);
}

void AddSection(const char* sname, LPVOID _section, DWORD _section_size, DWORD _entry_point_offset, PE *pe)
{
	DWORD idx = pe->int_headers.FileHeader.NumberOfSections;
	DWORD dwSectionSize = _section_size;
	pe->int_headers.FileHeader.NumberOfSections++;
	pe->m_sections = (isections*) realloc(pe->m_sections, pe->int_headers.FileHeader.NumberOfSections * sizeof(isections));
	memset(&pe->m_sections[idx], 0x00, sizeof(isections));
	pe->m_sections[idx].data = (BYTE*) malloc(align_(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment));
	pe->m_sections[idx].header.PointerToRawData = align_(pe->m_sections[idx - 1].header.PointerToRawData + pe->m_sections[idx - 1].header.SizeOfRawData, pe->int_headers.OptionalHeader.FileAlignment);
	pe->m_sections[idx].header.VirtualAddress = align_(pe->m_sections[idx - 1].header.VirtualAddress + pe->m_sections[idx - 1].header.Misc.VirtualSize, pe->int_headers.OptionalHeader.SectionAlignment);
	pe->m_sections[idx].header.SizeOfRawData = align_(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment);
	pe->m_sections[idx].header.Misc.VirtualSize = dwSectionSize;
	pe->m_sections[idx].header.Characteristics  = 0xE0000020;
	sprintf((char*) pe->m_sections[idx].header.Name, "%s", sname);
	memset(pe->m_sections[idx].data, 0x00, align_(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment));
	memcpy(pe->m_sections[idx].data, _section, _section_size);
	pe->int_headers.OptionalHeader.AddressOfEntryPoint = pe->m_sections[idx].header.VirtualAddress + _entry_point_offset;
}

int pe_read(const char* filename, PE *pe)
{
	LogMessage* message = LogMessage::GetSingleton();
	message->DoLogMessage("Opening file...", ERR_INFO);
	FILE *hFile = fopen(filename, "rb");
	if(hFile == NULL){
		message->DoLogMessage("Unable to open file!", ERR_ERROR);
		return 0;
	}
	message->DoLogMessage("Reading DOS MZ PE header...", ERR_INFO);
	fread(&pe->m_dos.header, sizeof(IMAGE_DOS_HEADER), 1, hFile);
	if(pe->m_dos.header.e_magic != IMAGE_DOS_SIGNATURE)
	{
		message->DoLogMessage("Not a valid PE file!", ERR_ERROR);
		return 0;
	}

	pe->m_dos.stub_size = pe->m_dos.header.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	if(pe->m_dos.stub_size){
		pe->m_dos.stub = (BYTE*) malloc(pe->m_dos.stub_size);
		fread(pe->m_dos.stub, pe->m_dos.stub_size, 1, hFile);
	}
	message->DoLogMessage("Reading PE header...", ERR_INFO);
	fread(&pe->int_headers, sizeof(IMAGE_NT_HEADERS), 1, hFile);
	if(pe->int_headers.Signature != IMAGE_NT_SIGNATURE){
		message->DoLogMessage("PE signature invalid!", ERR_ERROR);
		return 0;
	}

	if(pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size == sizeof(IMAGE_COR20_HEADER))
	{
		message->DoLogMessage("mupack cannot compress .NET assemblies!", ERR_ERROR);
		return 0;
	}

	if (pe->int_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		message->DoLogMessage("This file is not a x86 Windows file!", ERR_ERROR);
		if(pe->int_headers.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		message->DoLogMessage("Use the x64 build of mupack to compress this file!", ERR_WARNING);
		return 0;
	}
	

	message->DoLogMessage("Reading PE sections...", ERR_INFO);
	pe->m_sections = (isections*) malloc(pe->int_headers.FileHeader.NumberOfSections * sizeof(isections));
	for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
		fread(&pe->m_sections[i].header, sizeof(IMAGE_SECTION_HEADER), 1, hFile);
	for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
	{
		if(pe->m_sections[i].header.SizeOfRawData)
		{
			
			fseek(hFile, pe->m_sections[i].header.PointerToRawData, SEEK_SET);
			pe->m_sections[i].data = (BYTE*) malloc(pe->m_sections[i].header.SizeOfRawData);
			fread(pe->m_sections[i].data, pe->m_sections[i].header.SizeOfRawData, 1, hFile);
		}
	}
	pe->EntryPoint = pe->int_headers.OptionalHeader.AddressOfEntryPoint + pe->int_headers.OptionalHeader.ImageBase;
	
	rewind(hFile);
	unsigned char entrypoint_data[0x100] = {0};
	fseek(hFile, rvatoffset2(pe->int_headers.OptionalHeader.AddressOfEntryPoint), SEEK_SET);
	fread(entrypoint_data, sizeof(entrypoint_data), 1, hFile);

	size_t found3 = patternfind(entrypoint_data, sizeof(entrypoint_data), "BB 00 00 00 00 8D 83 ?? ?? ?? ?? 53 50 8D 83 ?? ?? ?? ?? FF D0 8D 83 ?? ?? ?? ?? FF E0");
	size_t found1 = patternfind(entrypoint_data, sizeof(entrypoint_data), "BB 00 00 00 00 E9 03 00 00 00 C2 0C 00 8D 83 ?? ?? ?? ?? 53 50 ?? 83 ?? ?? ?? ?? FF D0 8D 83 ?? ?? ?? ?? FF E0");
	size_t found2 = patternfind(entrypoint_data, sizeof(entrypoint_data), "BB 00 00 ?? 00 EB 03 C2 0C 00 8D 83 ?? ?? ?? ?? 53 50 8D 83 ?? ?? ?? ?? FF D0 8D ?? ?? ?? ?? 00 FF E0 }");
	if (found1 != -1)
	{
		message->DoLogMessage("This file is packed with mupack!", ERR_ERROR);
		return 0;
	}
	if (found2 != -1)
	{
		message->DoLogMessage("This file is packed with mupack!", ERR_ERROR);
		return 0;
	}
	if (found3 != -1)
	{
		message->DoLogMessage("This file is packed with mupack!", ERR_ERROR);
		return 0;
	}
	fclose(hFile);

	return 1;
}

void fix_checksum(const char* filename)
{
	typedef PIMAGE_NT_HEADERS(WINAPI * CheckSumMappedFile)(PVOID BaseAddress, DWORD FileLength, PDWORD HeaderSum, PDWORD CheckSum);
	HANDLE hFile;
	HANDLE hMapping;
	LPVOID pMapped;
	DWORD dwSize;
	DWORD dwOldChecksum = 0;
	DWORD dwNewChecksum = 0;
	CheckSumMappedFile xCheckSumMappedFile;
	PIMAGE_DOS_HEADER IDH;
	PIMAGE_NT_HEADERS INH;

	hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		dwSize = GetFileSize(hFile, NULL);
		if (dwSize)
		{
			hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, NULL, NULL, "ChecksumMapping");
			if (hMapping)
			{
				pMapped = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, dwSize);
				if (pMapped)
				{
					IDH = PIMAGE_DOS_HEADER(pMapped);
					if (IDH->e_magic == IMAGE_DOS_SIGNATURE)
					{
						INH = PIMAGE_NT_HEADERS(LPVOID(DWORD(pMapped) + IDH->e_lfanew));
						if (INH->Signature == IMAGE_NT_SIGNATURE)
						{
							xCheckSumMappedFile = CheckSumMappedFile(GetProcAddress(LoadLibraryA("imagehlp.dll"), "CheckSumMappedFile"));
							if (xCheckSumMappedFile(pMapped, dwSize, &dwOldChecksum, &dwNewChecksum) != NULL)
							{
								if (dwOldChecksum != dwNewChecksum)
								{
									INH->OptionalHeader.CheckSum = dwNewChecksum;
								}
							}

						}

					}

					UnmapViewOfFile(pMapped);
				}
				CloseHandle(hMapping);
			}

		}

		CloseHandle(hFile);
	}
}

int pe_write(const char* filename, PE *pe)
{
	TCHAR data[256] = { 0 };
	TCHAR dats[256] = { 0 };
	LogMessage* message = LogMessage::GetSingleton();
	FILE *hFile = fopen(filename, "wb");
	if(!hFile)
		return 0;
	fwrite(&pe->m_dos.header, sizeof(IMAGE_DOS_HEADER), 1, hFile);
	pe->m_dos.stub_size = pe->m_dos.header.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	if(pe->m_dos.stub_size)
    fwrite(pe->m_dos.stub, pe->m_dos.stub_size, 1, hFile);
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = NULL;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = NULL;
	pe->int_headers.OptionalHeader.SizeOfImage = pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.VirtualAddress + pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.Misc.VirtualSize;
	fwrite(&pe->int_headers, sizeof(IMAGE_NT_HEADERS), 1, hFile);
	fseek(hFile, pe->m_dos.header.e_lfanew + sizeof(IMAGE_NT_HEADERS), SEEK_SET);
	for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
	fwrite(&pe->m_sections[i].header, sizeof(IMAGE_SECTION_HEADER), 1, hFile);

	for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++){
		if(pe->m_sections[i].header.SizeOfRawData){
			sprintf(data, "Writing %s section...", pe->m_sections[i].header.Name);
			message->DoLogMessage(data, ERR_INFO);
			fseek(hFile, pe->m_sections[i].header.PointerToRawData, SEEK_SET);
			fwrite(pe->m_sections[i].data, pe->m_sections[i].header.SizeOfRawData, 1, hFile);
		}
	}
	fclose(hFile);
	fix_checksum(filename);
	return 1;
}

DWORD rvatoffset(DWORD Address);

void PrepareNewResourceEntry(PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntryOut, DWORD resourceBase, DWORD resourceType, DWORD level);

void PrepareNewResourceDirectory(PIMAGE_RESOURCE_DIRECTORY resDir, DWORD resourceBase, DWORD level, DWORD resourceType)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, _resDirEntry;
    UINT i;

	DWORD new_resource_section_size = pe.new_resource_section_size;
	new_resource_section_size += sizeof( IMAGE_RESOURCE_DIRECTORY );
	new_resource_section_size += sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY ) * ( resDir->NumberOfNamedEntries + resDir->NumberOfIdEntries );

	DWORD offset_to_names = new_resource_section_size;

    resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir+1);
    
	for ( i=0; i < resDir->NumberOfNamedEntries; i++, resDirEntry++ )
	{
		wchar_t * name = ( wchar_t * ) ( resourceBase + ( resDirEntry->Name & 0x7fffffff ) );
		new_resource_section_size += ( *name + 1 ) * sizeof( *name );
		new_resource_section_size = ( new_resource_section_size + 3 ) & ~3;
	}

	// reallocating it causes it to move around, so allocate it only once before entering this
	//pe.new_resource_section = ( unsigned char * ) realloc( pe.new_resource_section, new_resource_section_size );

	PIMAGE_RESOURCE_DIRECTORY _resDir = ( PIMAGE_RESOURCE_DIRECTORY ) ( pe.new_resource_section + pe.new_resource_section_size );
	pe.new_resource_section_size = new_resource_section_size;

	memcpy( _resDir, resDir, sizeof(*resDir) );

    resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir+1);
    
	_resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(_resDir+1);

	for ( i=0; i < _resDir->NumberOfNamedEntries; i++, resDirEntry++, _resDirEntry++ )
	{
		wchar_t * name = ( wchar_t * ) ( resourceBase + ( resDirEntry->Name & 0x7fffffff ) );
		wchar_t * name_target = ( wchar_t * ) ( pe.new_resource_section + offset_to_names );
	//	memcpy( name_target, name, ( *name + 1 ) * sizeof( *name ) );
		memcpy(name_target, name, (*name + 1) * 2);
		_resDirEntry->Name = 0x80000000 + offset_to_names;
		//offset_to_names += ( *name + 1 ) * sizeof( *name );
		offset_to_names += (*name + 1) * 2;
		DWORD offset_padded = ( offset_to_names + 3 ) & ~3;
		memset( name_target + *name + 1, 0, offset_padded - offset_to_names );
		offset_to_names = offset_padded;
	}

	for ( i=0; i < _resDir->NumberOfIdEntries; i++, resDirEntry++, _resDirEntry++ )
	{
		_resDirEntry->Name = resDirEntry->Name;
	}

    resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir+1);
    
	_resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(_resDir+1);

    for ( i=0; i < resDir->NumberOfNamedEntries; i++, resDirEntry++, _resDirEntry++ )
        PrepareNewResourceEntry(resDirEntry, _resDirEntry, resourceBase, resourceType, level+1);

    for ( i=0; i < resDir->NumberOfIdEntries; i++, resDirEntry++, _resDirEntry++ )
        PrepareNewResourceEntry(resDirEntry, _resDirEntry, resourceBase, resourceType, level+1);
}

void PrepareNewResourceEntry(PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntryOut, DWORD resourceBase, DWORD resourceType, DWORD level)
{
	UINT i;
    PIMAGE_RESOURCE_DATA_ENTRY pResDataEntry, _pResDataEntry;
    
    if ( resDirEntry->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY )
    {
		resDirEntryOut->OffsetToData = 0x80000000 + pe.new_resource_section_size;
        PrepareNewResourceDirectory( (PIMAGE_RESOURCE_DIRECTORY)
            ((resDirEntry->OffsetToData & 0x7FFFFFFF) + resourceBase),
            resourceBase, level, level == 1 ? resDirEntry->Name : resourceType);
		return;
    }

	DWORD new_resource_section_size = pe.new_resource_section_size;
	new_resource_section_size += sizeof( IMAGE_RESOURCE_DATA_ENTRY );

	//pe.new_resource_section = ( unsigned char * ) realloc( pe.new_resource_section, new_resource_section_size );

	resDirEntryOut->OffsetToData = pe.new_resource_section_size;
	_pResDataEntry = ( PIMAGE_RESOURCE_DATA_ENTRY ) ( pe.new_resource_section + pe.new_resource_section_size );
	pe.new_resource_section_size = new_resource_section_size;

	pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)
                    (resourceBase + resDirEntry->OffsetToData);

	_pResDataEntry->Size = pResDataEntry->Size;
	_pResDataEntry->CodePage = pResDataEntry->CodePage;
	_pResDataEntry->Reserved = pResDataEntry->Reserved;

	if(resourceType == (DWORD)RT_ICON||resourceType == (DWORD)RT_VERSION||
       resourceType == (DWORD)RT_GROUP_ICON|| resourceType == (DWORD)RT_MANIFEST)
	{
		_pResDataEntry->OffsetToData = pe.new_resource_data_size;
		pe.new_resource_data_size += ( pResDataEntry->Size + 3 ) & ~3;
	}
	else
	{
		_pResDataEntry->OffsetToData = 0x80000000 + pe.new_resource_cdata_size;
		pe.new_resource_cdata_size += ( pResDataEntry->Size + 3 ) & ~3;
	}
}

void ProcessResourceEntry(PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, DWORD resourceBase, PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntryOut, DWORD resourceBaseOut, DWORD resourceType, DWORD level);

void ProcessResourceDirectory(PIMAGE_RESOURCE_DIRECTORY resDir,
							   DWORD resourceBase,
							   PIMAGE_RESOURCE_DIRECTORY resDirOut,
							   DWORD resourceBaseOut,
							   DWORD level,
							   DWORD resourceType)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, resDirEntryOut;
    UINT i;

    resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir+1);
	resDirEntryOut = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDirOut+1);
    
    for ( i=0; i < resDir->NumberOfNamedEntries; i++, resDirEntry++, resDirEntryOut++ )
        ProcessResourceEntry(resDirEntry, resourceBase, resDirEntryOut, resourceBaseOut, resourceType, level+1);

    for ( i=0; i < resDir->NumberOfIdEntries; i++, resDirEntry++, resDirEntryOut++ )
        ProcessResourceEntry(resDirEntry, resourceBase, resDirEntryOut, resourceBaseOut, resourceType, level+1);
}

void ProcessResourceEntry(PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, DWORD resourceBase, PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntryOut, DWORD resourceBaseOut, DWORD resourceType, DWORD level)
{
	UINT i;
    PIMAGE_RESOURCE_DATA_ENTRY pResDataEntry, _pResDataEntry;
    
    if ( resDirEntry->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY )
    {
        return ProcessResourceDirectory( (PIMAGE_RESOURCE_DIRECTORY)
            ((resDirEntry->OffsetToData & 0x7FFFFFFF) + resourceBase),
			resourceBase,
			(PIMAGE_RESOURCE_DIRECTORY)
			((resDirEntryOut->OffsetToData & 0x7FFFFFFF) + resourceBaseOut),
            resourceBaseOut, level, level == 1 ? resDirEntry->Name : resourceType);
    }

    pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)
                    (resourceBase + resDirEntry->OffsetToData);

	_pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)
                    (resourceBaseOut + resDirEntryOut->OffsetToData);

	if ( _pResDataEntry->OffsetToData & 0x80000000 )
	{
		_pResDataEntry->OffsetToData = pe.resource_section_virtual_address
			+ pe.new_resource_section_size
			+ pe.new_resource_data_size
			+ ( _pResDataEntry->OffsetToData & 0x7FFFFFFF );
	}
	else
	{
		_pResDataEntry->OffsetToData = pe.resource_section_virtual_address
			+ pe.new_resource_section_size
			+ _pResDataEntry->OffsetToData;
	}

	unsigned char * src_data = ( unsigned char * ) rvatoffset( pResDataEntry->OffsetToData );
	unsigned char * dest_data = ( unsigned char * )( resourceBaseOut ) + _pResDataEntry->OffsetToData - pe.resource_section_virtual_address;

	memcpy( dest_data, src_data, pResDataEntry->Size );

	DWORD alignment = 4 - (pResDataEntry->Size & 3);
	if ( alignment & 3 ) memset( dest_data + pResDataEntry->Size, 0, alignment );
}


PIMAGE_TLS_DIRECTORY32 pImgTlsDir;
DWORD tls_callbacksnum = 0;
int compress_file(char* argv)
{
	LogMessage* message = LogMessage::GetSingleton();
	compress_data_ compress_data;
	compress_functions_ compress_functions;

	compress_data = &compress_lzma;
	compress_functions = &functions_lzma;

    WIN32_FILE_ATTRIBUTE_DATA  wfad;
	GetFileAttributesEx(argv, GetFileExInfoStandard, &wfad);
	int filesize = wfad.nFileSizeLow;
	ZeroMemory(&pe,sizeof(PE));
	if(!pe_read(argv, &pe))
	{
		message->DoLogMessage("File packed unsuccessfully!", ERR_ERROR);
		return 1;
	}
	char outfile[MAX_PATH] = {0};
	char ext[MAX_PATH] = {0};
	const char *dot = strrchr(argv, '.');
	if (dot) lstrcpyA(ext, dot);
	lstrcpyA(outfile, argv);
	lstrcatA(outfile, ".packed");
	lstrcatA(outfile, ext);
	

	/* Initialize internal dll calls */
	DWORD pe_dlls_count = sizeof(dlls) / 4;
	pe.dlls = (char**)malloc((pe_dlls_count + 1) * 4);
	for(int i = 0; i < pe_dlls_count; i++)
	{
		pe.dlls[i] = (char*)malloc(strlen(dlls[i]) + 1);
		strcpy(pe.dlls[i], dlls[i]);
	}
	DWORD pe_thunks_count = sizeof(thunks) / 4;
	pe.thunks = (char**)malloc(pe_thunks_count * 4);
	for(int i = 0; i < pe_thunks_count; i++)
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

	Imports = (PIMAGE_IMPORT_DESCRIPTOR) rvatoffset( pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );
	while(Imports->Name)
	{
		name = (const char *) rvatoffset( Imports->Name );
		if ( stricmp( name, "kernel32" ) && stricmp( name, "kernel32.dll" ) )
		{
			shortest_length = ~0u;
			dwThunk = Imports->OriginalFirstThunk ? Imports->OriginalFirstThunk : Imports->FirstThunk;
			Thunk = (DWORD*) rvatoffset( dwThunk );
			dwThunk = Imports->FirstThunk;
			while(*Thunk)
			{
				if(*Thunk & IMAGE_ORDINAL_FLAG)
				{
					sprintf_s( ordinal_name, "@%u", LOWORD( *Thunk ) );
					shortest_name = ordinal_name;
					shortest_length = 0;
					break;
				}
				else
				{
					iNames = (IMAGE_IMPORT_BY_NAME*) rvatoffset( *Thunk );
					size_t name_length = strlen( (const char*) iNames->Name );
					if ( name_length < shortest_length )
					{
						shortest_length = name_length;
						shortest_name = (const char *) iNames->Name;
					}
				}
				dwThunk += sizeof(DWORD);
				Thunk++;
			}

			++pe_dlls_count;
			pe.dlls = (char **) realloc( pe.dlls, ( pe_dlls_count + 1 ) * 4 );
			pe_thunks_count += 2;
			pe.thunks = (char **) realloc( pe.thunks, pe_thunks_count * 4 );

			pe.dlls[ pe_dlls_count - 1 ] = ( char * ) malloc( strlen( name ) + 1 );
			strcpy( pe.dlls[ pe_dlls_count - 1 ], name );

			pe.thunks[ pe_thunks_count - 2 ] = ( char * ) malloc( strlen( shortest_name ) + 1 );
			strcpy( pe.thunks[ pe_thunks_count - 2 ], shortest_name );
			pe.thunks[ pe_thunks_count - 1 ] = ( char * ) malloc( 1 );
			pe.thunks[ pe_thunks_count - 1 ][ 0 ] = '\0';
		}
		Imports++;
	}

	pe.dlls[ pe_dlls_count ] = ( char * ) malloc( 1 );
	pe.dlls[ pe_dlls_count ][ 0 ] = '\0';

	/* Calculate the space we need for dll calls */
	char **_dlls = pe.dlls;
	char **_thunks = pe.thunks;
	pe.sdllimports = sizeof(IMAGE_IMPORT_DESCRIPTOR); //zero import space
	while(*(*_dlls))
	{
		pe.sdllimports += sizeof(IMAGE_IMPORT_DESCRIPTOR); //import space
		pe.sdllimports += strlen(*_dlls); //import name space
		pe.sdllimports += sizeof(DWORD); //zero thunk space
		while(*(*_thunks))
		{
			if ( *(*_thunks) == '@' )
			{
				pe.sdllimports += sizeof(DWORD);
			}
			else
			{
				pe.sdllimports += sizeof(DWORD); //thunk space
				pe.sdllimports += sizeof(WORD) + strlen(*_thunks); //thunk hint + name space
			}
			_thunks++;
		}
		pe.sdllimports++;
		_thunks++;
		_dlls++;
	}

	pe.sdllexports = 0;

	if ( pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size )
	{
		pe.sdllexports = pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		pe.new_exports = ( unsigned char * ) malloc( pe.sdllexports );

		PIMAGE_EXPORT_DIRECTORY _in = (PIMAGE_EXPORT_DIRECTORY) rvatoffset( pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
		PIMAGE_EXPORT_DIRECTORY _out = (PIMAGE_EXPORT_DIRECTORY) pe.new_exports;

		memcpy( _out, _in, pe.sdllexports );

		_out->Name = rvatoffset( _in->Name ) - (DWORD)_in;
		_out->AddressOfFunctions = rvatoffset( _in->AddressOfFunctions ) - (DWORD)_in;
		_out->AddressOfNames = rvatoffset( _in->AddressOfNames ) - (DWORD)_in;
		_out->AddressOfNameOrdinals = rvatoffset( _in->AddressOfNameOrdinals ) - (DWORD)_in;

		DWORD * address = (DWORD *) ( rvatoffset( _in->AddressOfNames ) - (DWORD)_in + (DWORD)_out );

		for ( int i = 0; i < _in->NumberOfNames; i++ )
		{
			*address = rvatoffset( *address ) - (DWORD)_in;
			address++;
		}

		memset( _in, 0, pe.sdllexports );
	}

	//preserve TLS callbacks if they are there
	
	if ( pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size )
	{
		pImgTlsDir = (PIMAGE_TLS_DIRECTORY32)malloc(sizeof(IMAGE_TLS_DIRECTORY32));
		memset(pImgTlsDir, 0, sizeof(IMAGE_TLS_DIRECTORY32));
		TCHAR data[256] = { 0 };
		DWORD *tls_callbackptr = 0;
		sprintf(data, "Found TLS directory at 0x%04X...", pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		message->DoLogMessage(data, ERR_INFO);
		IMAGE_TLS_DIRECTORY32 *ptr = (IMAGE_TLS_DIRECTORY32*)rvatoffset(pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		memcpy(pImgTlsDir,ptr,sizeof(IMAGE_TLS_DIRECTORY32));
		tls_callbackptr = (DWORD*)rvatoffset(pImgTlsDir->AddressOfCallBacks - pe.int_headers.OptionalHeader.ImageBase);
		tls_callbacksnum = 0;
		while (*tls_callbackptr != 0)
		{
			tls_callbacksnum++;
			tls_callbackptr += sizeof(DWORD);
		}

	}

	if (pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size)
	{
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
	}

	if (pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size)
	{
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
	}


	if (pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size)
	{
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	}


	DWORD diff = 0; //General section offset difference
	DWORD carray = 0; //Section compression tracker



	pe.comparray = malloc(sizeof(DWORD));
	for(int i = 0; i < pe.int_headers.FileHeader.NumberOfSections; i++)
	{
		DWORD imageBase = pe.int_headers.OptionalHeader.ImageBase;
		DWORD codeStart = pe.int_headers.OptionalHeader.BaseOfCode;
		DWORD codeSize = pe.int_headers.OptionalHeader.SizeOfCode;
		TCHAR data[256] = { 0 };

		if(pe.m_sections[i].header.SizeOfRawData)
		{
			pe.m_sections[i].header.PointerToRawData -= diff;
			//Resources
			if(pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == pe.m_sections[i].header.VirtualAddress)
			{
				message->DoLogMessage("Compressing resources...", ERR_INFO);
				unsigned char* resources_backup = (unsigned char *)malloc(pe.m_sections[i].header.SizeOfRawData);
				memcpy(resources_backup, pe.m_sections[i].data, pe.m_sections[i].header.SizeOfRawData);
				PIMAGE_RESOURCE_DIRECTORY rescdir = (PIMAGE_RESOURCE_DIRECTORY)pe.m_sections[i].data, _rescdir;
				pe.rescaddress = (DWORD)pe.m_sections[i].data;
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
						message->DoLogMessage("Failed to compress resource section!", ERR_WARNING);
						message->DoLogMessage("Resource section is left uncompressed...", ERR_WARNING);
						carray++;
						pe.scomparray = sizeof(DWORD) + carray * sizeof(compdata);
						pe.comparray = realloc(pe.comparray, pe.scomparray);
						((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].src = (LPVOID)(pe.m_sections[i].header.VirtualAddress);
						((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].clen = 0;
						((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData;
						((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].ulen = 0;
						((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].iscode = 0;

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
					message->DoLogMessage("Failed to compress resource section!", ERR_ERROR);
					message->DoLogMessage("File packed unsuccessfully!", ERR_ERROR);
					free(resources_backup);
					return 0;
				}

				carray++;
				pe.scomparray = sizeof(DWORD) + carray * sizeof(compdata);
				pe.comparray = realloc(pe.comparray, pe.scomparray);

				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].src = (LPVOID)(pe.m_sections[i].header.VirtualAddress);
				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].clen = pe.m_sections[i].csize;
				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData;
				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].ulen = baseresc;
				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].iscode = 0;
				pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, pe.m_sections[i].csize + baseresc);
				pe.rescaddress = (DWORD)pe.m_sections[i].data;
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
				if (iscode){
					message->DoLogMessage("Compressing code section", ERR_INFO);
					x86_Convert(pe.m_sections[i].data, pe.m_sections[i].header.SizeOfRawData);


					try {
					
						pe.m_sections[i].cdata = compress_data(pe.m_sections[i].data, pe.m_sections[i].header.SizeOfRawData, &pe.m_sections[i].csize);
						if (!pe.m_sections[i].cdata)
						{
								message->DoLogMessage("Failed to compress code section!", ERR_ERROR);
								message->DoLogMessage("File packed unsuccessfully!", ERR_ERROR);
								return 0;
						}
					}
					catch (...) {
							message->DoLogMessage("Failed to compress code section!", ERR_ERROR);
							message->DoLogMessage("File packed unsuccessfully!", ERR_ERROR);
							return 0;
					}


					carray++;
					pe.scomparray = sizeof(DWORD) + carray * sizeof(compdata);
					pe.comparray = realloc(pe.comparray, pe.scomparray);
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].src = (LPVOID)(pe.m_sections[i].header.VirtualAddress);
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].clen = pe.m_sections[i].csize;
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData;
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].ulen = 0;
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].iscode = 1;
					sprintf(data, "Data compressed to 0x%04X bytes...", pe.m_sections[i].csize);
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
					sprintf(data, "Compressing %s section at 0x%04X.........", pe.m_sections[i].header.Name, pe.m_sections[i].header.VirtualAddress);
					message->DoLogMessage(data, ERR_INFO);
					sprintf(data, "%s section is 0x%04X bytes.........", pe.m_sections[i].header.Name, pe.m_sections[i].header.SizeOfRawData);
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
							sprintf(data, "Failed to pack %s section!", pe.m_sections[i].header.Name);
							message->DoLogMessage(data, ERR_ERROR);
							message->DoLogMessage("File packed unsuccessfully!", ERR_ERROR);
							return 0;
						}
					}
					catch (...) {
						sprintf(data, "Failed to pack %s section!", pe.m_sections[i].header.Name);
						message->DoLogMessage(data, ERR_ERROR);
						message->DoLogMessage("File packed unsuccessfully!", ERR_ERROR);
						return 0;
					}
					carray++;
					pe.scomparray = sizeof(DWORD) + carray * sizeof(compdata);
					pe.comparray = realloc(pe.comparray, pe.scomparray);
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].src = (LPVOID)(pe.m_sections[i].header.VirtualAddress);
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].clen = pe.m_sections[i].csize;
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData;
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].ulen = 0;
					((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].iscode = 0;
					sprintf(data, "Data compressed to 0x%04X bytes...", pe.m_sections[i].csize);
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
	*((DWORD*)pe.comparray) = carray;
	compress_functions(&pe);
	
	if (!pe_write(outfile, &pe))
	{
		message->DoLogMessage("File packed unsuccessfully!", ERR_ERROR);
		return 1;
	}
	message->DoLogMessage("File packed successfully!", ERR_SUCCESS);
	return 0;
}

DWORD rvatoffset2(DWORD dwVirtAddr)
{
	DWORD dwReturn = dwVirtAddr;
	for (WORD wSections = 0; wSections < pe.int_headers.FileHeader.NumberOfSections; wSections++) {
		if (dwReturn >= (pe.m_sections[wSections].header.VirtualAddress))
		{
			if (dwReturn < (pe.m_sections[wSections].header.VirtualAddress + pe.m_sections[wSections].header.SizeOfRawData))
			{
				dwReturn -= (pe.m_sections[wSections].header.VirtualAddress);
				dwReturn += (pe.m_sections[wSections].header.PointerToRawData);
				return dwReturn;
			}
		}
	}
	return NULL;
}


DWORD VAToFile(DWORD dwVirtAddr)
{
	DWORD dwReturn = dwVirtAddr;
	for (WORD wSections = 0; wSections < pe.int_headers.FileHeader.NumberOfSections; wSections++) {
		if (dwReturn >= (pe.int_headers.OptionalHeader.ImageBase + pe.m_sections[wSections].header.VirtualAddress))
		{
			if (dwReturn < (pe.int_headers.OptionalHeader.ImageBase + pe.m_sections[wSections].header.VirtualAddress + pe.m_sections[wSections].header.SizeOfRawData))
			{
				dwReturn -= (pe.int_headers.OptionalHeader.ImageBase + pe.m_sections[wSections].header.VirtualAddress);
				dwReturn += (pe.m_sections[wSections].header.PointerToRawData);
				return dwReturn;
			}
		}
	}
	return NULL;
}



DWORD rvatoffset(DWORD Address) //We need this function for several compressed executables
{
	int i;
	for(i = 0; i < pe.int_headers.FileHeader.NumberOfSections; i++)
	{
		if(pe.m_sections[i].header.SizeOfRawData && Address &&
			Address >= pe.m_sections[i].header.VirtualAddress &&
			Address <= pe.m_sections[i].header.VirtualAddress + pe.m_sections[i].header.SizeOfRawData)
			break;
	}
	return ((DWORD)pe.m_sections[i].data + Address - pe.m_sections[i].header.VirtualAddress);
}
