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

extern PE pe;

DWORD rvatoffset(DWORD Address, PE* pe) //We need this function for several compressed executables
{
	int i;
	for (i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
	{
		if (pe->m_sections[i].header.SizeOfRawData && Address &&
			Address >= pe->m_sections[i].header.VirtualAddress &&
			Address <= pe->m_sections[i].header.VirtualAddress + pe->m_sections[i].header.SizeOfRawData)
			break;
	}
	return ((DWORD)pe->m_sections[i].data + Address - pe->m_sections[i].header.VirtualAddress);
}

void AddSection(const char* sname, LPVOID _section, DWORD _section_size, DWORD _entry_point_offset, PE *pe)
{
	DWORD idx = pe->int_headers.FileHeader.NumberOfSections;
	DWORD dwSectionSize = _section_size;
	pe->int_headers.FileHeader.NumberOfSections++;
	pe->m_sections = (isections*)realloc(pe->m_sections, pe->int_headers.FileHeader.NumberOfSections * sizeof(isections));
	memset(&pe->m_sections[idx], 0x00, sizeof(isections));
	pe->m_sections[idx].data = (BYTE*)malloc(align_(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment));
	pe->m_sections[idx].header.PointerToRawData = align_(pe->m_sections[idx - 1].header.PointerToRawData + pe->m_sections[idx - 1].header.SizeOfRawData, pe->int_headers.OptionalHeader.FileAlignment);
	pe->m_sections[idx].header.VirtualAddress = align_(pe->m_sections[idx - 1].header.VirtualAddress + pe->m_sections[idx - 1].header.Misc.VirtualSize, pe->int_headers.OptionalHeader.SectionAlignment);
	pe->m_sections[idx].header.SizeOfRawData = align_(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment);
	pe->m_sections[idx].header.Misc.VirtualSize = dwSectionSize;
	pe->m_sections[idx].header.Characteristics = 0xE0000020;
	sprintf((char*)pe->m_sections[idx].header.Name, "%s", sname);
	memset(pe->m_sections[idx].data, 0x00, align_(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment));
	memcpy(pe->m_sections[idx].data, _section, _section_size);
	pe->int_headers.OptionalHeader.AddressOfEntryPoint = pe->m_sections[idx].header.VirtualAddress + _entry_point_offset;
}

int pe_read(TCHAR* filename, PE *pe)
{
	LogMessage* message = LogMessage::GetSingleton();
	message->DoLogMessage(L"Opening file...", ERR_INFO);
	FILE *hFile = _wfopen(filename, L"rb");
	if (hFile == NULL) {
		message->DoLogMessage(L"Unable to open file!", ERR_ERROR);
		return 0;
	}
	message->DoLogMessage(L"Reading DOS MZ PE header...", ERR_INFO);
	fread(&pe->m_dos.header, sizeof(IMAGE_DOS_HEADER), 1, hFile);
	if (pe->m_dos.header.e_magic != IMAGE_DOS_SIGNATURE)
	{
		message->DoLogMessage(L"Not a valid PE file!", ERR_ERROR);
		return 0;
	}

	pe->m_dos.stub_size = pe->m_dos.header.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	if (pe->m_dos.stub_size) {
		pe->m_dos.stub = (BYTE*)malloc(pe->m_dos.stub_size);
		fread(pe->m_dos.stub, pe->m_dos.stub_size, 1, hFile);
	}
	message->DoLogMessage(L"Reading PE header...", ERR_INFO);
	fread(&pe->int_headers, sizeof(IMAGE_NT_HEADERS), 1, hFile);
	if (pe->int_headers.Signature != IMAGE_NT_SIGNATURE) {
		message->DoLogMessage(L"PE signature invalid!", ERR_ERROR);
		return 0;
	}

	if (pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size == sizeof(IMAGE_COR20_HEADER))
	{
		message->DoLogMessage(L"mupack cannot compress .NET assemblies!", ERR_ERROR);
		return 0;
	}

	if (pe->int_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		message->DoLogMessage(L"This file is not a x86 Windows file!", ERR_ERROR);
		if (pe->int_headers.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			message->DoLogMessage(L"Use the x64 build of mupack to compress this file!", ERR_WARNING);
		return 0;
	}


	message->DoLogMessage(L"Reading PE sections...", ERR_INFO);
	pe->m_sections = (isections*)malloc(pe->int_headers.FileHeader.NumberOfSections * sizeof(isections));
	for (int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
		fread(&pe->m_sections[i].header, sizeof(IMAGE_SECTION_HEADER), 1, hFile);
	for (int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
	{
		if (pe->m_sections[i].header.SizeOfRawData)
		{

			fseek(hFile, pe->m_sections[i].header.PointerToRawData, SEEK_SET);
			pe->m_sections[i].data = (BYTE*)malloc(pe->m_sections[i].header.SizeOfRawData);
			fread(pe->m_sections[i].data, pe->m_sections[i].header.SizeOfRawData, 1, hFile);
		}
	}
	pe->oep = pe->int_headers.OptionalHeader.AddressOfEntryPoint + pe->int_headers.OptionalHeader.ImageBase;

	fclose(hFile);

	unsigned filesz = 0;
	unsigned char* entrypoint_data = Mud_FileAccess::load_data(filename, &filesz);
	size_t found3 = patternfind(entrypoint_data, filesz, "BB 00 00 00 00 8D 83 ?? ?? ?? ?? 53 50 8D 83 ?? ?? ?? ?? FF D0 8D 83 ?? ?? ?? ?? FF E0");
	size_t found1 = patternfind(entrypoint_data, filesz, "BB 00 00 00 00 E9 03 00 00 00 C2 0C 00 8D 83 ?? ?? ?? ?? 53 50 ?? 83 ?? ?? ?? ?? FF D0 8D 83 ?? ?? ?? ?? FF E0");
	size_t found2 = patternfind(entrypoint_data, filesz, "BB 00 00 ?? 00 EB 03 C2 0C 00 8D 83 ?? ?? ?? ?? 53 50 8D 83 ?? ?? ?? ?? FF D0 8D ?? ?? ?? ?? 00 FF E0 }");
	free(entrypoint_data);
	if (found1 != -1 || found2 != -1 || found3 != -1)
	{
		message->DoLogMessage(L"This file is packed with mupack!", ERR_ERROR);
		return 0;
	}
	return 1;
}

void fix_checksum(TCHAR* filename)
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

	hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		dwSize = GetFileSize(hFile, NULL);
		hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, NULL, NULL, "ChecksumMapping");
		pMapped = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, dwSize);
		IDH = PIMAGE_DOS_HEADER(pMapped);
		INH = PIMAGE_NT_HEADERS(LPVOID(DWORD(pMapped) + IDH->e_lfanew));
		xCheckSumMappedFile = CheckSumMappedFile(GetProcAddress(LoadLibraryA("imagehlp.dll"), "CheckSumMappedFile"));
		if (xCheckSumMappedFile(pMapped, dwSize, &dwOldChecksum, &dwNewChecksum) != NULL)
		{
			if (dwOldChecksum != dwNewChecksum)
			{
				INH->OptionalHeader.CheckSum = dwNewChecksum;
			}
		}
		UnmapViewOfFile(pMapped);
		CloseHandle(hMapping);
		CloseHandle(hFile);
	}
}

int pe_write(TCHAR* filename, PE *pe)
{
	TCHAR data[256] = { 0 };
	TCHAR dats[256] = { 0 };
	LogMessage* message = LogMessage::GetSingleton();
	FILE *hFile = _wfopen(filename, L"wb");
	if (!hFile)
		return 0;
	fwrite(&pe->m_dos.header, sizeof(IMAGE_DOS_HEADER), 1, hFile);
	pe->m_dos.stub_size = pe->m_dos.header.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	if (pe->m_dos.stub_size)
		fwrite(pe->m_dos.stub, pe->m_dos.stub_size, 1, hFile);
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = NULL;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = NULL;
	pe->int_headers.OptionalHeader.SizeOfImage = pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.VirtualAddress + pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.Misc.VirtualSize;
	fwrite(&pe->int_headers, sizeof(IMAGE_NT_HEADERS), 1, hFile);
	fseek(hFile, pe->m_dos.header.e_lfanew + sizeof(IMAGE_NT_HEADERS), SEEK_SET);
	for (int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
		fwrite(&pe->m_sections[i].header, sizeof(IMAGE_SECTION_HEADER), 1, hFile);

	for (int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++) {
		if (pe->m_sections[i].header.SizeOfRawData) {
			wsprintf(data, L"Writing %s section...", pe->m_sections[i].header.Name);
			message->DoLogMessage(data, ERR_INFO);
			fseek(hFile, pe->m_sections[i].header.PointerToRawData, SEEK_SET);
			fwrite(pe->m_sections[i].data, pe->m_sections[i].header.SizeOfRawData, 1, hFile);
		}
	}
	fclose(hFile);
	fix_checksum(filename);
	return 1;
}

void PrepareNewResourceEntry(PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntryOut, DWORD resourceBase, DWORD resourceType, DWORD level);

void PrepareNewResourceDirectory(PIMAGE_RESOURCE_DIRECTORY resDir, DWORD resourceBase, DWORD level, DWORD resourceType)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, _resDirEntry;
	UINT i;

	DWORD new_resource_section_size = pe.new_resource_section_size;
	new_resource_section_size += sizeof(IMAGE_RESOURCE_DIRECTORY);
	new_resource_section_size += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (resDir->NumberOfNamedEntries + resDir->NumberOfIdEntries);

	DWORD offset_to_names = new_resource_section_size;

	resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir + 1);

	for (i = 0; i < resDir->NumberOfNamedEntries; i++, resDirEntry++)
	{
		wchar_t * name = (wchar_t *)(resourceBase + (resDirEntry->Name & 0x7fffffff));
		new_resource_section_size += (*name + 1) * sizeof(*name);
		new_resource_section_size = (new_resource_section_size + 3) & ~3;
	}

	// reallocating it causes it to move around, so allocate it only once before entering this
	//pe.new_resource_section = ( unsigned char * ) realloc( pe.new_resource_section, new_resource_section_size );

	PIMAGE_RESOURCE_DIRECTORY _resDir = (PIMAGE_RESOURCE_DIRECTORY)(pe.new_resource_section + pe.new_resource_section_size);
	pe.new_resource_section_size = new_resource_section_size;

	memcpy(_resDir, resDir, sizeof(*resDir));

	resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir + 1);

	_resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(_resDir + 1);

	for (i = 0; i < _resDir->NumberOfNamedEntries; i++, resDirEntry++, _resDirEntry++)
	{
		wchar_t * name = (wchar_t *)(resourceBase + (resDirEntry->Name & 0x7fffffff));
		wchar_t * name_target = (wchar_t *)(pe.new_resource_section + offset_to_names);
		//	memcpy( name_target, name, ( *name + 1 ) * sizeof( *name ) );
		memcpy(name_target, name, (*name + 1) * 2);
		_resDirEntry->Name = 0x80000000 + offset_to_names;
		//offset_to_names += ( *name + 1 ) * sizeof( *name );
		offset_to_names += (*name + 1) * 2;
		DWORD offset_padded = (offset_to_names + 3) & ~3;
		memset(name_target + *name + 1, 0, offset_padded - offset_to_names);
		offset_to_names = offset_padded;
	}

	for (i = 0; i < _resDir->NumberOfIdEntries; i++, resDirEntry++, _resDirEntry++)
	{
		_resDirEntry->Name = resDirEntry->Name;
	}

	resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir + 1);

	_resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(_resDir + 1);

	for (i = 0; i < resDir->NumberOfNamedEntries; i++, resDirEntry++, _resDirEntry++)
		PrepareNewResourceEntry(resDirEntry, _resDirEntry, resourceBase, resourceType, level + 1);

	for (i = 0; i < resDir->NumberOfIdEntries; i++, resDirEntry++, _resDirEntry++)
		PrepareNewResourceEntry(resDirEntry, _resDirEntry, resourceBase, resourceType, level + 1);
}

void PrepareNewResourceEntry(PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntryOut, DWORD resourceBase, DWORD resourceType, DWORD level)
{
	UINT i;
	PIMAGE_RESOURCE_DATA_ENTRY pResDataEntry, _pResDataEntry;

	if (resDirEntry->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
	{
		resDirEntryOut->OffsetToData = 0x80000000 + pe.new_resource_section_size;
		PrepareNewResourceDirectory((PIMAGE_RESOURCE_DIRECTORY)
			((resDirEntry->OffsetToData & 0x7FFFFFFF) + resourceBase),
			resourceBase, level, level == 1 ? resDirEntry->Name : resourceType);
		return;
	}

	DWORD new_resource_section_size = pe.new_resource_section_size;
	new_resource_section_size += sizeof(IMAGE_RESOURCE_DATA_ENTRY);

	//pe.new_resource_section = ( unsigned char * ) realloc( pe.new_resource_section, new_resource_section_size );

	resDirEntryOut->OffsetToData = pe.new_resource_section_size;
	_pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(pe.new_resource_section + pe.new_resource_section_size);
	pe.new_resource_section_size = new_resource_section_size;

	pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)
		(resourceBase + resDirEntry->OffsetToData);

	_pResDataEntry->Size = pResDataEntry->Size;
	_pResDataEntry->CodePage = pResDataEntry->CodePage;
	_pResDataEntry->Reserved = pResDataEntry->Reserved;

	if (resourceType == (DWORD)RT_ICON || resourceType == (DWORD)RT_VERSION ||
		resourceType == (DWORD)RT_GROUP_ICON || resourceType == (DWORD)RT_MANIFEST)
	{
		_pResDataEntry->OffsetToData = pe.new_resource_data_size;
		pe.new_resource_data_size += (pResDataEntry->Size + 3) & ~3;
	}
	else
	{
		_pResDataEntry->OffsetToData = 0x80000000 + pe.new_resource_cdata_size;
		pe.new_resource_cdata_size += (pResDataEntry->Size + 3) & ~3;
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

	resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir + 1);
	resDirEntryOut = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDirOut + 1);

	for (i = 0; i < resDir->NumberOfNamedEntries; i++, resDirEntry++, resDirEntryOut++)
		ProcessResourceEntry(resDirEntry, resourceBase, resDirEntryOut, resourceBaseOut, resourceType, level + 1);

	for (i = 0; i < resDir->NumberOfIdEntries; i++, resDirEntry++, resDirEntryOut++)
		ProcessResourceEntry(resDirEntry, resourceBase, resDirEntryOut, resourceBaseOut, resourceType, level + 1);
}

void ProcessResourceEntry(PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, DWORD resourceBase, PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntryOut, DWORD resourceBaseOut, DWORD resourceType, DWORD level)
{
	UINT i;
	PIMAGE_RESOURCE_DATA_ENTRY pResDataEntry, _pResDataEntry;

	if (resDirEntry->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
	{
		return ProcessResourceDirectory((PIMAGE_RESOURCE_DIRECTORY)
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

	if (_pResDataEntry->OffsetToData & 0x80000000)
	{
		_pResDataEntry->OffsetToData = pe.resource_section_virtual_address
			+ pe.new_resource_section_size
			+ pe.new_resource_data_size
			+ (_pResDataEntry->OffsetToData & 0x7FFFFFFF);
	}
	else
	{
		_pResDataEntry->OffsetToData = pe.resource_section_virtual_address
			+ pe.new_resource_section_size
			+ _pResDataEntry->OffsetToData;
	}

	unsigned char * src_data = (unsigned char *)rvatoffset(pResDataEntry->OffsetToData, &pe);
	unsigned char * dest_data = (unsigned char *)(resourceBaseOut)+_pResDataEntry->OffsetToData - pe.resource_section_virtual_address;

	memcpy(dest_data, src_data, pResDataEntry->Size);

	DWORD alignment = 4 - (pResDataEntry->Size & 3);
	if (alignment & 3) memset(dest_data + pResDataEntry->Size, 0, alignment);
}
