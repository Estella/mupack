
#pragma once


#define align_(_size, _base_size) \
	(((_size + _base_size - 1) / _base_size) * _base_size)
#define addr(address) \
	((DWORD)pe.m_sections[i].data + (address - pe.m_sections[i].header.VirtualAddress))
#define arrayof(x)		(sizeof(x)/sizeof(x[0]))

typedef int(_stdcall *tdefilt) (PVOID, DWORD);
typedef void(_stdcall *tmentry)(LPVOID, LPVOID);
typedef void(_stdcall *trestore)(LPVOID, LPVOID);
typedef void(_stdcall *ttlscallback)(PVOID, DWORD, DWORD);
typedef WINBASEAPI PVOID(WINAPI **tVirtualAlloc)(PVOID, DWORD, DWORD, DWORD);
typedef WINBASEAPI PVOID(WINAPI **tRtlMoveMemory)(PVOID, PVOID, DWORD);
typedef WINBASEAPI BOOL(WINAPI **tVirtualFree)(PVOID, DWORD, DWORD);
typedef WINBASEAPI BOOL(WINAPI **tVirtualProtect)(PVOID, DWORD, DWORD, PDWORD);
typedef WINBASEAPI FARPROC(WINAPI **tGetProcAddress)(HINSTANCE, LPCSTR);
typedef WINBASEAPI HINSTANCE(WINAPI **tGetModuleHandleA)(LPCSTR);
typedef WINBASEAPI HMODULE(WINAPI **tGetModuleHandle)(LPCSTR);




#pragma pack(push, 1)

typedef struct dos_section
{
	IMAGE_DOS_HEADER header;
	DWORD stub_size;
	BYTE *stub;
};

typedef struct isections
{
	IMAGE_SECTION_HEADER header;
	BYTE *data;
	DWORD csize;
	BYTE *cdata;
};

typedef struct compdata
{
	LPVOID src;
	DWORD clen;
	DWORD nlen;
	DWORD ulen;
	DWORD iscode;
};

typedef struct PE
{
	DWORD oep;
	dos_section m_dos;
	LPVOID compdata_struct;
	DWORD sz_compdata_struct;
	char **dlls;
	char **thunks;
	DWORD sz_dllimports;
	DWORD sz_dllexports;
	DWORD resourcedir_address;
	IMAGE_NT_HEADERS int_headers;
	isections *m_sections;
	unsigned char *new_resource_section;
	unsigned char *new_exports;
	DWORD new_resource_section_size;
	DWORD new_resource_data_size;
	DWORD new_resource_cdata_size;
	DWORD resource_section_virtual_address;
	PIMAGE_TLS_DIRECTORY32 ptr_tlsdir;
	DWORD tls_callbacksnum;
};
#pragma pack(pop)

#ifndef DEMO
extern "C" unsigned char* compress_lzma(unsigned char *in_data, DWORD in_size, DWORD *out_size);
extern void functions_lzma(PE *pe);
#endif
extern "C" unsigned char* compress_fr(unsigned char* in_data, DWORD in_size, DWORD* out_size);
extern void functions_fr(PE *pe);

typedef unsigned char* (*compress_data_)(unsigned char *in_data, DWORD in_size, DWORD *out_size);
typedef void(*compress_functions_)(PE *pe);




int compress_file(TCHAR* argv);
int pe_read(TCHAR* filename, PE *pe);
int pe_write(TCHAR* filename, PE *pe);
void AddSection(const char* sname, LPVOID _section, DWORD _section_size, DWORD _entry_point_offset, PE *pe);
BYTE * comp(BYTE* input, int in_size, int * out_size);
DWORD rvatoffset(DWORD Address, PE* pe);
void ProcessResourceDirectory(PIMAGE_RESOURCE_DIRECTORY resDir,
	DWORD resourceBase,
	PIMAGE_RESOURCE_DIRECTORY resDirOut,
	DWORD resourceBaseOut,
	DWORD level,
	DWORD resourceType);

void PrepareNewResourceDirectory(PIMAGE_RESOURCE_DIRECTORY resDir, DWORD resourceBase, DWORD level, DWORD resourceType);

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif
// private type definitions needed for header compilation
typedef struct _RVA_ITEM RVA_ITEM, *PRVA_ITEM;
struct _RVA_ITEM
{
	PRVA_ITEM pLink;
	DWORD dwRva;
};

class CRelocBuilder
{
public:

	CRelocBuilder()
	{
		m_pRvaList = NULL;
	}
	~CRelocBuilder()
	{
		DeleteRvaList();
	}

	// interface functions
	VOID  AddRelocation(DWORD dwRva)
	{
		PRVA_ITEM pNewRva;

		pNewRva = CreateRva(dwRva);
		if (pNewRva)
			pNewRva->dwRva = dwRva;
	}
	DWORD GetSize()
	{
		DWORD     dwCurrentBase,
			dwRvaBase,
			dwSize;
		PRVA_ITEM pCurrentRva;

		dwSize = 0;
		{
			// this basically mirrors the logic of the export function
			dwCurrentBase = -1;
			pCurrentRva = m_pRvaList;
			while (pCurrentRva)
			{
				dwRvaBase = pCurrentRva->dwRva & 0xFFFFF000;
				if (dwRvaBase != dwCurrentBase)
				{
					dwCurrentBase = dwRvaBase;
					dwSize += IMAGE_SIZEOF_BASE_RELOCATION;
				}
				dwSize += sizeof(WORD);
				pCurrentRva = pCurrentRva->pLink;
			}
			dwSize += IMAGE_SIZEOF_BASE_RELOCATION;
		}
		return dwSize;
	}
	VOID  Export(PVOID pvOutput)
	{
		DWORD                  dwCurrentBase,
			dwRvaBase;
		PRVA_ITEM              pCurrentRva;
		PIMAGE_BASE_RELOCATION pRelocHeader;
		PWORD                  pRelocs;

		if (pvOutput)
		{
			pRelocHeader = (PIMAGE_BASE_RELOCATION)pvOutput;
			pRelocs = (PWORD)pvOutput;
			dwCurrentBase = -1;
			pCurrentRva = m_pRvaList;
			while (pCurrentRva)
			{
				// create a new table if needed
				dwRvaBase = pCurrentRva->dwRva & 0xFFFFF000;
				if (dwRvaBase != dwCurrentBase)
				{
					dwCurrentBase = dwRvaBase;
					pRelocHeader->SizeOfBlock = DWORD((PBYTE)pRelocs - (PBYTE)pRelocHeader);
					pRelocHeader = (PIMAGE_BASE_RELOCATION)pRelocs;
					pRelocHeader->VirtualAddress = dwCurrentBase;
					pRelocs = PWORD((PBYTE)pRelocHeader + IMAGE_SIZEOF_BASE_RELOCATION);
				}
				*pRelocs = WORD((IMAGE_REL_BASED_HIGHLOW << 12) | (pCurrentRva->dwRva & 0xFFF));
				pRelocs++;
				pCurrentRva = pCurrentRva->pLink;
			}
			pRelocHeader->SizeOfBlock = DWORD((PBYTE)pRelocs - (PBYTE)pRelocHeader);
			pRelocHeader = (PIMAGE_BASE_RELOCATION)pRelocs;

			// output terminating header
			pRelocHeader->VirtualAddress = 0;
			pRelocHeader->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION);
		}
	}

	// private functions
	PRVA_ITEM CreateRva(DWORD dwRva)
	{
		PRVA_ITEM   pNewRva,
			*pPrevLink,
			pRva;

		pRva = m_pRvaList;
		pPrevLink = &m_pRvaList;
		while (pRva)
		{
			if (pRva->dwRva == dwRva)
				return NULL;
			else if (pRva->dwRva > dwRva)
				break;

			pPrevLink = &pRva->pLink;
			pRva = pRva->pLink;
		}
		pNewRva = (PRVA_ITEM)malloc(sizeof(RVA_ITEM));
		pNewRva->pLink = pRva;
		*pPrevLink = pNewRva;
		return pNewRva;
	}
	VOID DeleteRvaList()
	{
		PRVA_ITEM pCurrentRva,
			pNextRva;

		pCurrentRva = m_pRvaList;
		while (pCurrentRva)
		{
			pNextRva = pCurrentRva->pLink;
			free(pCurrentRva);
			pCurrentRva = pNextRva;
		}
		m_pRvaList = NULL;
	}
	// member variables
	PIMAGE_BASE_RELOCATION m_pReloc;
	PRVA_ITEM              m_pRvaList;
};
