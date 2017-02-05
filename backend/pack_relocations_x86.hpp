#include <windows.h>

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

