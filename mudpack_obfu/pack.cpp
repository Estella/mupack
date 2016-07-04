#include "stdafx.h"
#include <winnt.h>
#include <stdlib.h>
#include <stdio.h>
#include <imagehlp.h>//#include <Dbghelp.h>
#include "pack.h"

#include "AsmJit/AsmJit.h"
using namespace AsmJit;

#include "junkcode.h"
#include "junkcode_emit.h"



void CryptFile(int(__cdecl *callback1) (unsigned int, unsigned int),char *filenameload)
{
	callback1(0,0);
	int compress = compress_file(filenameload);
	if (!compress)
	{
		callback1(100,0);
	}
	else
	{
		callback1(0,0);
	}
}

#define CALCULATE_ADDRESS(base, offset) (((DWORD)(base)) + (offset))

//----------------------------------------------------------------
// PE STUB IN HERE!!!!!
//----------------------------------------------------------------
#pragma optimize ("gst",off)
void restore(pointers *p, INT_PTR base_offset)
{
	IMAGE_IMPORT_DESCRIPTOR *Imports;
	IMAGE_IMPORT_BY_NAME *iNames;
	DWORD dwThunk;
	DWORD *Thunk;
	DWORD *Function;
	Imports = (IMAGE_IMPORT_DESCRIPTOR*)(p->ImageBase + p->OriginalImports);
	while(Imports->Name)
	{
		HINSTANCE Lib = (*p->GetModuleHandleA)((const char*)(Imports->Name + p->ImageBase));
		dwThunk = Imports->OriginalFirstThunk ? Imports->OriginalFirstThunk : Imports->FirstThunk;
		Thunk = (DWORD*)(dwThunk + p->ImageBase);
		dwThunk = Imports->FirstThunk;
		while(*Thunk)
		{
			
			iNames = (IMAGE_IMPORT_BY_NAME*)(*Thunk + p->ImageBase);
			if(*Thunk & IMAGE_ORDINAL_FLAG)
			{
				Function = (DWORD*)(p->ImageBase + dwThunk);
				*Function = (DWORD)((*p->GetProcAddress)(Lib, (char*)LOWORD(*Thunk)));
			}
			else
			{
				
				Function = (DWORD*)(p->ImageBase + dwThunk);
				*Function = (DWORD)((*p->GetProcAddress)(Lib, (char*)iNames->Name));
			}
			dwThunk += sizeof(DWORD);
			Thunk++;

		}
		
		Imports++;
	}
	if ( p->OriginalRelocations && p->OriginalRelocationsSize )
	{
		DWORD prelocs = p->ImageBase + p->OriginalRelocations;
		DWORD prelocs_end = prelocs + p->OriginalRelocationsSize;
	
		while ( prelocs < prelocs_end )
		{
			
			PIMAGE_BASE_RELOCATION preloc = (PIMAGE_BASE_RELOCATION) prelocs;
			DWORD dwPageAddr = p->ImageBase + preloc->VirtualAddress;
			DWORD dwBlockSize = preloc->SizeOfBlock;
			for ( DWORD i = 4; i < ( dwBlockSize >> 1 ); i++ )
			{
				DWORD dwOffset = *(WORD*)( prelocs + (i << 1) );
				DWORD dwType = ( dwOffset >> 12) & 0xf;
				DWORD dwRPtr = dwPageAddr + (dwOffset & 0xfff);
				DWORD dwRDat;
				switch (dwType)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					dwRDat = *(DWORD*)dwRPtr;
					dwRDat = dwRDat + base_offset;
					*(DWORD*)dwRPtr = dwRDat;
					break;
				case IMAGE_REL_BASED_HIGH:
					dwRDat = (*(WORD*)dwRPtr) << 16;
					dwRDat = dwRDat + base_offset;
					*(WORD*)dwRPtr = (WORD)(dwRDat >> 16);
					break;
				case IMAGE_REL_BASED_LOW:
					dwRDat = *(WORD*)dwRPtr;
					dwRDat = dwRDat + base_offset;
					*(WORD*)dwRPtr = dwRDat;
					break;
				case IMAGE_REL_BASED_HIGHADJ:
				default:
					break;
				}
			}

			prelocs += dwBlockSize;
		}
	}
}
void erestore(void){}

void mentry(pointers *p, INT_PTR base_offset)
{
		DWORD OldP= NULL;
		DWORD * fixup = (DWORD*)&p->VirtualAlloc;
		DWORD * fixup_end = (DWORD*)&p->OriginalImports;
		while (fixup < fixup_end) *fixup++ += base_offset;
		DWORD carray = *((DWORD*)p->ocompdata);
		if (!carray) return;
		*((DWORD*)p->ocompdata) = 0;
		compdata *cmpdata = (compdata*)((DWORD)p->ocompdata + sizeof(DWORD));
		JUNKCODE
		for(int i = 0; i < carray; i++)
		{
			JUNKCODE
			DWORD* ucompd = (DWORD*)(*p->VirtualAlloc)(NULL, cmpdata->nlen, MEM_COMMIT, PAGE_READWRITE);
			DWORD* workmem = (DWORD*)(*p->VirtualAlloc)(NULL, cmpdata->wlen, MEM_COMMIT, PAGE_READWRITE);
			LPVOID input_data = (LPVOID)(p->ImageBase + (DWORD)cmpdata->src + (DWORD)cmpdata->ulen);
			(*p->decomp)(ucompd,input_data,workmem);
			JUNKCODE
			(*p->VirtualFree)(workmem, 0, MEM_RELEASE);
			JUNKCODE
			(*p->VirtualProtect)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src), cmpdata->nlen , PAGE_EXECUTE_READWRITE, &OldP);
			(*p->copymem)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src + (DWORD)cmpdata->ulen), ucompd, cmpdata->nlen - cmpdata->ulen );
			JUNKCODE
			(*p->VirtualFree)(ucompd, 0, MEM_RELEASE);
			cmpdata->ulen = OldP;
			cmpdata++;
		}
		JUNKCODE
		p->restore(p, (LPVOID)base_offset);
		cmpdata = (compdata*)((DWORD)p->ocompdata + sizeof(DWORD));
		
		for(int i = 0; i < carray; i++)
		{
			
			(*p->VirtualProtect)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src), cmpdata->nlen , cmpdata->ulen, &OldP);
			cmpdata++;
			JUNKCODE
		}
}
void ementry(void){} 
#pragma optimize ("gst",on)
//-----------------------------------------------------------------
// PE ENDS HERE
//----------------------------------------------------------------

void functions(pointers *p, PE *pe)
{
	DWORD unpacker_sz = get_depackersize();
	DWORD unpacker_ptr = get_depackerptr();
	DWORD psize, sfunc[3];
	sfunc[0] = (DWORD)&ementry - (DWORD)&mentry;
	sfunc[1] = (DWORD)&erestore - (DWORD)&restore;
	sfunc[2] = (DWORD)unpacker_sz;

	psize = sfunc[0] + sfunc[1] + sfunc[2] + sizeof(pointers) + pe->scomparray + pe->sdllimports + pe->sdllexports + 12;
	LPVOID psection = malloc(psize);
	memset(psection, 0x00, psize);
	p->mentry = (tmentry)((DWORD)psection + sizeof(pointers));
	p->restore = (tmentry)((DWORD)psection + sizeof(pointers) + sfunc[0]);
	p->decomp = (tdecomp)((DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1]);
	p->ocompdata = (DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1] + sfunc[2];
	memcpy(psection, p, sizeof(pointers));
	memcpy((LPVOID)p->mentry, (LPVOID)&mentry, sfunc[0]);
	memcpy((LPVOID)p->restore, (LPVOID)&restore, sfunc[1]);
	memcpy((LPVOID)p->decomp, (LPVOID)unpacker_ptr, sfunc[2]);
	
	memcpy((LPVOID)p->ocompdata, pe->comparray, pe->scomparray);
	AddSection(".ML!", psection, psize, NULL, pe);
	construct((pointers*) pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].data, pe, sfunc);
}

struct junktable{
	uint8_t *data;
	int size;
};

junktable tables[10] = {junkcode1,614,
	                   junkcode2,674,
					   junkcode3,627,
					   junkcode4,663,
					   junkcode5,661,
					   junkcode6,699,
					   junkcode7,655,
					   junkcode8,673,
					   junkcode9,649,
					   junkcode10,641
};



int rand_lim(int limit) {
/* return a random number between 0 and limit inclusive.
 */

    int divisor = RAND_MAX/(limit+1);
    int retval;

    do { 
        retval = rand() / divisor;
    } while (retval > limit);

    return retval;
}

void junkcode_jit(Assembler* junker)
{
	if (!junker->canEmit()) return; 
	int tablenum = rand_lim(9);
	int codesize = tables[tablenum].size;
	for (int i=0;i<codesize;i++)
	{
		//junker->_emitByte(junkcode1[i]);
		junker->_emitByte(tables[tablenum].data[i]);
	}
}

void copytostub(pointers *pt,X86Assembler *assembl,DWORD *code_offset)
{

	memcpy(&pt->opcode[*code_offset],assembl->make(), assembl->getCodeSize()); 
	*code_offset += assembl->getCodeSize();
	assembl->reset();
}

void construct(pointers *pt, PE *pe, DWORD sfunc[3])
{
	DWORD vaddress = pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.VirtualAddress;
	DWORD pointer = pe->int_headers.OptionalHeader.ImageBase + vaddress;
	DWORD entry = pe->int_headers.OptionalHeader.ImageBase + vaddress + sizeof(pointers);
	X86Assembler assembl;
	FileLogger logger(stderr);
	DWORD code_offset = 0;

	logger.setLogBinary(true);
	assembl.setLogger(&logger);

	srand(GetTickCount());

	assembl.xor_(ebx,ebx);
	junkcode_jit(&assembl);
	copytostub(pt,&assembl,&code_offset);
	assembl.lea(eax,ptr(ebx,pointer));
	assembl.push(ebx);
	assembl.push(eax);
	assembl.lea(eax,ptr(ebx,entry));
	assembl.call(eax);
	junkcode_jit(&assembl);
	copytostub(pt,&assembl,&code_offset);
	assembl.lea(eax,ptr(ebx,pe->EntryPoint));
	assembl.jmp(eax);
	copytostub(pt,&assembl,&code_offset);


	pt->mentry = (tmentry)entry;
	pt->restore = (trestore)(entry + sfunc[0]);
	pt->decomp = (tdecomp)(entry + sfunc[0] + sfunc[1]);
	pt->ocompdata = entry + sfunc[0] + sfunc[1] + sfunc[2];

	DWORD pimports = (DWORD)pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].data + sizeof(pointers) + sfunc[0] + sfunc[1] + sfunc[2] + pe->scomparray;
	DWORD pimportsrva = entry + sfunc[0] + sfunc[1] + sfunc[2] + pe->scomparray - pe->int_headers.OptionalHeader.ImageBase;

	char **_dlls = pe->dlls;
	char **_thunks = pe->thunks;
	IMAGE_IMPORT_DESCRIPTOR *Imports = NULL;
	DWORD *Thunks = NULL;

	pe->sdllimports = 0;
	Imports = (IMAGE_IMPORT_DESCRIPTOR*)(pimports);
	while(*(*_dlls))
	{
		pe->sdllimports += sizeof(IMAGE_IMPORT_DESCRIPTOR); //imports
		_dlls++;
	}
	pe->sdllimports += sizeof(IMAGE_IMPORT_DESCRIPTOR); //zero import

	_dlls = pe->dlls;
	Thunks = (DWORD*)(pimports + pe->sdllimports);

	DWORD internals_count = 6;
	DWORD *internals = (DWORD*)(&pt->VirtualAlloc);

	while(*(*_dlls))
	{
		Imports->FirstThunk = pimportsrva + pe->sdllimports;
		while(*(*_thunks))
		{
			if (internals_count)
			{
				*internals = pe->int_headers.OptionalHeader.ImageBase + pimportsrva + pe->sdllimports;
				internals++;
				internals_count--;
			}
			pe->sdllimports += sizeof(DWORD); //thunks
			_thunks++;
		}
		pe->sdllimports += sizeof(DWORD); //zero thunk
		_thunks++;
		_dlls++;
		Imports++;
	}

	_dlls = pe->dlls;
	_thunks = pe->thunks;
	Imports = (IMAGE_IMPORT_DESCRIPTOR*)(pimports);
	while(*(*_dlls))
	{
		Imports->Name = pimportsrva + pe->sdllimports;
		strcpy((char*)(pimports + pe->sdllimports), *_dlls);
		pe->sdllimports +=  strlen((char*)*_dlls);//import names
		while(*(*_thunks))
		{
			if ( *(*_thunks) == '@' )
			{
				char * end;
				*Thunks = strtoul( (*_thunks) + 1, &end, 10 ) + IMAGE_ORDINAL_FLAG;
			}
			else
			{
				*Thunks = pimportsrva + pe->sdllimports;
				memset( (char*)(pimports + pe->sdllimports), 0, sizeof(WORD) );
				pe->sdllimports += sizeof(WORD); //thunk hints
				strcpy((char*)(pimports + pe->sdllimports), *_thunks);
				pe->sdllimports +=  strlen((char*)*_thunks);//import names
			}
			_thunks++;
			Thunks++;
		}
		pe->sdllimports++;
		_thunks++;
		_dlls++;
		Imports++;
		Thunks++;
	}
	pt->OriginalImports = pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	pt->OriginalRelocations = pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	pt->OriginalRelocationsSize = pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pimportsrva;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = pe->sdllimports;

	DWORD pexports = pimports + pe->sdllimports;
	DWORD pexportsrva = pimportsrva + pe->sdllimports;

	DWORD prelocs = pexports + pe->sdllexports;
	DWORD prelocsrva = pexportsrva + pe->sdllexports;

	if (pe->sdllexports)
	{
		PIMAGE_EXPORT_DIRECTORY _dir = (PIMAGE_EXPORT_DIRECTORY) pe->new_exports;

		_dir->Name += pexportsrva;
		_dir->AddressOfFunctions += pexportsrva;
		_dir->AddressOfNameOrdinals += pexportsrva;

		DWORD * address = (DWORD *) ( (DWORD)pe->new_exports + _dir->AddressOfNames );

		for ( int i = 0; i < _dir->NumberOfNames; i++ )
		{
			*address += pexportsrva;
			address++;
		}

		_dir->AddressOfNames += pexportsrva;

		memcpy( (VOID*)pexports, _dir, pe->sdllexports );

		pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = pexportsrva;
	}

	if ( pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size )
	{
		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION) prelocs;
		reloc->VirtualAddress = vaddress + 1;
		reloc->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD);

		WORD * reloc_item = (WORD*)(reloc+1);
		*reloc_item = IMAGE_REL_BASED_HIGHLOW << 12;

		pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = prelocsrva;
		pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD);
	}

	pt->ImageBase = pe->int_headers.OptionalHeader.ImageBase;
}


