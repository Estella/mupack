#include "../stdafx.h"
#include <winnt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <imagehlp.h>//#include <Dbghelp.h>
#include "pack_x86.h"
#include "xbyak/xbyak.h"
#include "../logger.h"
#include "Types.h"
#include "pack_relocations_x86.hpp"
#ifndef DEMO
extern "C" DWORD _stdcall get_lzmadepackersize();
extern "C" DWORD _stdcall get_lzmadepackerptr();
#endif // !DEMO
extern "C" DWORD _stdcall get_frdepackersize();
extern "C" DWORD _stdcall get_frdepackerptr();



#define Test86MSByte(b) ((b) == 0 || (b) == 0xFF)
#define x86_Convert_Init(state) { state = 0; }

#define CALCULATE_ADDRESS(base, offset) (((DWORD)(base)) + (offset))
#define MARK_END_OF_FUNCTION(funcname) static void funcname ## _eof_marker() { }
#define SIZEOF_FUNCTION(funcname) ((unsigned long)&funcname ## _eof_marker - (unsigned long)&funcname)

#pragma pack(push, 1)
typedef struct pointers
{
	BYTE opcode[34];
	tVirtualAlloc VirtualAlloc;
	tVirtualFree VirtualFree;
	tVirtualProtect VirtualProtect;
	tGetProcAddress GetProcAddress;
	tGetModuleHandleA GetModuleHandleA;
	tmentry mentry;
	trestore restore;
	DWORD decomp;
	DWORD codefilt;
	DWORD ocompdata;
	DWORD ImageBase;
	DWORD OriginalImports;
	DWORD OriginalRelocations;
	DWORD OriginalRelocationsSize;
	DWORD TlsCallbackBackup;
	DWORD TlsCallbackNew;
	DWORD IsDepacked;
};
void construct(pointers *p, PE *pe, DWORD sfunc[3], int section_size);


//----------------------------------------------------------------
// PE STUB IN HERE!!!!!
//----------------------------------------------------------------

#pragma optimize ("gs",on)
static void restore(pointers *p, INT_PTR base_offset)
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
				DWORD HighWord;
				DWORD LowWord;
				if(dwType == IMAGE_REL_BASED_HIGHLOW)
				{
					dwRDat = *(DWORD*)dwRPtr;
					dwRDat = dwRDat + base_offset;
					*(DWORD*)dwRPtr = dwRDat;
				}
			}
			prelocs += dwBlockSize;
		}
	}
}
#pragma optimize ("",off)
MARK_END_OF_FUNCTION(restore)
#pragma optimize ("gt",on)
#ifndef DEMO
static void mentry_lzma(pointers *p, INT_PTR base_offset)
{
	if (p->IsDepacked)return;

		DWORD OldP= NULL;
		DWORD * fixup = (DWORD*)&p->VirtualAlloc;
		DWORD * fixup_end = (DWORD*)&p->OriginalImports;
		while (fixup < fixup_end) *fixup++ += base_offset;
		DWORD carray = *((DWORD*)p->ocompdata);
		*((DWORD*)p->ocompdata) = 0;
		compdata *cmpdata = (compdata*)((DWORD)p->ocompdata + sizeof(DWORD));
		for(int i = 0; i < carray; i++)
		{
			if (cmpdata->clen != 0)
			{
				DWORD nlendiff = (DWORD)cmpdata->nlen - (DWORD)cmpdata->ulen;
				DWORD* workmem = (DWORD*)(*p->VirtualAlloc)(NULL, 0xC4000, MEM_COMMIT, PAGE_READWRITE);
				(*p->VirtualProtect)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src), (DWORD)cmpdata->nlen, PAGE_READWRITE, &OldP);
				unsigned char* input_data = (unsigned char*)(p->ImageBase + (DWORD)cmpdata->src + (DWORD)cmpdata->ulen);
				unsigned char* ucompd = (unsigned char*)(*p->VirtualAlloc)(NULL, cmpdata->nlen, MEM_COMMIT, PAGE_READWRITE);
				typedef void(_stdcall *tdecomp)(UInt16* workmem,
					const unsigned char *inStream, SizeT inSize,
					unsigned char *outStream, SizeT outSize);
				tdecomp decomp = (tdecomp)p->decomp;
				decomp((UInt16*)workmem, input_data + 5, (SizeT)cmpdata->clen - 5, (unsigned char*)ucompd, (SizeT)nlendiff);
				if (cmpdata->iscode)
				{
					tdefilt defilter = (tdefilt)p->codefilt;
					defilter(ucompd, cmpdata->nlen);
				}
				while (nlendiff--) input_data[nlendiff] = ucompd[nlendiff];
				cmpdata->ulen = OldP;
				(*p->VirtualFree)(ucompd, 0, MEM_RELEASE);
				(*p->VirtualFree)(workmem, 0, MEM_RELEASE);
				
			}
			
			cmpdata++;
		}
		p->restore(p, (LPVOID)base_offset);
		cmpdata = (compdata*)((DWORD)p->ocompdata + sizeof(DWORD));
		
		for(int i = 0; i < carray; i++)
		{
			if(cmpdata->clen != 0)(*p->VirtualProtect)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src), cmpdata->nlen , cmpdata->ulen, &OldP);
			cmpdata++;	
		}
		if (p->TlsCallbackBackup != 0)
		{
			p->TlsCallbackBackup += p->ImageBase;
			p->TlsCallbackNew += p->ImageBase;
			PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK *)p->TlsCallbackBackup;
			PIMAGE_TLS_CALLBACK* callback_bckup = (PIMAGE_TLS_CALLBACK *)p->TlsCallbackNew;
			if (callback) {
				while (*callback) {
					(*callback)((LPVOID)p->ImageBase, DLL_PROCESS_ATTACH, NULL);
					*callback_bckup = *callback;
					callback_bckup++;
					callback++;
				}
			}
		}
		p->IsDepacked = 0x01;
}
#pragma optimize ("",off)
MARK_END_OF_FUNCTION(mentry_lzma)
#pragma optimize ("",on)

#endif // !DEMO
#pragma optimize ("gt",on)
static void mentry_fr(pointers *p, INT_PTR base_offset)
{
	if (p->IsDepacked)return;

	DWORD OldP = NULL;
	DWORD * fixup = (DWORD*)&p->VirtualAlloc;
	DWORD * fixup_end = (DWORD*)&p->OriginalImports;
	while (fixup < fixup_end) *fixup++ += base_offset;
	DWORD carray = *((DWORD*)p->ocompdata);
	*((DWORD*)p->ocompdata) = 0;
	compdata *cmpdata = (compdata*)((DWORD)p->ocompdata + sizeof(DWORD));
	for (int i = 0; i < carray; i++)
	{
		if (cmpdata->clen != 0)
		{
			DWORD nlendiff = (DWORD)cmpdata->nlen - (DWORD)cmpdata->ulen;
			unsigned char* input_data = (unsigned char*)(p->ImageBase + (DWORD)cmpdata->src + (DWORD)cmpdata->ulen);
			unsigned char* ucompd = (unsigned char*)(*p->VirtualAlloc)(NULL, cmpdata->nlen, MEM_COMMIT, PAGE_READWRITE);
			typedef int(_stdcall *tdecomp) (PVOID,PVOID);
			tdecomp decomp = (tdecomp)p->decomp;
			decomp(ucompd, input_data);

			if (cmpdata->iscode)
			{
				tdefilt defilter = (tdefilt)p->codefilt;
				defilter(ucompd, cmpdata->nlen);
			}
			(*p->VirtualProtect)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src), (DWORD)cmpdata->nlen, PAGE_EXECUTE_READWRITE, &OldP);

			while (nlendiff--) input_data[nlendiff] = ucompd[nlendiff];

			(*p->VirtualFree)(ucompd, 0, MEM_RELEASE);
			cmpdata->ulen = OldP;
		}
		cmpdata++;
	}
	p->restore(p, (LPVOID)base_offset);
	cmpdata = (compdata*)((DWORD)p->ocompdata + sizeof(DWORD));

	for (int i = 0; i < carray; i++)
	{
		if (cmpdata->clen != 0)(*p->VirtualProtect)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src), (DWORD)cmpdata->nlen, (DWORD)cmpdata->ulen, &OldP);
		cmpdata++;
	}
	if (p->TlsCallbackBackup != 0)
	{
		p->TlsCallbackBackup += p->ImageBase;
		p->TlsCallbackNew += p->ImageBase;
		PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK *)p->TlsCallbackBackup;
		PIMAGE_TLS_CALLBACK* callback_bckup = (PIMAGE_TLS_CALLBACK *)p->TlsCallbackNew;
		if (callback) {
			while (*callback) {
				(*callback)((LPVOID)p->ImageBase, DLL_PROCESS_ATTACH, NULL);
				*callback_bckup = *callback;
				callback_bckup++;
				callback++;
			}
		}
	}
	p->IsDepacked = 0x01;
}
#pragma optimize ("",off)
MARK_END_OF_FUNCTION(mentry_fr)
#pragma optimize ("gs",on)

static SizeT x86_lzdefilter(Byte *data, SizeT size)
{
	UInt32 state = 0;
	UInt32 ip = 0;
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
#pragma optimize ("gs",off)
MARK_END_OF_FUNCTION(x86_lzdefilter)
#pragma optimize ("",on)

//-----------------------------------------------------------------
// PE ENDS HERE
//----------------------------------------------------------------
void functions_lzma(PE *pe)
{
	

	pointers p;
	ZeroMemory(&p, sizeof(pointers));

	LogMessage* message = LogMessage::GetSingleton();
	TCHAR data[256] = { 0 };
	message->DoLogMessage("Copying decompressor code...", ERR_INFO);

	DWORD unpacker_sz = get_lzmadepackersize();
	DWORD unpacker_ptr = get_lzmadepackerptr();

	sprintf(data, "LZMA depacker is %d bytes...", unpacker_sz);
	message->DoLogMessage(data, ERR_INFO);

	DWORD psize, sfunc[4];
	sfunc[0] = SIZEOF_FUNCTION(mentry_lzma);
	sfunc[1] = SIZEOF_FUNCTION(restore);
	sfunc[2] = (DWORD)unpacker_sz;
	sfunc[3] = SIZEOF_FUNCTION(x86_lzdefilter);

	
	if (tls_callbacksnum)
	{
		tls_callbacksnum = (sizeof(DWORD)*tls_callbacksnum + 1);
	}
	else
	{
		tls_callbacksnum = (sizeof(DWORD) * 2);
	}


	sprintf(data, "TLS callback number is %d bytes...", tls_callbacksnum);
	psize = sfunc[0] + sfunc[1] + sfunc[2] + sfunc[3] + sizeof(pointers) + pe->scomparray+ pe->sdllimports + pe->sdllexports+sizeof(IMAGE_TLS_DIRECTORY32) + sizeof(DWORD) + tls_callbacksnum;
	LPVOID psection = malloc(psize);
	memset(psection, 0x00, psize);
	p.mentry = (tmentry)((DWORD)psection + sizeof(pointers));
	p.restore = (tmentry)((DWORD)psection + sizeof(pointers) + sfunc[0]);
	p.decomp = (DWORD)((DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1]);
	p.codefilt = (DWORD)((DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1]+sfunc[2]);
	p.ocompdata = (DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1]+sfunc[2]+sfunc[3];


	memcpy(psection, &p, sizeof(pointers));
	memcpy((LPVOID)p.mentry, (LPVOID)&mentry_lzma, sfunc[0]);
	memcpy((LPVOID)p.restore, (LPVOID)&restore, sfunc[1]);
	memcpy((LPVOID)p.decomp, (LPVOID)unpacker_ptr, sfunc[2]);
	memcpy((LPVOID)p.codefilt, (LPVOID)&x86_lzdefilter, sfunc[3]);
	
	memcpy((LPVOID)p.ocompdata, pe->comparray, pe->scomparray);
	AddSection(".ML!", psection, psize, NULL, pe);

	sprintf(data, "Decompressor stub is %d bytes...", psize);
	message->DoLogMessage(data, ERR_INFO);
	construct((pointers*) pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].data, pe, sfunc,psize);
}

void functions_fr(PE *pe)
{
	pointers p;
	ZeroMemory(&p, sizeof(pointers));

	LogMessage* message = LogMessage::GetSingleton();
	TCHAR data[256] = { 0 };
	message->DoLogMessage("Copying decompressor code...", ERR_INFO);

	DWORD unpacker_sz = get_frdepackersize();
	DWORD unpacker_ptr = get_frdepackerptr();

	DWORD psize, sfunc[4];
	sfunc[0] = SIZEOF_FUNCTION(mentry_fr);
	sfunc[1] = SIZEOF_FUNCTION(restore);
	sfunc[2] = (DWORD)unpacker_sz;
	sfunc[3] = SIZEOF_FUNCTION(x86_lzdefilter);


	
	/*
	DWORD func_size = sfunc[0] + sfunc[1] + sfunc[3];
	BYTE* data2 = (BYTE*)malloc(func_size);
	memcpy((LPVOID)data2, (LPVOID)&mentry_fr, sfunc[0]);
	memcpy((LPVOID)(data2 + sfunc[0]), (LPVOID)&restore, sfunc[1]);
	memcpy((LPVOID)(data2 + sfunc[0] + sfunc[1]), (LPVOID)&x86_lzdefilter, sfunc[3]);
	DWORD compressed_data_size;
	BYTE* compressed_data = compress_fr(data2, func_size, &compressed_data_size);
	sprintf(data, "Decompressor stub functions is %d bytes...", compressed_data_size);
	message->DoLogMessage(data, ERR_INFO);

	free(data2);
	free(compressed_data);*/


	if (tls_callbacksnum)
	{
		tls_callbacksnum = (sizeof(DWORD)*tls_callbacksnum + 1);
	}
	else
	{
		tls_callbacksnum = (sizeof(DWORD) * 2);
	}

	psize = sfunc[0] + sfunc[1] + sfunc[2] + sfunc[3] + sizeof(pointers) + pe->scomparray + pe->sdllimports + pe->sdllexports + sizeof(IMAGE_TLS_DIRECTORY32) + sizeof(DWORD) + tls_callbacksnum;
	LPVOID psection = malloc(psize);
	memset(psection, 0x00, psize);
	p.mentry = (tmentry)((DWORD)psection + sizeof(pointers));
	p.restore = (tmentry)((DWORD)psection + sizeof(pointers) + sfunc[0]);
	p.decomp = (DWORD)((DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1]);
	p.codefilt = (DWORD)((DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1] + sfunc[2]);
	p.ocompdata = (DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1] + sfunc[2] + sfunc[3];


	memcpy(psection, &p, sizeof(pointers));
	memcpy((LPVOID)p.mentry, (LPVOID)&mentry_fr, sfunc[0]);
	memcpy((LPVOID)p.restore, (LPVOID)&restore, sfunc[1]);
	memcpy((LPVOID)p.decomp, (LPVOID)unpacker_ptr, sfunc[2]);
	memcpy((LPVOID)p.codefilt, (LPVOID)&x86_lzdefilter, sfunc[3]);

	memcpy((LPVOID)p.ocompdata, pe->comparray, pe->scomparray);
	AddSection(".ML!", psection, psize, NULL, pe);

	sprintf(data, "Decompressor stub is %d bytes...", psize);
	message->DoLogMessage(data, ERR_INFO);
	construct((pointers*)pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].data, pe, sfunc, psize);
}


class Entrypoint_Code : public Xbyak::CodeGenerator {
public:
	Entrypoint_Code(int pointer, int entry, int OEP)
	{
		mov(ebx, 0);
		jmp(".tls");
		ret(0xC);
		L(".tls");
		lea(eax, ptr[ebx + pointer]);
		push(ebx);
		push(eax);
		lea(eax, ptr[ebx + entry]);
		call(eax);
		lea(eax, ptr[ebx + OEP]);
		jmp(eax);
	}
};

void construct(pointers *pt, PE *pe, DWORD sfunc[4], int section_size)
{

	LogMessage* message = LogMessage::GetSingleton();
	TCHAR data[256] = { 0 };



	DWORD vaddress = pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.VirtualAddress;
	DWORD pointer = pe->int_headers.OptionalHeader.ImageBase + vaddress;
	DWORD entry = pe->int_headers.OptionalHeader.ImageBase + vaddress + sizeof(pointers);

	sprintf(data, "PE stub location is at 0x%04X...", pointer);
	message->DoLogMessage(data, ERR_INFO);
	message->DoLogMessage("Generating shellcode...", ERR_INFO);
	memset(&pt->opcode, 0x00, sizeof(pt->opcode));
	Entrypoint_Code code(pointer, entry, pe->EntryPoint);
	memcpy(&pt->opcode,code.getCode(),code.getSize());


	pt->mentry = (tmentry)entry;
	pt->restore = (trestore)(entry + sfunc[0]);
	pt->decomp = (DWORD)(entry + sfunc[0] + sfunc[1]);
	pt->codefilt = (DWORD)(entry + sfunc[0] + sfunc[1] + sfunc[2]);
	pt->ocompdata = entry + sfunc[0] + sfunc[1] + sfunc[2] + sfunc[3];

	DWORD pimports = (DWORD)pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].data + sizeof(pointers) + sfunc[0] + sfunc[1] + sfunc[2] + sfunc[3] + pe->scomparray;
	DWORD pimportsrva = entry + sfunc[0] + sfunc[1] + sfunc[2] + sfunc[3] + pe->scomparray - pe->int_headers.OptionalHeader.ImageBase;

	sprintf(data, "Building imports at 0x%04X ...", pimportsrva);
	message->DoLogMessage(data, ERR_INFO);

	char **_dlls = pe->dlls;
	char **_thunks = pe->thunks;
	IMAGE_IMPORT_DESCRIPTOR *Imports = NULL;
	DWORD *Thunks = NULL;

	pe->sdllimports = 0;
	Imports = (IMAGE_IMPORT_DESCRIPTOR*)(pimports);
	while (*(*_dlls))
	{
		pe->sdllimports += sizeof(IMAGE_IMPORT_DESCRIPTOR); //imports
		_dlls++;
	}
	pe->sdllimports += sizeof(IMAGE_IMPORT_DESCRIPTOR); //zero import

	_dlls = pe->dlls;
	Thunks = (DWORD*)(pimports + pe->sdllimports);

	DWORD internals_count = 5;
	DWORD *internals = (DWORD*)(&pt->VirtualAlloc);

	while (*(*_dlls))
	{
		Imports->FirstThunk = pimportsrva + pe->sdllimports;
		while (*(*_thunks))
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
	while (*(*_dlls))
	{
		Imports->Name = pimportsrva + pe->sdllimports;
		strcpy((char*)(pimports + pe->sdllimports), *_dlls);
		pe->sdllimports += strlen((char*)*_dlls);//import names
		while (*(*_thunks))
		{
			if (*(*_thunks) == '@')
			{
				char * end;
				*Thunks = strtoul((*_thunks) + 1, &end, 10) + IMAGE_ORDINAL_FLAG;
			}
			else
			{
				*Thunks = pimportsrva + pe->sdllimports;
				memset((char*)(pimports + pe->sdllimports), 0, sizeof(WORD));
				pe->sdllimports += sizeof(WORD); //thunk hints
				strcpy((char*)(pimports + pe->sdllimports), *_thunks);
				pe->sdllimports += strlen((char*)*_thunks);//import names
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





	if (pe->sdllexports)
	{

		sprintf(data, "Building exports at 0x%04X ...", pexportsrva);
		message->DoLogMessage(data, ERR_INFO);

		PIMAGE_EXPORT_DIRECTORY _dir = (PIMAGE_EXPORT_DIRECTORY)pe->new_exports;

		_dir->Name += pexportsrva;
		_dir->AddressOfFunctions += pexportsrva;
		_dir->AddressOfNameOrdinals += pexportsrva;

		DWORD * address = (DWORD *)((DWORD)pe->new_exports + _dir->AddressOfNames);

		for (int i = 0; i < _dir->NumberOfNames; i++)
		{
			*address += pexportsrva;
			address++;
		}

		_dir->AddressOfNames += pexportsrva;

		memcpy((VOID*)pexports, _dir, pe->sdllexports);

		pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = pexportsrva;
	}



	DWORD ptls = pexports + pe->sdllexports;
	DWORD tlsrva = pexportsrva + pe->sdllexports;
	DWORD ptlsindex = ptls + sizeof(IMAGE_TLS_DIRECTORY32);
	DWORD tlsindexrva = tlsrva + sizeof(IMAGE_TLS_DIRECTORY32);
	DWORD tlsfakecallback = ptlsindex + sizeof(DWORD);
	DWORD tlscallbackfakerva= tlsindexrva + sizeof(DWORD);
	pt->TlsCallbackNew = 0;
	pt->TlsCallbackBackup = 0;
	//copy out new TLS callback array, length of old TLS callback array, padded with zeros
	//in stub, copy out old tls callback array vals to new tls callback array
	if (pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		DWORD * address = (DWORD *)tlsfakecallback;
		*address = pointer+0x07;
		pt->TlsCallbackNew = tlscallbackfakerva;
		pt->TlsCallbackBackup = pImgTlsDir->AddressOfCallBacks - pe->int_headers.OptionalHeader.ImageBase;
		pImgTlsDir->AddressOfCallBacks = tlscallbackfakerva + pe->int_headers.OptionalHeader.ImageBase;
		pImgTlsDir->AddressOfIndex = pe->int_headers.OptionalHeader.ImageBase + tlsindexrva;
		memcpy((IMAGE_TLS_DIRECTORY32*)ptls, pImgTlsDir, sizeof(IMAGE_TLS_DIRECTORY32));
		sprintf(data, "Building new TLS directory at 0x%04X ...", tlsrva);
		message->DoLogMessage(data, ERR_INFO);

		pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = tlsrva;
		free(pImgTlsDir);
		
	}
	DWORD prelocs = tlsfakecallback + tls_callbacksnum;
	DWORD prelocsrva = tlscallbackfakerva + tls_callbacksnum;
	DWORD sizeofrelocs = 0;
	if (pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		sprintf(data, "Building relocations at 0x%04X ...", prelocsrva);
		message->DoLogMessage(data, ERR_INFO);
		CRelocBuilder ripper_reloc;
		ripper_reloc.AddRelocation(vaddress + 1);
		if (pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{	
			//TLS callback ptr;
			ripper_reloc.AddRelocation(tlsrva + offsetof(IMAGE_TLS_DIRECTORY32, StartAddressOfRawData));
			ripper_reloc.AddRelocation(tlsrva + offsetof(IMAGE_TLS_DIRECTORY32, EndAddressOfRawData));
			ripper_reloc.AddRelocation(tlsrva + offsetof(IMAGE_TLS_DIRECTORY32, AddressOfIndex));
			ripper_reloc.AddRelocation(tlsrva + offsetof(IMAGE_TLS_DIRECTORY32, AddressOfCallBacks));
			ripper_reloc.AddRelocation(tlscallbackfakerva);
		}
		ripper_reloc.Export((BYTE*)prelocs);
		sizeofrelocs = ripper_reloc.GetSize();
		pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = prelocsrva;
		pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = sizeofrelocs;
		ripper_reloc.DeleteRvaList();
	}
	pt->ImageBase = pe->int_headers.OptionalHeader.ImageBase;
}


