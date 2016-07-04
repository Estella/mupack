
#pragma once


#define align_(_size, _base_size) \
	(((_size + _base_size - 1) / _base_size) * _base_size)
#define addr(address) \
	((DWORD)pe.m_sections[i].data + (address - pe.m_sections[i].header.VirtualAddress))
#define arrayof(x)		(sizeof(x)/sizeof(x[0]))

extern PIMAGE_TLS_DIRECTORY32 pImgTlsDir;
extern DWORD tls_callbacksnum;

typedef int(_stdcall *tdefilt) (PVOID, DWORD);
typedef void (_stdcall *tmentry)(LPVOID,LPVOID);
typedef void (_stdcall *trestore)(LPVOID,LPVOID);
typedef void(_stdcall *ttlscallback)(PVOID, DWORD, DWORD);
typedef WINBASEAPI PVOID (WINAPI **tVirtualAlloc)(PVOID,DWORD,DWORD,DWORD);
typedef WINBASEAPI PVOID (WINAPI **tRtlMoveMemory)(PVOID,PVOID,DWORD);
typedef WINBASEAPI BOOL (WINAPI **tVirtualFree)(PVOID,DWORD,DWORD);
typedef WINBASEAPI BOOL (WINAPI **tVirtualProtect)(PVOID,DWORD,DWORD,PDWORD);
typedef WINBASEAPI FARPROC (WINAPI **tGetProcAddress)(HINSTANCE,LPCSTR);
typedef WINBASEAPI HINSTANCE (WINAPI **tGetModuleHandleA)(LPCSTR);
typedef WINBASEAPI HMODULE (WINAPI **tGetModuleHandle)(LPCSTR);




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
	DWORD ignore;
};

typedef struct PE
{
	DWORD EntryPoint;
	dos_section m_dos;
	LPVOID comparray;
	DWORD scomparray;
	char **dlls;
	char **thunks;
	DWORD sdllimports;
	DWORD sdllexports;
	DWORD rescaddress;
	IMAGE_NT_HEADERS int_headers;
	isections *m_sections;
	unsigned char *new_resource_section;
	unsigned char *new_exports;
	DWORD new_resource_section_size;
	DWORD new_resource_data_size;
	DWORD new_resource_cdata_size;
	DWORD resource_section_virtual_address;
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




int compress_file(char* argv);
int pe_read(const char* filename, PE *pe);
int pe_write(const char* filename, PE *pe);
void AddSection(const char* sname, LPVOID _section, DWORD _section_size, DWORD _entry_point_offset, PE *pe);
BYTE * comp(BYTE* input, int in_size, int * out_size);