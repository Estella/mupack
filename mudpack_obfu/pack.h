
#pragma once

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
#define align_(_size, _base_size) \
	(((_size + _base_size - 1) / _base_size) * _base_size)
#define addr(address) \
	((DWORD)pe.m_sections[i].data + (address - pe.m_sections[i].header.VirtualAddress))
#define arrayof(x)		(sizeof(x)/sizeof(x[0]))

typedef int (_stdcall *tdecomp) (PVOID, PVOID, PVOID);
typedef void (_stdcall *tmentry)(LPVOID,LPVOID);
typedef void (_stdcall *trestore)(LPVOID,LPVOID);
typedef WINBASEAPI PVOID (WINAPI **tVirtualAlloc)(PVOID,DWORD,DWORD,DWORD);
typedef WINBASEAPI PVOID (WINAPI **tRtlMoveMemory)(PVOID,PVOID,DWORD);
typedef WINBASEAPI BOOL (WINAPI **tVirtualFree)(PVOID,DWORD,DWORD);
typedef WINBASEAPI BOOL (WINAPI **tVirtualProtect)(PVOID,DWORD,DWORD,PDWORD);
typedef WINBASEAPI FARPROC (WINAPI **tGetProcAddress)(HINSTANCE,LPCSTR);
typedef WINBASEAPI HINSTANCE (WINAPI **tGetModuleHandleA)(LPCSTR);
typedef WINBASEAPI HMODULE (WINAPI **tGetModuleHandle)(LPCSTR);

#pragma pack(push, 1)
typedef struct compdata
{
	LPVOID src;
	DWORD clen;
	DWORD nlen;
	DWORD ulen;
	DWORD wlen;
};

typedef struct pointers
{
	BYTE opcode[4096];
	tVirtualAlloc VirtualAlloc;
	tVirtualFree VirtualFree;
	tVirtualProtect VirtualProtect;
	tGetProcAddress GetProcAddress;
	tGetModuleHandleA GetModuleHandleA;
	tRtlMoveMemory copymem;
	tmentry mentry;
	trestore restore;
	tdecomp decomp;
	DWORD ocompdata;
	DWORD ImageBase;
	DWORD OriginalImports;
	DWORD OriginalRelocations;
	DWORD OriginalRelocationsSize;
};
#pragma pack(pop)

typedef DWORD (_stdcall *tgetdepackersize) ();
extern tgetdepackersize get_depackersize;
typedef DWORD (_stdcall *tgetworkmemsize) ();
extern tgetworkmemsize get_workmemsize;
typedef DWORD (_stdcall *tgetdepackerptr) ();
extern tgetdepackerptr get_depackerptr;
typedef unsigned char* (_stdcall *tcmpdata)(unsigned char *,DWORD,DWORD *);
extern tcmpdata cmp_data;
typedef void (_stdcall *tfreecmpdata)(void *);
extern tfreecmpdata freecmp_data;
bool plugin_load(char* filename);
void plugin_free();

struct plugin{
	unsigned char  fname[MAX_PATH+1]; //filename
	unsigned char  name[255]; //filename
};



void construct(pointers *p, PE *pe, DWORD sfunc[2]);
int compress_file(char* argv);
void functions(pointers *pt, PE *pe);
int pe_read(const char* filename, PE *pe);
int pe_write(const char* filename, PE *pe);
void AddSection(const char* sname, LPVOID _section, DWORD _section_size, DWORD _entry_point_offset, PE *pe);
void CryptFile(int(__cdecl *callback) (unsigned int, unsigned int),char *filenameload);
BYTE * comp(BYTE* input, int in_size, int * out_size);