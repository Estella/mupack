#include <cstdlib>
#include <vector>

using namespace std;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef WIN32
    #include <direct.h>
    #include <malloc.h>
#else
    #include <unistd.h>
    #include <sys/stat.h>
#endif

#define VER         "0.3"

int decomp(char * file, char* directory);
int comp(char * file, char* directory);
void std_err(void);
void io_err(void);





BYTE *Load_Input_File(char *FileName, DWORD *Size)
{
	BYTE *Memory;
	FILE *Input = fopen(FileName, "rb");

	if (!Input) return(NULL);
	// Get the filesize
	fseek(Input, 0, SEEK_END);
	*Size = ftell(Input);
	fseek(Input, 0, SEEK_SET);

	Memory = (BYTE *)malloc(*Size);
	if (!Memory) return(NULL);
	if (fread(Memory, 1, *Size, Input) != (size_t)*Size) return(NULL);
	if (Input) fclose(Input);
	Input = NULL;
	return(Memory);
}

extern "C"
{
#include "LzmaEnc.h"
	//#include "7z/LzmaDec.h"
}


void* Alloc(void *p, size_t size) { return malloc(size); }
void Free(void *p, void *address) { if (address) free(address); }
ISzAlloc alloc = { Alloc, Free };

extern "C"  unsigned char* __stdcall compress_lzma(unsigned char* input_data, DWORD in_size, DWORD* out_size)
{
	if (!in_size)return NULL;
	unsigned char* pvOutput;
	unsigned int Packed_Size;
	BYTE *Packed_Mem = (BYTE *)malloc(in_size * 2);
	memset(Packed_Mem, 0, in_size * 2);
	Packed_Size = in_size * 2;
	CLzmaEncProps props;
	LzmaEncProps_Init(&props);
	props.level = 9;
	props.fb = 273;
	props.lc = 8;
	props.lp = 0;
	props.pb = 2;
	props.algo = 1;
	props.numThreads = 4;
	SizeT s = LZMA_PROPS_SIZE;
	SRes err = LzmaEncode((Byte*)Packed_Mem + LZMA_PROPS_SIZE, (SizeT*)&Packed_Size,
		(Byte*)input_data, in_size, &props, (Byte*)Packed_Mem, &s, 1, NULL, &alloc, &alloc);
	Packed_Size += LZMA_PROPS_SIZE;
	if (err != SZ_OK || Packed_Size > in_size)
	{
		free(Packed_Mem);
		return NULL;
	}

	*out_size = Packed_Size;
	pvOutput = (unsigned char*)malloc(*out_size);
	memcpy(pvOutput, Packed_Mem, *out_size);
	free(Packed_Mem);
	return pvOutput;
}
