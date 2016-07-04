#include <string>
#include <windows.h>
#include "aplib.h"
#pragma comment (lib, "aplib.lib")

#define STDCALL __stdcall
#define DLLEXPORT __declspec(dllexport)

extern "C" void STDCALL free_compressdata(void *data)
{
	free(data);
	data = NULL;
}

extern "C" DWORD _stdcall get_workmemsz()
{
    return 0;
}

extern "C"  unsigned char*  STDCALL compress_data(unsigned char *in_data,DWORD in_size,DWORD *out_size)
{
	char *workmem    = (char*)malloc(aP_workmem_size(in_size));
	unsigned char *compressed = (unsigned char*)malloc(aP_max_packed_size(in_size));
	size_t datasz = aP_pack(in_data, compressed, in_size, workmem, NULL, NULL);
	if (datasz == APLIB_ERROR)
	{
		free(workmem);
		workmem = NULL;
		free(compressed);
		compressed = NULL;
		return NULL;
	}
	*out_size = datasz;
	free(workmem);
	workmem = NULL;
	return compressed;
}

extern "C" const char* STDCALL get_name()
{
	return "aplib";
}







typedef struct {
	const unsigned char *source;
	unsigned char *destination;
	unsigned int tag;
	unsigned int bitcount;
} APDEPACKDATA;

static __forceinline int aP_getbit(APDEPACKDATA *ud)
{
	unsigned int bit;

	/* check if tag is empty */
	if (!ud->bitcount--)
	{
		/* load next tag */
		ud->tag = *ud->source++;
		ud->bitcount = 7;
	}

	/* shift bit out of tag */
	bit = (ud->tag >> 7) & 0x01;
	ud->tag <<= 1;

	return bit;
}

static __forceinline unsigned int aP_getgamma(APDEPACKDATA *ud)
{
	unsigned int result = 1;

	/* input gamma2-encoded bits */
	do {
		result = (result << 1) + aP_getbit(ud);
	} while (aP_getbit(ud));

	return (result);
}

unsigned int aP_depackC(const void *destination, void *source, void *workmem)
{
	APDEPACKDATA ud;
	unsigned int offs, len, R0, LWM;
	int done;
	int i;

	ud.source = (const unsigned char *) source;
	ud.destination = (unsigned char *) destination;
	ud.bitcount = 0;

	LWM = 0;
	done = 0;

	/* first byte verbatim */
	*ud.destination++ = *ud.source++;

	/* main decompression loop */
	while (!done)
	{
		if (aP_getbit(&ud))
		{
			if (aP_getbit(&ud))
			{
				if (aP_getbit(&ud))
				{
					offs = 0;

					for (i = 4; i; i--) offs = (offs << 1) + aP_getbit(&ud);

					if (offs)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					} else {
						*ud.destination++ = 0x00;
					}

					LWM = 0;

				} else {

					offs = *ud.source++;

					len = 2 + (offs & 0x0001);

					offs >>= 1;

					if (offs)
					{
						for (; len; len--)
						{
							*ud.destination = *(ud.destination - offs);
							ud.destination++;
						}
					} else done = 1;

					R0 = offs;
					LWM = 1;
				}

			} else {

				offs = aP_getgamma(&ud);

				if ((LWM == 0) && (offs == 2))
				{
					offs = R0;

					len = aP_getgamma(&ud);

					for (; len; len--)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

				} else {

					if (LWM == 0) offs -= 3; else offs -= 2;

					offs <<= 8;
					offs += *ud.source++;

					len = aP_getgamma(&ud);

					if (offs >= 32000) len++;
					if (offs >= 1280) len++;
					if (offs < 128) len += 2;

					for (; len; len--)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

					R0 = offs;
				}

				LWM = 1;
			}

		} else {

			*ud.destination++ = *ud.source++;
			LWM = 0;
		}
	}

	return ud.destination - (unsigned char *) destination;
}

extern "C" DWORD STDCALL unpack()
{
	return aP_depackC(NULL,NULL,NULL);
}