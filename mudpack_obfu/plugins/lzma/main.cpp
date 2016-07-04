
#include <windows.h>
#include <tchar.h>

#define STDCALL __stdcall
#define DLLEXPORT __declspec(dllexport)

// TODO: Enter extra includes here.
//#define _LZMA_PROB32
#include <initguid.h>
#include "lzma\7zip\Compress\LZMA\LZMAEncoder.h"
#include "lzma\7zip\Common\StreamObjects.h"
#include "lzma\7zip\Common\ProgressUtils.h"
#include "lzma\Windows\PropVariant.h"
#include "lzma\7zip\Compress\LZMA_C\LzmaDecode.h"

// function prototypes
typedef BOOL(STDCALL *PROGRESSCALLBACK)(DWORD dwPercent);
void __stdcall FreeCompressionMemory(PVOID pvCompressionMemory);

// TODO: Enter extra function prototypes here.
class LZMAProgress : public ICompressProgressInfo, public CMyUnknownImp
{
public:

    HRESULT STDMETHODCALLTYPE SetRatioInfo(const UInt64 *inSize, const UInt64 *outSize);

    MY_UNKNOWN_IMP
};

// global variables
PROGRESSCALLBACK g_ProgressCallback;

// TODO: Enter exrtra global variables here.
#define COMPRESSION_MODE       2 // 0-2
#define DICTIONARY_SIZE       25 // 0-28
#define FAST_BYTES           273 // 5-273
#define LITERAL_CONTEXT_BITS   8 // 0-8
#define LITERAL_POS_BITS       0 // 0-4
#define POS_BITS               2 // 0-4
UInt64  g_qwInputSize;

// code start
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if(fdwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinstDLL);

    return TRUE;
}

extern "C"  unsigned char* __stdcall compress_data(unsigned char* pvInput, DWORD dwInputSize, DWORD* pdwOutputSize)
{
    unsigned char* pvOutput;

    g_ProgressCallback = NULL;
    if(g_ProgressCallback)
    {
        if(g_ProgressCallback(0) == FALSE)
        {
            return NULL;
        }
    }

    // TODO: Implement the Compress function.
    NCompress::NLZMA::CEncoder * Encoder;
    CSequentialInStreamImp     * inStream;
    CSequentialOutStreamImp    * outStream;
    LZMAProgress               * Progress;
    PROPID propIDs[] = {NCoderPropID::kAlgorithm, NCoderPropID::kDictionarySize, NCoderPropID::kNumFastBytes, NCoderPropID::kLitContextBits, NCoderPropID::kLitPosBits, NCoderPropID::kPosStateBits};
    NWindows::NCOM::CPropVariant properties[] = {UInt32(COMPRESSION_MODE), UInt32(1 << DICTIONARY_SIZE), UInt32(FAST_BYTES), UInt32(LITERAL_CONTEXT_BITS), UInt32(LITERAL_POS_BITS), UInt32(POS_BITS)};

    pvOutput = NULL;
    Encoder = new NCompress::NLZMA::CEncoder();
    Encoder->AddRef();
    if(Encoder->SetCoderProperties(propIDs, properties, 6) == S_OK)
    {
        Encoder->SetWriteEndMarkerMode(true);
        inStream = new CSequentialInStreamImp();
        inStream->AddRef();
        inStream->Init((PBYTE)pvInput, dwInputSize);
        outStream = new CSequentialOutStreamImp();
        outStream->AddRef();
        g_qwInputSize = dwInputSize;
        Progress = new LZMAProgress();
        Progress->AddRef();
        if(Encoder->Code(inStream, outStream, &g_qwInputSize, NULL, Progress) == S_OK)
        {
            *pdwOutputSize = (DWORD)outStream->GetSize();
            pvOutput = (unsigned char*)VirtualAlloc(NULL, *pdwOutputSize, MEM_COMMIT, PAGE_READWRITE);
            memcpy(pvOutput, outStream->GetBuffer(), *pdwOutputSize);
        }
        outStream->Release();
        inStream->Release();
    }
    Encoder->Release();

    if(g_ProgressCallback)
    {
        if(g_ProgressCallback(100) == FALSE)
        {
            VirtualFree(pvOutput,0,MEM_RELEASE);
            return NULL;
        }
    }

    return pvOutput;
}

extern "C" void __stdcall free_compressdata(void *data)
{
    VirtualFree(data,0,MEM_RELEASE);
}

extern "C" const char* STDCALL get_name()
{
	return "LZMA";
}

extern "C" DWORD _stdcall get_workmemsz()
{
    CLzmaDecoderState state;
    state.Properties.lc = LITERAL_CONTEXT_BITS;
    state.Properties.lp = LITERAL_POS_BITS;
    state.Properties.pb = POS_BITS;
    return DWORD(LzmaGetNumProbs(&state.Properties) * sizeof(CProb));
}

// TODO: Add extra functions here.
HRESULT STDMETHODCALLTYPE LZMAProgress::SetRatioInfo(const UInt64 *inSize, const UInt64 *outSize)
{
    if(g_ProgressCallback)
    {
        if(!g_ProgressCallback(DWORD(*inSize * 100 / g_qwInputSize)))
            return S_FALSE;
    }
    return S_OK;
}
