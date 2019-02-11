// Written by Fabian "ryg" Giesen.
// I hereby place this code in the public domain.

#include "_types.hpp"
#include "frpacker.hpp"
#include <stdlib.h>
/****************************************************************************/

extern "C"  unsigned char* compress_fr(unsigned char* in_data, int in_size, int* out_size)
{
	if (!in_size) return NULL;
	size_t outsize = 0;
	CCAPackerBackEnd pbe;
	PackerFrontEnd *pfe = NULL;
	pfe = new BestPackerFrontEnd(&pbe);
	unsigned OutLimit = in_size + (in_size / 8) + 4096 + 512;
	unsigned char* OutImage = (unsigned char*)malloc(OutLimit + 512);
	outsize = pfe->Pack(in_data, in_size, OutImage, 0, 0);
	if (!outsize)
	{
		delete pfe;
		pfe = NULL;
		free(OutImage);
		return NULL;
	}
	*out_size = outsize;
	delete pfe;
	pfe = NULL;
	return OutImage;
}



void PackerBackEnd::InitPrevOffset(sInt count)
{
	nPrevOffsets = count;
	for (sInt i = 0; i < nPrevOffsets; i++)
		PrevOffset[i] = 0;
}

sInt PackerBackEnd::FindPrevOffset(sU32 offs) const
{
	for (sInt i = 0; i < nPrevOffsets; i++)
		if (offs == PrevOffset[i])
			return i;

	return -1;
}

void PackerBackEnd::NewPrevOffset(sU32 offs)
{
	sInt ind = FindPrevOffset(offs);
	ind = (ind == -1) ? nPrevOffsets - 1 : ind;

	// shift around
	for (sInt i = ind; i > 0; i--)
		PrevOffset[i] = PrevOffset[i - 1];

	// add
	PrevOffset[0] = offs;
}

/****************************************************************************/

PackerFrontEnd::PackerFrontEnd(PackerBackEnd *backEnd)
{
	BackEnd = backEnd;
}

PackerFrontEnd::~PackerFrontEnd()
{
	BackEnd = 0;
	Source = 0;
	SourceSize = 0;
}

PackerBackEnd *PackerFrontEnd::GetBackEnd()
{
	return BackEnd;
}

sU32 PackerFrontEnd::MaxOutputSize(sU32 inSize)
{
	return BackEnd->MaxOutputSize(inSize);
}

sU32 PackerFrontEnd::Pack(const sU8 *src, sU32 srcSize, sU8 *dst, PackerCallback cb, sInt relax)
{
	sInt i, bestp, bestsz, sz;
	sF32 profiles[17 * 16];

	Source = src;
	SourceSize = srcSize;

	SourcePtr = BackEnd->EncodeStart(dst, src);
	if (cb)
		cb(0, srcSize, 0);
	DoPack(cb);
	BackEnd->EncodeEnd(profiles);
	sz = BackEnd->GetCurrentSize();
	if (cb)
		cb(srcSize, srcSize, sz);

	if (relax)
	{
		bestp = -1;
		bestsz = sz;

		for (i = 0; i < relax; i++)
		{
			SourcePtr = BackEnd->EncodeStart(dst, src, profiles + i * 16);
			if (cb)
				cb(0, srcSize, 0);
			DoPack(cb);
			BackEnd->EncodeEnd(profiles + (i + 1) * 16);
			sz = BackEnd->GetCurrentSize();
			if (cb)
				cb(srcSize, srcSize, sz);

			if (sz < bestsz)
			{
				bestp = i;
				bestsz = sz;
			}
		}

		if (bestp != i - 1)
		{
			SourcePtr = BackEnd->EncodeStart(dst, src, (bestp == -1) ? 0 : profiles + bestp * 16);
			if (cb)
				cb(0, srcSize, 0);
			DoPack(cb);
			BackEnd->EncodeEnd();
			sz = BackEnd->GetCurrentSize();
			if (cb)
				cb(srcSize, srcSize, sz);
		}
	}

	return sz;
}

/****************************************************************************/

void GoodPackerFrontEnd::FindMatch(Match &match, sU32 start, sU32 lookAhead)
{
	sInt key, depth;
	sU32 node, offset, matchLen, bestOffset, bestLen;
	sF32 bestSize, matchSize;
	const sU8 *bytes, *ptr1, *ptr2;

	// todo: makes those two modifiable parameters.
	static const sInt MaxOffset = 512 * 1024;
	static const sInt MaxChainLen = 4096;

	// update the hash chain
	while (FillPtr <= start)
	{
		key = *(sU16 *)(Source + FillPtr);
		Link[FillPtr] = Head[key];
		Head[key] = FillPtr++;
	}

	bestOffset = 0;
	bestLen = 0;
	bestSize = BackEnd->MatchLen(bestOffset, bestLen);
	node = Link[start];
	bytes = Source;
	depth = MaxChainLen;

	if (lookAhead > 1)
	{
		while (node != ~0U && depth--)
		{
			offset = start - node;
			if (offset > MaxOffset)
				break;

			if (bytes[node + bestLen] == bytes[start + bestLen] || BackEnd->FindPrevOffset(offset) != -1)
			{
				matchLen = 0;
				ptr1 = bytes + node;
				ptr2 = bytes + start;

				if (lookAhead > 3)
				{
					while (matchLen < lookAhead - 3 && *(sU32 *)(ptr1 + matchLen) == *(sU32 *)(ptr2 + matchLen))
						matchLen += 4;
				}

				while (matchLen < lookAhead && ptr1[matchLen] == ptr2[matchLen])
					matchLen++;

				if (matchLen == lookAhead)
				{
					bestOffset = offset;
					bestLen = matchLen;
					break;
				}

				matchSize = BackEnd->MatchLen(offset, matchLen);
				if (matchSize<1e+20f && matchLen > bestLen + (matchSize - bestSize)*BackEnd->InvAvgMatchLen)
				{
					bestOffset = offset;
					bestLen = matchLen;
					bestSize = matchSize;
				}
			}

			node = Link[node];
		}
	}

	match.Offs = bestOffset;
	match.Len = bestLen;
}

void GoodPackerFrontEnd::TryBetterAhead()
{
	Match tm;

	FindMatch(tm, AheadStart, Ahead);
	if (tm.Len >= Ahead && BackEnd->MatchLen(tm.Offs, Ahead) < BackEnd->MatchLen(BM.Offs, Ahead))
		BM = tm;
}

void GoodPackerFrontEnd::FlushAhead(sF32 bias)
{
	if (Ahead)
	{
		if (BackEnd->LiteralLen(AheadStart, Ahead) + bias >= BackEnd->MatchLen(BM.Offs, Ahead))
			BackEnd->EncodeMatch(BM.Offs, Ahead);
		else
			BackEnd->EncodeLiteral(AheadStart, Ahead);

		Ahead = 0;
	}
}

void GoodPackerFrontEnd::DoPack(PackerCallback cb)
{
	sU32 lookAhead, testAhead;
	Match tm; // tempmatch
	sBool betterMatch;
	sF32 sizec, sizet;
	sU8 tick;

	Head = new sU32[65536];
	sSetMem(Head, 0xff, sizeof(sU32) * 65536);
	Link = new sU32[SourceSize];
	FillPtr = 0;

	tick = 0;
	AheadStart = 0;
	Ahead = 0;

	while (SourcePtr < SourceSize - 1)
	{
		if (!++tick && cb)
			cb(SourcePtr, SourceSize, BackEnd->GetCurrentSize());

		lookAhead = SourceSize - SourcePtr;
		FindMatch(CM, SourcePtr, lookAhead);

		if (CM.Len >= 2)
		{
			betterMatch = sFALSE;
			sizec = BackEnd->MatchLen(CM.Offs, CM.Len);

			// try to find a better match
			if (BackEnd->FindPrevOffset(CM.Offs) == -1 || Ahead && BackEnd->MatchLen(BM.Offs, Ahead) < BackEnd->LiteralLen(AheadStart, Ahead))
			{
				for (testAhead = 1; !betterMatch && CM.Len > testAhead && testAhead < 3; testAhead++)
				{
					FindMatch(tm, SourcePtr + testAhead, lookAhead - testAhead);
					sizet = BackEnd->MatchLen(tm.Offs, tm.Len);
					if (sizet < 1e+20f && CM.Len < tm.Len + (sizec - sizet)*BackEnd->InvAvgMatchLen
						|| Ahead && tm.Len >= CM.Len && sizet < sizec)
						betterMatch = sTRUE;
				}

				if (testAhead == 2 && !Ahead && tm.Len<CM.Len && BackEnd->LiteralLen(SourcePtr, 1) + sizet>sizec)
					betterMatch = sFALSE;
			}

			if (!betterMatch)
			{
				if (Ahead)
				{
					TryBetterAhead();
					FlushAhead(sizec - BackEnd->MatchLen(CM.Offs, CM.Len, BM.Offs));
				}

				if (BackEnd->LiteralLen(SourcePtr, CM.Len) < BackEnd->MatchLen(CM.Offs, CM.Len))
					BackEnd->EncodeLiteral(SourcePtr, CM.Len);
				else
					BackEnd->EncodeMatch(CM.Offs, CM.Len);

				SourcePtr += CM.Len;
			}
			else
			{
				if (!Ahead)
				{
					BM = CM;
					AheadStart = SourcePtr;
				}

				Ahead++;
				SourcePtr++;
			}
		}
		else
		{
			if (Ahead)
				Ahead++;
			else
				BackEnd->EncodeLiteral(SourcePtr, 1);

			SourcePtr++;
		}

		if (Ahead && Ahead == BM.Len)
		{
			TryBetterAhead();
			FlushAhead();
		}
	}

	FlushAhead();
	if (SourcePtr != SourceSize)
		BackEnd->EncodeLiteral(SourcePtr, SourceSize - SourcePtr);

	delete[] Link;
	delete[] Head;
}

GoodPackerFrontEnd::GoodPackerFrontEnd(PackerBackEnd *backEnd)
	: PackerFrontEnd(backEnd)
{
}

/****************************************************************************/
#ifndef DEMO
void BestPackerFrontEnd::DoPack(PackerCallback cb)
{
	struct Token
	{
		sU32  DecodeSize;
		sU32  Pos;
		sF64  CodeSize;
	};

	Token *tk, *tokens;
	sU32 *links;
	sU32 *head, i, key, ptr, depth, bestOff, bestLen, count, maxs;
	sU32 lastBestLen, lastBestOff;
	sF32 sz;
	const sU8 *src1, *src2;
	sU8 tick;

	tokens = new Token[SourceSize + 1];
	sSetMem(tokens, 0, sizeof(Token)*(SourceSize + 1));

	// prepare match tables
	head = new sU32[65536];
	links = new sU32[SourceSize];
	sSetMem(head, 0xff, sizeof(sU32) * 65536);

	for (i = 0; i < SourceSize - 1; i++)
	{
		key = *(sU16 *)(Source + i);
		links[i] = head[key];
		head[key] = i;
	}

	links[SourceSize - 1] = ~0U;
	delete[] head;

	// pathfinding loop
	tick = 0;
	lastBestLen = 0;
	lastBestOff = 0;

	for (i = SourceSize - 1; i != ~0U; i--)
	{
		tk = tokens + i;

		// start with literal
		tk->DecodeSize = 1;
		tk->Pos = i;
		tk->CodeSize = BackEnd->AvgLiteralLen + tk[1].CodeSize;

		ptr = links[i];
		depth = 0;

		if (lastBestLen && i >= lastBestOff && Source[i] == Source[i - lastBestOff])
		{
			// try to append to match from last iteration if possible
			sz = BackEnd->MatchLen(lastBestOff, lastBestLen + 1);
			if (sz + tk[lastBestLen + 1].CodeSize < tk->CodeSize)
			{
				bestLen = lastBestLen + 1;
				bestOff = lastBestOff;
				tk->DecodeSize = bestLen;
				tk->Pos = bestOff;
				tk->CodeSize = sz + tk[bestLen].CodeSize;
			}
		}
		else
		{
			bestOff = 0;
			bestLen = 0;
		}

		maxs = SourceSize - i;

		if (!++tick && cb)
			cb(sMin(maxs, SourceSize - 1), SourceSize, 0);

		while (ptr != ~0U)
		{
			src1 = Source + i;
			src2 = Source + ptr;
			count = 0;

			if (src1[bestLen] == src2[bestLen])
			{
				while (count + 3 < maxs && *(sU32 *)(src1 + count) == *(sU32 *)(src2 + count))
					count += 4;

				while (count < maxs && src1[count] == src2[count])
					count++;

				if (count > 1)
				{
					sz = BackEnd->MatchLen(i - ptr, count);

					if (sz + tk[count].CodeSize < tk->CodeSize)
					{
						bestLen = count;
						bestOff = i - ptr;
						tk->DecodeSize = bestLen;
						tk->Pos = bestOff;
						tk->CodeSize = sz + tk[bestLen].CodeSize;
					}
				}
			}

			if (++depth == 2048)
				break;

			ptr = links[ptr];
		}

		lastBestLen = bestLen;
		lastBestOff = bestOff;
	}

	// encoding loop
	for (i = SourcePtr; i < SourceSize; i += tokens[i].DecodeSize)
	{
		tk = tokens + i;

		// try things we can't during pathfinding: actual literal size...
		sz = BackEnd->LiteralLen(i, 1);
		if (sz + tk[1].CodeSize < tk->CodeSize)
		{
			tk->DecodeSize = 1;
			tk->CodeSize = sz + tk[1].CodeSize;
		}

		// and previous match references
		for (sInt j = 0; j < BackEnd->nPrevOffsets; j++)
		{
			if (BackEnd->PrevOffset[j])
			{
				count = 0;
				src1 = Source + i;
				src2 = Source + i - BackEnd->PrevOffset[j];
				while (i + count < SourceSize && src1[count] == src2[count])
					count++;

				if (count > 1)
				{
					sz = BackEnd->MatchLen(BackEnd->PrevOffset[j], count);
					if (sz + tk[count].CodeSize < tk->CodeSize)
					{
						tk->DecodeSize = count;
						tk->Pos = BackEnd->PrevOffset[j];
						tk->CodeSize = sz + tk[count].CodeSize;
					}
				}
			}
		}

		if (tk->DecodeSize == 1)
			BackEnd->EncodeLiteral(i, tk->DecodeSize);
		else
			BackEnd->EncodeMatch(tk->Pos, tk->DecodeSize);
	}

	delete[] tokens;
	delete[] links;
}

BestPackerFrontEnd::BestPackerFrontEnd(PackerBackEnd *backEnd)
	: PackerFrontEnd(backEnd)
{
}
#endif

/****************************************************************************/

#define sRANGETOP   (1<<24)
#define sRANGEBOT   (1<<16)

void RangeCoder::InitEncode(sU8 *buffer)
{
	Buffer = buffer;
	Bytes = Low = 0;
	Range = ~0;
}

void RangeCoder::FinishEncode()
{
	sInt i;

	for (i = 0; i < 4; i++)
	{
		Buffer[Bytes++] = Low >> 24;
		Low <<= 8;
	}
}

void RangeCoder::Encode(sU32 cumfreq, sU32 freq, sU32 totfreq)
{
	Range /= totfreq;
	Low += cumfreq * Range;
	Range *= freq;

	while ((Low ^ Low + Range) < sRANGETOP || Range < sRANGEBOT && ((Range = -sInt(Low) & sRANGEBOT - 1), 1))
	{
		Buffer[Bytes++] = Low >> 24;
		Low <<= 8;
		Range <<= 8;
	}
}

void RangeCoder::EncodePlain(sU32 value, sU32 max)
{
	Encode(value, 1, max);
}

void RangeCoder::InitDecode(sU8 *buffer)
{
	sInt i;

	Bytes = Low = Code = 0;
	Range = ~0;
	Buffer = buffer;

	for (i = 0; i < 4; i++)
		Code = (Code << 8) + Buffer[Bytes++];
}

sU32 RangeCoder::GetFreq(sU32 totfreq)
{
	Range /= totfreq;
	return (Code - Low) / Range;
}

void RangeCoder::Decode(sU32 cumfreq, sU32 freq)
{
	Low += cumfreq * Range;
	Range *= freq;
	while ((Low ^ Low + Range) < sRANGETOP || Range < sRANGEBOT && ((Range = -sInt(Low) & sRANGEBOT - 1), 1))
	{
		Code = (Code << 8) + Buffer[Bytes++];
		Range <<= 8;
		Low <<= 8;
	}
}

sU32 RangeCoder::DecodePlain(sU32 max)
{
	sU32 v;

	v = GetFreq(max);
	Decode(v, 1);

	return v;
}

/****************************************************************************/

void RangeModel::Init(sInt symbols, sInt thresh)
{
	sInt i;

	Symbols = symbols;
	Freq = new sInt[symbols * 2];
	TotFreq = symbols;
	Thresh = thresh;

	BitsOut = 0.0f;
	SymCount = 0;

	for (i = 0; i < symbols; i++)
	{
		Freq[i * 2 + 0] = i;
		Freq[i * 2 + 1] = 1;
	}
}

sF32 RangeModel::Encode(RangeCoder &coder, sInt symbol)
{
	sF32 size;

	size = GetBits(symbol);
	SymCount++;
	BitsOut += size;

	coder.Encode(Freq[symbol * 2 + 0], Freq[symbol * 2 + 1], TotFreq);
	Update(symbol);

	return size;
}

sInt RangeModel::Decode(RangeCoder &coder)
{
	sInt i, j, val;

	val = coder.GetFreq(GetTotFreq());

	for (i = 0; i < Symbols; i++)
	{
		j = val - Freq[i * 2 + 0];
		if (j >= 0 && j < Freq[i * 2 + 1])
			break;
	}

	coder.Decode(Freq[i * 2 + 0], Freq[i * 2 + 1]);
	Update(i);

	return i;
}

void RangeModel::Update(sInt symbol)
{
	sInt i, j;

	Freq[symbol * 2 + 1] += 2;
	TotFreq += 2;

	for (i = symbol + 1; i < Symbols; i++)
		Freq[i * 2] += 2;

	if (TotFreq >= Thresh)
	{
		j = 0;
		for (i = 0; i < Symbols; i++)
		{
			Freq[i * 2 + 0] = j;
			Freq[i * 2 + 1] -= Freq[i * 2 + 1] / 2;
			j += Freq[i * 2 + 1];
		}

		TotFreq = j;
	}
}

/****************************************************************************/

void CarryRangeCoder::InitEncode(sU8 *buffer)
{
	Buffer = buffer;
	Bytes = 0;

	Low = 0;
	Range = ~0;
	FFNum = 0;
	Cache = 0;
	FirstByte = sTRUE;
}

void CarryRangeCoder::FinishEncode()
{
	sInt i;

	for (i = 0; i < 5; i++)
		ShiftLow();
}

void CarryRangeCoder::EncodeBit(sU32 prob, sBool bit)
{
	sU32 newBound = (Range >> 11) * prob;

	if (!bit)
		Range = newBound;
	else
	{
		Low += newBound;
		Range -= newBound;
	}

	while (Range < 0x01000000U)
	{
		Range <<= 8;
		ShiftLow();
	}
}

void CarryRangeCoder::ShiftLow()
{
	sU32 Carry = Low >> 32;

	if (Low < 0xff000000U || Carry == 1)
	{
		if (!FirstByte)
			Buffer[Bytes++] = Cache + Carry;
		else
			FirstByte = sFALSE;

		while (FFNum)
		{
			Buffer[Bytes++] = 0xff + Carry;
			FFNum--;
		}

		Cache = (Low >> 24) & 0xff;
	}
	else
		FFNum++;

	Low = (Low << 8) & 0xffffffff;
}

/****************************************************************************/

void BitBuffer::InitEncode(sU8 *buffer)
{
	Buffer = buffer;
	BitPos = 7;
	Bytes = 0;
	Tag = 0;
}

void BitBuffer::FinishEncode()
{
	if (Tag)
		*Tag <<= (7 - BitPos);
}

void BitBuffer::PutBit(sBool bit)
{
	if (++BitPos == 8)
	{
		BitPos = 0;
		Tag = Buffer + Bytes++;
		*Tag = 0;
	}

	if (bit)
		*Tag = (*Tag << 1) | 1;
	else
		*Tag = *Tag << 1;
}

void BitBuffer::PutByte(sU8 value)
{
	Buffer[Bytes++] = value;
}

/****************************************************************************/

sF32 BitModel::Cost[513];
sBool BitModel::CostInit = sFALSE;

void BitModel::Init(sInt move)
{
	sInt i;

	Prob = 1024;
	Move = move;

	if (!CostInit)
	{
		for (i = 1; i < 513; i++)
			Cost[i] = -sFLog(i / 512.0f) / sFLog(2.0);

		Cost[0] = 1e+20f;
	}
}

sF32 BitModel::Encode(CarryRangeCoder &coder, sBool bit)
{
	sF32 cost;

	cost = GetBits(bit);
	coder.EncodeBit(Prob, bit);

	if (!bit)
		Prob += (2048 - Prob) >> Move;
	else
		Prob -= Prob >> Move;

	return cost;
}

sF32 BitModel::GetBits(sBool bit) const
{
	sInt pi, ik;
	sF32 t;

	pi = Prob;
	if (bit)
		pi = 2048 - pi;

	ik = pi >> 2;
	t = (pi & 3) * 0.25f;

	return Cost[ik] * (1.0f - t) + Cost[ik + 1] * t;
}

/****************************************************************************/

void GammaModel::Init(sInt move)
{
	sInt i;

	for (i = 0; i < 256; i++)
		Models[i].Init(move);

	Ctx = 1;
}

sF32 GammaModel::Encode(CarryRangeCoder &coder, sInt value)
{
	sF32 cbits;

	cbits = Models[Ctx].Encode(coder, value >> 1);
	Ctx = (Ctx * 2) + (value >> 1);
	cbits += Models[Ctx].Encode(coder, value & 1);
	Ctx = (Ctx * 2) + (value & 1);

	if (!(value & 2))
		Ctx = 1;

	return cbits;
}

sF32 GammaModel::GetBits(sInt value) const
{
	sF32 cbits;

	cbits = Models[Ctx].GetBits(value >> 1);
	Ctx = (Ctx * 2) + (value >> 1);
	cbits += Models[Ctx].GetBits(value & 1);
	Ctx = (Ctx * 2) + (value & 1);

	if (!(value & 2))
		Ctx = 1;

	return cbits;
}

/****************************************************************************/

// constants that require changes in the depacker
static const sInt MatchOffs1 = 96;
static const sInt MatchOffs2 = 2048;

sF32 CCAPackerBackEnd::RealGammaLen(sInt j, sU32 value)
{
	sInt invertlen;
	sU32 invert;
	sF32 sz;

	invertlen = 0;
	invert = 0;
	sz = 0.0f;

	if (value < 2)
		return 1e+20f;

	do
	{
		invert = (invert << 1) | (value & 1);
		invertlen++;
	} while ((value >>= 1) > 1);

	while (--invertlen)
	{
		sz += GammaSize[j * 4 + (invert & 1) + 2];
		//sz += Gamma[j].GetBits((invert & 1) + 2);
		invert >>= 1;
	}

	return sz + GammaSize[j * 4 + (invert & 1)];
	//return sz + Gamma[j].GetBits(invert & 1);*/
}

sF32 CCAPackerBackEnd::EncodeGamma(sInt j, sU32 value)
{
	sInt invertlen;
	sU32 invert;
	sF32 sz;

	invertlen = 0;
	invert = 0;
	sz = 0.0f;

	do
	{
		invert = (invert << 1) | (value & 1);
		invertlen++;
	} while ((value >>= 1) > 1);

	while (--invertlen)
	{
		sz += Gamma[j].Encode(Coder, (invert & 1) | 2);
		invert >>= 1;
	}
	sz += Gamma[j].Encode(Coder, invert & 1);

	return sz;
}

sU32 CCAPackerBackEnd::MaxOutputSize(sU32 inSize)
{
	return inSize + (inSize / 8) + 256; // should be ok
}

sF32 CCAPackerBackEnd::MatchLen(sU32 pos, sU32 len, sU32 PO)
{
	sBool prev = sFALSE;

	if (!PO)
		prev = FindPrevOffset(pos) != -1;
	else
		prev = pos == PO;

	if (!pos || len < 2 || !prev && ((pos >= 96 && len < 3) || (pos >= 2048 && len < 4)))
		return 1e+20f;

	if (prev)
		return GammaLen(1, len) + CodesSize[1];
	else
	{
		if (pos >= MatchOffs1) len--;
		if (pos >= MatchOffs2) len--;

		pos--;
		return GammaLen(0, (pos >> 4) + 2) + GammaLen(1, len) + CodesSize[1] + 4.0f;
	}
}

sF32 CCAPackerBackEnd::LiteralLen(sU32 pos, sU32 len)
{
	sF32 clen;
	sInt j, ctx, bit;

	clen = CodesSize[0] * len;
	while (len--)
	{
		ctx = 1;
		for (j = 7; j >= 0; j--)
		{
			bit = (Source[pos] >> j) & 1;
			clen += LitBit[ctx].GetBits(bit);
			ctx = (ctx * 2) + bit;
		}

		pos++;
	}

	return clen;
}

sU32 CCAPackerBackEnd::EncodeStart(sU8 *dest, const sU8 *src, sF32 *profile)
{
	sInt i, j;

	static sF32 defaultProfile[] =
	{
	  1.5580f, 3.2685f, 1.8210f, 1.8699f, // gamma 0
	  2.0000f, 1.1142f, 2.3943f, 3.3536f, // gamma 1
	  0.7216f, 1.3454f,                   // codes
	  5.9170f, 7.2410f                    // average code lengths
	};

	Coder.InitEncode(dest);
	Codes[0].Init(5);
	Codes[1].Init(5);
	Gamma[0].Init(5);
	Gamma[1].Init(5);
	PrevMatch.Init(5);

	Source = src;
	LWM = sFALSE;

	InitPrevOffset(1);

	if (!profile)
		profile = defaultProfile;

	// setup parameters from profile
	GammaSize[0] = profile[0];
	GammaSize[1] = profile[1];
	GammaSize[2] = profile[2];
	GammaSize[3] = profile[3];
	GammaSize[4] = profile[4];
	GammaSize[5] = profile[5];
	GammaSize[6] = profile[6];
	GammaSize[7] = profile[7];
	CodesSize[0] = profile[8];
	CodesSize[1] = profile[9];
	InvAvgMatchLen = 1.0 / profile[10];
	AvgLiteralLen = profile[11];

	AccMatchLen = 0.0f;
	AccMatchCount = 0;
	AccLiteralLen = 0.0f;
	AccLiteralCount = 0;

	for (j = 0; j < 2; j++)
		for (i = 0; i < 256; i++)
			GammaLens[j][i] = RealGammaLen(j, i);

	for (i = 1; i < 256; i++)
		LitBit[i].Init(4);

	for (i = 0; i < 2; i++)
		for (j = 1; j < 16; j++)
			MatchLow[i][j].Init(5);

	// encode first byte
	j = 1;
	for (i = 7; i >= 0; i--)
	{
		sInt bit = (*src >> i) & 1;
		LitBit[j].Encode(Coder, bit);
		j = (j * 2) + bit;
	}
	src++;

	return 1;
}

void CCAPackerBackEnd::EncodeEnd(sF32 *outProfile)
{
	sInt i;

	if (outProfile)
	{
		/*outProfile[ 0] = Gamma[0].GetBits(0);
		outProfile[ 1] = Gamma[0].GetBits(1);
		outProfile[ 2] = Gamma[0].GetBits(2);
		outProfile[ 3] = Gamma[0].GetBits(3);
		outProfile[ 4] = Gamma[1].GetBits(0);
		outProfile[ 5] = Gamma[1].GetBits(1);
		outProfile[ 6] = Gamma[1].GetBits(2);
		outProfile[ 7] = Gamma[1].GetBits(3);
		outProfile[ 8] = Codes.GetBits(0);
		outProfile[ 9] = Codes.GetBits(1);*/
		outProfile[10] = 2.0f * AccMatchLen / AccMatchCount;
		outProfile[11] = AccLiteralLen / AccLiteralCount;
	}

	Codes[LWM].Encode(Coder, 1);
	if (!LWM)
		PrevMatch.Encode(Coder, 0);
	// encode 2^32 (eqv. 0) as offset
	for (i = 0; i < 30; i++)
		Gamma[0].Encode(Coder, 2);
	Gamma[0].Encode(Coder, 2);

	Coder.FinishEncode();
}

void CCAPackerBackEnd::EncodeMatch(sU32 pos, sU32 len)
{
	sF32 sz;
	sInt rlen, ctx, i, pv, bit;

	rlen = len;
	sz = Codes[LWM].Encode(Coder, 1);

	sInt prev = FindPrevOffset(pos);

	if (prev > 0 || prev == 0 && !LWM) // previous match
	{
		for (i = LWM; i < nPrevOffsets; i++)
			sz += PrevMatch.Encode(Coder, i == prev);

		//sz += PrevMatch.Encode(Coder,1);
		sz += EncodeGamma(1, len);
	}
	else // normal match
	{
		for (i = LWM; i < nPrevOffsets; i++)
			sz += PrevMatch.Encode(Coder, i == prev);

		/*if(!LWM)
		  sz += PrevMatch.Encode(Coder,0);*/

		pv = pos - 1;
		sz += EncodeGamma(0, (pv >> 4) + 2);
		ctx = 1;

		for (i = 3; i >= 0; i--)
		{
			bit = (pv >> i) & 1;
			sz += MatchLow[pv >= 16][ctx].Encode(Coder, bit);
			ctx = (ctx * 2) + bit;
		}

		if (pos >= MatchOffs2) len--;
		if (pos >= MatchOffs1) len--;

		sz += EncodeGamma(1, len);
	}

	AccMatchLen += 1.0f*sz / rlen;
	AccMatchCount++;

	NewPrevOffset(pos);
	LWM = sTRUE;
}

void CCAPackerBackEnd::EncodeLiteral(sU32 pos, sU32 len)
{
	sU32 i, ctx, bit;
	sInt j;

	for (i = 0; i < len; i++)
	{
		Codes[LWM].Encode(Coder, 0);

		ctx = 1;
		for (j = 7; j >= 0; j--)
		{
			bit = (Source[pos] >> j) & 1;
			AccLiteralLen += LitBit[ctx].Encode(Coder, bit);
			ctx = (ctx * 2) + bit;
		}

		pos++;
		AccLiteralCount++;
		LWM = sFALSE;
	}
}

sU32 CCAPackerBackEnd::GetCurrentSize()
{
	return Coder.GetBytes();
}
