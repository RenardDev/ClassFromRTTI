#include "RTTI.h"

typedef struct _TYPEDESCRIPTOR {
	void* pVTable;
	void* pSpare;
	char Name;
} TYPEDESCRIPTOR, *PTYPEDESCRIPTOR;

// Helpful functions
static void* FindSignatureNative(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature) {
	const size_t unSignatureLength = strlen(reinterpret_cast<const char*>(szSignature));
	const uintptr_t unEnd = reinterpret_cast<uintptr_t>(pEnd) - unSignatureLength;
	for (uintptr_t i = 0; (i < reinterpret_cast<uintptr_t>(pEnd)) && (pBegin <= reinterpret_cast<void*>(unEnd)); ++i, ++pBegin) {
		uintptr_t unNextStart = 0;
		uintptr_t unResult = 0;
		bool bSuccess = true;
		for (size_t j = 0; j < unSignatureLength; ++j) {
			if (reinterpret_cast<const unsigned char*>(szSignature)[j] == 0x2A) {
				continue;
			}
			const unsigned char unSymbol = pBegin[j];
			if (unSymbol == reinterpret_cast<const unsigned char*>(szSignature)[0]) {
				unNextStart = j;
			}
			if (unSymbol != reinterpret_cast<const unsigned char*>(szSignature)[j]) {
				unResult = unNextStart;
				bSuccess = false;
				break;
			}
		}
		if (bSuccess) {
			return pBegin;
		}
		else {
			i += unResult;
		}
	}
	return nullptr;
}

static void* FindSignatureSSE2(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature) {
	const size_t unSignatureLength = strlen(reinterpret_cast<const char*>(szSignature));
	const uintptr_t unSignaturesCount = static_cast<uintptr_t>(ceil(static_cast<float>(unSignatureLength) / 16.f));
	unsigned int pSignatures[32];
	memset(pSignatures, 0, sizeof(pSignatures));
	for (uintptr_t i = 0; i < unSignaturesCount; ++i) {
		for (char j = static_cast<char>(strnlen(reinterpret_cast<const char*>(szSignature) + i * 16, 16)) - 1; j >= 0; --j) {
			if (reinterpret_cast<const unsigned char*>(szSignature)[i * 16 + j] != 0x2A) {
				pSignatures[i] |= 1 << j;
			}
		}
	}

	const __m128i xmm0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(szSignature));

	for (; pBegin != pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 64), _MM_HINT_NTA)) {
		if (pBegin > pEnd) {
			break;
		}
		if (reinterpret_cast<const unsigned char*>(szSignature)[0] == pBegin[0]) {
			if ((_mm_movemask_epi8(_mm_cmpeq_epi8(xmm0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(pBegin)))) & pSignatures[0]) == pSignatures[0]) {
				for (uintptr_t i = 1; i < unSignaturesCount; ++i) {
					if ((_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(pBegin + i * 16)), _mm_loadu_si128(reinterpret_cast<const __m128i*>(szSignature + i * 16)))) & pSignatures[i]) == pSignatures[i]) {
						if ((i + 1) == unSignaturesCount) {
							return pBegin;
						}
					}
				}
				return pBegin;
			}
		}
	}

	return nullptr;
}

static void* FindSignatureAVX2(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature) {
	const size_t unSignatureLength = strlen(reinterpret_cast<const char*>(szSignature));
	const uintptr_t unSignaturesCount = static_cast<uintptr_t>(ceil(static_cast<float>(unSignatureLength) / 32.f));
	unsigned int pSignatures[64];
	memset(pSignatures, 0, sizeof(pSignatures));
	for (uintptr_t i = 0; i < unSignaturesCount; ++i) {
		for (char j = static_cast<char>(strnlen(reinterpret_cast<const char*>(szSignature) + i * 32, 32)) - 1; j >= 0; --j) {
			if (reinterpret_cast<const unsigned char*>(szSignature)[i * 32 + j] != 0x2A) {
				pSignatures[i] |= 1 << j;
			}
		}
	}

	const __m256i ymm0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(szSignature));

	for (; pBegin != pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 128), _MM_HINT_NTA)) {
		if (pBegin > pEnd) {
			break;
		}
		if (reinterpret_cast<const unsigned char*>(szSignature)[0] == pBegin[0]) {
			if ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(ymm0, _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pBegin)))) & pSignatures[0]) == pSignatures[0]) {
				for (uintptr_t i = 1; i < unSignaturesCount; ++i) {
					if ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(pBegin + i * 32)), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(szSignature + i * 32)))) & pSignatures[i]) == pSignatures[i]) {
						if ((i + 1) == unSignaturesCount) {
							return pBegin;
						}
					}
				}
				return pBegin;
			}
		}
	}

	return nullptr;
}

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
static void GetRealModuleDimensions(void** ppBegin, void **ppEnd) {
	void* pBegin = *ppBegin;
	void* pEnd = *ppEnd;

	/*
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pBegin);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
	PIMAGE_OPTIONAL_HEADER pOH = &(pNTHs->OptionalHeader);
	PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(pFH) + sizeof(IMAGE_FILE_HEADER) + pFH->SizeOfOptionalHeader);
	for (unsigned short i = 0; i < pFH->NumberOfSections; ++i, ++pFirstSection) {
		if (strncmp(reinterpret_cast<char*>(&(pFirstSection->Name)), ".data", 8) == 0) {
			void* pSectionBegin = reinterpret_cast<char*>(pBegin) + pFirstSection->PointerToRawData;
			void* pSectionEnd = reinte
			rpret_cast<char*>(pSectionBegin) + pFirstSection->SizeOfRawData;
			printf("SECTION [%016llX; %016llX]\n", (UINT64)(pFirstSection->PointerToRawData - pFirstSection->VirtualAddress), (UINT64)(pFirstSection->VirtualAddress + pFirstSection->Misc.VirtualSize));
		}
	}
	*/

	*ppBegin = pBegin;
	*ppEnd = pEnd;
}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

//---------------------------------------------------------------------------------
// RTTI interface
//---------------------------------------------------------------------------------
RTTI::RTTI(bool bCaching, bool bRangeCaching, bool bModulesCaching, bool bForceFastMethod, bool bMinIters) {
	m_bAvailableSSE2 = false;
	m_bAvailableAVX2 = false;
	m_bCaching = bCaching;
	m_bRangesCaching = bRangeCaching;
	m_bModulesCaching = bModulesCaching;
	m_bForceFastMethod = bForceFastMethod;
	m_bMinIters = bMinIters;
	m_vecRangesSymbolsAddressesCache.clear();
	m_vecModulesSymbolsAddressesCache.clear();
	m_vecRangesSymbolsOffsetsCache.clear();
	m_vecModulesSymbolsOffsetsCache.clear();

	int cpuinf[4];
	__cpuid(cpuinf, 0x00000000);
	int nIDs = cpuinf[0];
	if (nIDs >= 0x00000001) {
		__cpuid(cpuinf, 0x00000001);
		m_bAvailableSSE2 = (cpuinf[3] & (1 << 26)) != 0;
	}
	if (nIDs >= 0x00000007) {
		__cpuid(cpuinf, 0x00000007);
		m_bAvailableAVX2 = (cpuinf[1] & (1 << 5)) != 0;
	}
}

RTTI::~RTTI() {
	// Nothing...
}

// Finding Signature
void* RTTI::FindSignature(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature) {
	if (m_bAvailableAVX2) {
		return FindSignatureAVX2(pBegin, pEnd, szSignature);
	}
	else if (m_bAvailableSSE2) {
		return FindSignatureSSE2(pBegin, pEnd, szSignature);
	}
	else {
		return FindSignatureNative(pBegin, pEnd, szSignature);
	}
}

// Finding TypeInfo
void* RTTI::FindTypeInfoAddressFromRange(void* pBegin, void* pEnd) {
	// Prevention from self-analysing.
	char szEncodedPattern[] = { '\xD1', '\xC0', '\xBE', '\xA9', '\x8B', '\x86', '\x8F', '\x9A', '\xA0', '\x96', '\x91', '\x99', '\x90', '\xBF', '\xBF' }; // ".?AVtype_info@@"
	char szPattern[sizeof(szEncodedPattern) + 1];
	memset(szPattern, 0, sizeof(szPattern));
	for (unsigned char i = 0; i < (sizeof(szPattern) - 1); ++i) {
		szPattern[i] = szEncodedPattern[i] ^ 0xFF;
	}
	return FindSignature(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szPattern);
}

// Finding VTables
//  One
void* RTTI::GetFastVTableAddressFromRange(void* pBegin, void* pEnd, const char* szClassName) {
	if (m_bCaching && m_bRangesCaching) {
		void* pResult = GetVTableAddressFromRangeCache(pBegin, pEnd, szClassName);
		if (pResult) {
			return pResult;
		}
	}

	std::unique_ptr<char[]> mem_szSymbolBuffer(new char[RTTI_DEFAULT_MAX_SYMBOL_LENGTH]); // 0x7FF - Max for MSVC
	char* szSymbolBuffer = mem_szSymbolBuffer.get();
	if (!szSymbolBuffer) {
		return nullptr;
	}
	memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);
	sprintf_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH, ".?AV%s@@", szClassName);

	void* pType = reinterpret_cast<PTYPEDESCRIPTOR>(reinterpret_cast<char*>(FindSignature(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szSymbolBuffer)));
	if (!pType) {
		return nullptr;
	}

	PTYPEDESCRIPTOR pTypeDescriptor = reinterpret_cast<PTYPEDESCRIPTOR>(reinterpret_cast<char*>(pType) - sizeof(void*) * 2);

	// Converting
#ifdef _WIN64
	uintptr_t unTypeOffsetTemp = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(pTypeDescriptor) - reinterpret_cast<uintptr_t>(pBegin));
	unsigned int unTypeOffset = (*(reinterpret_cast<unsigned int*>(&unTypeOffsetTemp)));

	char szTypeOffset[sizeof(int) + 1];
	memset(szTypeOffset, 0, sizeof(szTypeOffset));
	for (unsigned char i = 0; i < sizeof(int); ++i) {
		char cByte = reinterpret_cast<char*>(&unTypeOffset)[i];
		if (cByte == '\x00') {
			cByte = '\x2A';
		}
		szTypeOffset[i] = cByte;
	}
#elif _WIN32
	char szType[sizeof(void*) + 1];
	memset(szType, 0, sizeof(szType));
	for (unsigned char i = 0; i < sizeof(void*); ++i) {
		char cByte = reinterpret_cast<char*>(&pTypeDescriptor)[i];
		if (cByte == '\x00') {
			cByte = '\x2A';
		}
		szType[i] = cByte;
	}
#endif

	// Finding
	void* pLastReference = pBegin;
	while (pLastReference < pEnd) {
#ifdef _WIN64
		void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szTypeOffset);
#elif _WIN32
		void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szType);
#endif
		if (!pReference) {
			break;
		}

#ifdef _WIN64
		if (!(((*(reinterpret_cast<unsigned int*>(pReference))) != 0) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<unsigned char*>(pReference) + sizeof(int))) != 0)))) {
			pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
			continue;
		}
#elif _WIN32
		if (!(((*(reinterpret_cast<unsigned int*>(pReference))) >= reinterpret_cast<unsigned int>(pBegin)) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(pReference) + sizeof(int))) >= reinterpret_cast<unsigned int>(pBegin))))) {
			pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
			continue;
		}
#endif

		void* pLocation = reinterpret_cast<char*>(pReference) - (sizeof(unsigned long) * 3);

		char szLocation[sizeof(void*) + 1];
		memset(szLocation, 0, sizeof(szLocation));
		for (unsigned char i = 0; i < sizeof(void*); ++i) {
			char cByte = reinterpret_cast<char*>(&pLocation)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
			}
			szLocation[i] = cByte;
		}

		void* pMeta = FindSignature(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szLocation);
		if (!pMeta) {
			pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
			continue;
		}

		void* pAddress = reinterpret_cast<void*>(reinterpret_cast<char*>(pMeta) + sizeof(void*));

		if (m_bCaching && m_bRangesCaching) {
			bool bExistsRange = false;
			for (vecRangesSymbolsAddresses::iterator it = m_vecRangesSymbolsAddressesCache.begin(); it != m_vecRangesSymbolsAddressesCache.end(); ++it) {
				RangeOfDataForRTII& dataRange = std::get<0>(*it);
				void*& pcBegin = std::get<0>(dataRange);
				void*& pcEnd = std::get<1>(dataRange);
				if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
					bExistsRange = true;
					vecSymbolsAddresses& vecSymbols = std::get<1>(*it);
					bool bExistsSymbol = false;
					for (vecSymbolsAddresses::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
						void*& psAddress = std::get<1>(*sit);
						if (pAddress == psAddress) {
							bExistsSymbol = true;
						}
					}
					if (!bExistsSymbol) {
						vecSymbols.push_back(SymbolAddress(szSymbolBuffer, pAddress));
					}
				}
			}
			if (!bExistsRange) {
				vecSymbolsAddresses vecSymbols;
				vecSymbols.push_back(SymbolAddress(szSymbolBuffer, pAddress));
				m_vecRangesSymbolsAddressesCache.push_back(RangeSymbolsAddresses(RangeOfDataForRTII(pBegin, pEnd), vecSymbols));
			}
		}

		return pAddress;
	}

	return nullptr;
}

void* RTTI::GetVTableAddressFromRange(void* pBegin, void* pEnd, const char* szClassName) {
	if (m_bCaching && m_bRangesCaching) {
		void* pResult = GetVTableAddressFromRangeCache(pBegin, pEnd, szClassName);
		if (pResult) {
			return pResult;
		}
	}

	void* pAddress = GetFastVTableAddressFromRange(pBegin, pEnd, szClassName);
	if (pAddress) {
		if (m_bCaching && m_bRangesCaching) {
			bool bExistsRange = false;
			for (vecRangesSymbolsAddresses::iterator it = m_vecRangesSymbolsAddressesCache.begin(); it != m_vecRangesSymbolsAddressesCache.end(); ++it) {
				RangeOfDataForRTII& dataRange = std::get<0>(*it);
				void*& pcBegin = std::get<0>(dataRange);
				void*& pcEnd = std::get<1>(dataRange);
				if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
					bExistsRange = true;
					vecSymbolsAddresses& vecSymbols = std::get<1>(*it);
					bool bExistsSymbol = false;
					for (vecSymbolsAddresses::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
						void*& psAddress = std::get<1>(*sit);
						if (pAddress == psAddress) {
							bExistsSymbol = true;
						}
					}
					if (!bExistsSymbol) {
						vecSymbols.push_back(SymbolAddress(szClassName, pAddress));
					}
				}
			}
			if (!bExistsRange) {
				vecSymbolsAddresses vecSymbols;
				vecSymbols.push_back(SymbolAddress(szClassName, pAddress));
				m_vecRangesSymbolsAddressesCache.push_back(RangeSymbolsAddresses(RangeOfDataForRTII(pBegin, pEnd), vecSymbols));
			}
		}

		return pAddress;
	}
	else if (m_bForceFastMethod) {
		return nullptr;
	}

	void* pTypeInfo = FindTypeInfoAddressFromRange(pBegin, pEnd);
	if (!pTypeInfo) {
		return nullptr;
	}

	PTYPEDESCRIPTOR pTypeDesc = reinterpret_cast<PTYPEDESCRIPTOR>(reinterpret_cast<char*>(pTypeInfo) - (sizeof(void*) * 2));

	std::unique_ptr<char[]> mem_szSymbolBuffer(new char[RTTI_DEFAULT_MAX_SYMBOL_LENGTH]); // 0x7FF - Max for MSVC
	char* szSymbolBuffer = mem_szSymbolBuffer.get();
	if (!szSymbolBuffer) {
		return nullptr;
	}
	memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);

	// Converting
	char szVTable[sizeof(void*) + 1];
	memset(szVTable, 0, sizeof(szVTable));
	for (unsigned char i = 0; i < sizeof(void*); ++i) {
		char cByte = reinterpret_cast<char*>(&(pTypeDesc->pVTable))[i];
		if (cByte == '\x00') {
			cByte = '\x2A';
		}
		szVTable[i] = cByte;
	}

	// Finding
	void* pLastType = pBegin;
	while (pLastType < pEnd) {
		void* pType = FindSignature(reinterpret_cast<unsigned char*>(pLastType), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szVTable);
		if (!pType) {
			break;
		}

		// Converting
#ifdef _WIN64
		uintptr_t unTypeOffsetTemp = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(pType) - reinterpret_cast<uintptr_t>(pBegin));
		unsigned int unTypeOffset = (*(reinterpret_cast<unsigned int*>(&unTypeOffsetTemp)));

		char szTypeOffset[sizeof(int) + 1];
		memset(szTypeOffset, 0, sizeof(szTypeOffset));
		for (unsigned char i = 0; i < sizeof(int); ++i) {
			char cByte = reinterpret_cast<char*>(&unTypeOffset)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
			}
			szTypeOffset[i] = cByte;
		}
#elif _WIN32
		char szType[sizeof(void*) + 1];
		memset(szType, 0, sizeof(szType));
		for (unsigned char i = 0; i < sizeof(void*); ++i) {
			char cByte = reinterpret_cast<char*>(&pType)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
			}
			szType[i] = cByte;
		}
#endif

		// Finding
		void* pLastReference = pBegin;
		while (pLastReference < pEnd) {
#ifdef _WIN64
			void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szTypeOffset);
#elif _WIN32
			void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szType);
#endif
			if (!pReference) {
				break;
			}

#ifdef _WIN64
			if (!(((*(reinterpret_cast<unsigned int*>(pReference))) != 0) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(pReference) + sizeof(int))) != 0)))) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}
#elif _WIN32
			if (!(((*(reinterpret_cast<unsigned int*>(pReference))) >= reinterpret_cast<unsigned int>(pBegin)) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<unsigned int*>(pReference) + sizeof(int))) >= reinterpret_cast<unsigned int>(pBegin))))) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}
#endif

			void* pLocation = reinterpret_cast<char*>(pReference) - (sizeof(int) * 3);

			char szLocation[sizeof(void*) + 1];
			memset(szLocation, 0, sizeof(szLocation));
			for (unsigned char i = 0; i < sizeof(void*); ++i) {
				char cByte = reinterpret_cast<char*>(&pLocation)[i];
				if (cByte == '\x00') {
					cByte = '\x2A';
				}
				szLocation[i] = cByte;
			}

			void* pMeta = FindSignature(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szLocation);
			if (!pMeta) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}

			PTYPEDESCRIPTOR pTypeDescriptor = reinterpret_cast<PTYPEDESCRIPTOR>(pType);
			char* pSymbol = &(pTypeDescriptor->Name);

			char* pNewSymbol = pSymbol;
			if (pSymbol[4] == '?') {
				pNewSymbol = pSymbol + 1;
			}
			else if (pSymbol[0] == '.') {
				pNewSymbol = pSymbol + 4;
			}
			else if (pSymbol[0] == '?') {
				pNewSymbol = pSymbol + 2;
			}
			else {
				break;
			}

			memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);
			sprintf_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH, "??_7%s6B@", pNewSymbol);
			if (!((UnDecorateSymbolName(szSymbolBuffer, szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1, UNDNAME_NAME_ONLY | UNDNAME_NO_SPECIAL_SYMS)) != 0)) {
				break;
			}

			size_t unSymbolBufferLength = strnlen_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1);

			void* pPattern1 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "::`anonymous namespace'");
			if (pPattern1) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern1) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 24);
			}

			void* pPattern2 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "::`vftable'");
			if (pPattern2) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern2) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 12);
			}

			void* pPattern3 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "const ");
			if (pPattern3) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern3) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 7);
			}

			if (strcmp(szSymbolBuffer, szClassName) != 0) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}

			void* pAddress = reinterpret_cast<void*>(reinterpret_cast<char*>(pMeta) + sizeof(void*));

			if (m_bCaching && m_bRangesCaching) {
				bool bExistsRange = false;
				for (vecRangesSymbolsAddresses::iterator it = m_vecRangesSymbolsAddressesCache.begin(); it != m_vecRangesSymbolsAddressesCache.end(); ++it) {
					RangeOfDataForRTII& dataRange = std::get<0>(*it);
					void*& pcBegin = std::get<0>(dataRange);
					void*& pcEnd = std::get<1>(dataRange);
					if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
						bExistsRange = true;
						vecSymbolsAddresses& vecSymbols = std::get<1>(*it);
						bool bExistsSymbol = false;
						for (vecSymbolsAddresses::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
							void*& psAddress = std::get<1>(*sit);
							if (pAddress == psAddress) {
								bExistsSymbol = true;
							}
						}
						if (!bExistsSymbol) {
							vecSymbols.push_back(SymbolAddress(szSymbolBuffer, pAddress));
						}
					}
				}
				if (!bExistsRange) {
					vecSymbolsAddresses vecSymbols;
					vecSymbols.push_back(SymbolAddress(szSymbolBuffer, pAddress));
					m_vecRangesSymbolsAddressesCache.push_back(RangeSymbolsAddresses(RangeOfDataForRTII(pBegin, pEnd), vecSymbols));
				}
			}

			return pAddress;
		}

		pLastType = reinterpret_cast<void*>(reinterpret_cast<char*>(pType) + sizeof(void*));
	}

	return nullptr;
}

uintptr_t RTTI::GetFastVTableOffsetFromRange(void* pBegin, void* pEnd, const char* szClassName) {
	if (m_bCaching && m_bRangesCaching) {
		uintptr_t unResult = GetVTableOffsetFromRangeCache(pBegin, pEnd, szClassName);
		if (unResult) {
			return unResult;
		}
	}

	std::unique_ptr<char[]> mem_szSymbolBuffer(new char[RTTI_DEFAULT_MAX_SYMBOL_LENGTH]); // 0x7FF - Max for MSVC
	char* szSymbolBuffer = mem_szSymbolBuffer.get();
	if (!szSymbolBuffer) {
		return 0;
	}
	memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);
	sprintf_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH, ".?AV%s@@", szClassName);

	void* pType = reinterpret_cast<PTYPEDESCRIPTOR>(reinterpret_cast<char*>(FindSignature(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szSymbolBuffer)));
	if (!pType) {
		return 0;
	}

	PTYPEDESCRIPTOR pTypeDescriptor = reinterpret_cast<PTYPEDESCRIPTOR>(reinterpret_cast<char*>(pType) - sizeof(void*) * 2);

	// Converting
#ifdef _WIN64
	uintptr_t unTypeOffsetTemp = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(pTypeDescriptor) - reinterpret_cast<uintptr_t>(pBegin));
	unsigned int unTypeOffset = (*(reinterpret_cast<unsigned int*>(&unTypeOffsetTemp)));

	char szTypeOffset[sizeof(int) + 1];
	memset(szTypeOffset, 0, sizeof(szTypeOffset));
	for (unsigned char i = 0; i < sizeof(int); ++i) {
		char cByte = reinterpret_cast<char*>(&unTypeOffset)[i];
		if (cByte == '\x00') {
			cByte = '\x2A';
		}
		szTypeOffset[i] = cByte;
	}
#elif _WIN32
	char szType[sizeof(void*) + 1];
	memset(szType, 0, sizeof(szType));
	for (unsigned char i = 0; i < sizeof(void*); ++i) {
		char cByte = reinterpret_cast<char*>(&pTypeDescriptor)[i];
		if (cByte == '\x00') {
			cByte = '\x2A';
		}
		szType[i] = cByte;
	}
#endif

	// Finding
	void* pLastReference = pBegin;
	while (pLastReference < pEnd) {
#ifdef _WIN64
		void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szTypeOffset);
#elif _WIN32
		void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szType);
#endif
		if (!pReference) {
			break;
		}

#ifdef _WIN64
		if (!(((*(reinterpret_cast<unsigned int*>(pReference))) != 0) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<unsigned char*>(pReference) + sizeof(int))) != 0)))) {
			pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
			continue;
		}
#elif _WIN32
		if (!(((*(reinterpret_cast<unsigned int*>(pReference))) >= reinterpret_cast<unsigned int>(pBegin)) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(pReference) + sizeof(int))) >= reinterpret_cast<unsigned int>(pBegin))))) {
			pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
			continue;
		}
#endif

		void* pLocation = reinterpret_cast<char*>(pReference) - (sizeof(unsigned long) * 3);

		char szLocation[sizeof(void*) + 1];
		memset(szLocation, 0, sizeof(szLocation));
		for (unsigned char i = 0; i < sizeof(void*); ++i) {
			char cByte = reinterpret_cast<char*>(&pLocation)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
			}
			szLocation[i] = cByte;
		}

		void* pMeta = FindSignature(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szLocation);
		if (!pMeta) {
			pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
			continue;
		}

		uintptr_t unOffset = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(pMeta) + sizeof(void*) - reinterpret_cast<uintptr_t>(pBegin));

		if (m_bCaching && m_bRangesCaching) {
			bool bExistsRange = false;
			for (vecRangesSymbolsOffsets::iterator it = m_vecRangesSymbolsOffsetsCache.begin(); it != m_vecRangesSymbolsOffsetsCache.end(); ++it) {
				RangeOfDataForRTII& dataRange = std::get<0>(*it);
				void*& pcBegin = std::get<0>(dataRange);
				void*& pcEnd = std::get<1>(dataRange);
				if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
					bExistsRange = true;
					vecSymbolsOffsets& vecSymbols = std::get<1>(*it);
					bool bExistsSymbol = false;
					for (vecSymbolsOffsets::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
						uintptr_t& unsOffset = std::get<1>(*sit);
						if (unOffset == unsOffset) {
							bExistsSymbol = true;
						}
					}
					if (!bExistsSymbol) {
						vecSymbols.push_back(SymbolOffset(szSymbolBuffer, unOffset));
					}
				}
			}
			if (!bExistsRange) {
				vecSymbolsOffsets vecSymbols;
				vecSymbols.push_back(SymbolOffset(szSymbolBuffer, unOffset));
				m_vecRangesSymbolsOffsetsCache.push_back(RangeSymbolsOffsets(RangeOfDataForRTII(pBegin, pEnd), vecSymbols));
			}
		}

		return unOffset;
	}

	return 0;
}

uintptr_t RTTI::GetVTableOffsetFromRange(void* pBegin, void* pEnd, const char* szClassName) {
	if (m_bCaching && m_bRangesCaching) {
		uintptr_t unResult = GetVTableOffsetFromRangeCache(pBegin, pEnd, szClassName);
		if (unResult) {
			return unResult;
		}
	}

	uintptr_t unOffset = GetFastVTableOffsetFromRange(pBegin, pEnd, szClassName);
	if (unOffset) {
		if (m_bCaching && m_bRangesCaching) {
			bool bExistsRange = false;
			for (vecRangesSymbolsOffsets::iterator it = m_vecRangesSymbolsOffsetsCache.begin(); it != m_vecRangesSymbolsOffsetsCache.end(); ++it) {
				RangeOfDataForRTII& dataRange = std::get<0>(*it);
				void*& pcBegin = std::get<0>(dataRange);
				void*& pcEnd = std::get<1>(dataRange);
				if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
					bExistsRange = true;
					vecSymbolsOffsets& vecSymbols = std::get<1>(*it);
					bool bExistsSymbol = false;
					for (vecSymbolsOffsets::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
						uintptr_t& unsOffset = std::get<1>(*sit);
						if (unOffset == unsOffset) {
							bExistsSymbol = true;
						}
					}
					if (!bExistsSymbol) {
						vecSymbols.push_back(SymbolOffset(szClassName, unOffset));
					}
				}
			}
			if (!bExistsRange) {
				vecSymbolsOffsets vecSymbols;
				vecSymbols.push_back(SymbolOffset(szClassName, unOffset));
				m_vecRangesSymbolsOffsetsCache.push_back(RangeSymbolsOffsets(RangeOfDataForRTII(pBegin, pEnd), vecSymbols));
			}
		}
		return unOffset;
	}
	else if (m_bForceFastMethod) {
		return 0;
	}

	void* pTypeInfo = FindTypeInfoAddressFromRange(pBegin, pEnd);
	if (!pTypeInfo) {
		return 0;
	}

	PTYPEDESCRIPTOR pTypeDesc = reinterpret_cast<PTYPEDESCRIPTOR>(reinterpret_cast<char*>(pTypeInfo) - (sizeof(void*) * 2));

	std::unique_ptr<char[]> mem_szSymbolBuffer(new char[RTTI_DEFAULT_MAX_SYMBOL_LENGTH]); // 0x7FF - Max for MSVC
	char* szSymbolBuffer = mem_szSymbolBuffer.get();
	if (!szSymbolBuffer) {
		return 0;
	}
	memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);

	// Converting
	char szVTable[sizeof(void*) + 1];
	memset(szVTable, 0, sizeof(szVTable));
	for (unsigned char i = 0; i < sizeof(void*); ++i) {
		char cByte = reinterpret_cast<char*>(&(pTypeDesc->pVTable))[i];
		if (cByte == '\x00') {
			cByte = '\x2A';
		}
		szVTable[i] = cByte;
	}

	// Finding
	void* pLastType = pBegin;
	while (pLastType < pEnd) {
		void* pType = FindSignature(reinterpret_cast<unsigned char*>(pLastType), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szVTable);
		if (!pType) {
			break;
		}

		// Converting
#ifdef _WIN64
		uintptr_t unTypeOffsetTemp = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(pType) - reinterpret_cast<uintptr_t>(pBegin));
		unsigned int unTypeOffset = (*(reinterpret_cast<unsigned int*>(&unTypeOffsetTemp)));

		char szTypeOffset[sizeof(int) + 1];
		memset(szTypeOffset, 0, sizeof(szTypeOffset));
		for (unsigned char i = 0; i < sizeof(int); ++i) {
			char cByte = reinterpret_cast<char*>(&unTypeOffset)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
			}
			szTypeOffset[i] = cByte;
		}
#elif _WIN32
		char szType[sizeof(void*) + 1];
		memset(szType, 0, sizeof(szType));
		for (unsigned char i = 0; i < sizeof(void*); ++i) {
			char cByte = reinterpret_cast<char*>(&pType)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
			}
			szType[i] = cByte;
		}
#endif

		// Finding
		void* pLastReference = pBegin;
		while (pLastReference < pEnd) {
#ifdef _WIN64
			void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szTypeOffset);
#elif _WIN32
			void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szType);
#endif
			if (!pReference) {
				break;
			}

#ifdef _WIN64
			if (!(((*(reinterpret_cast<unsigned int*>(pReference))) != 0) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<unsigned char*>(pReference) + sizeof(int))) != 0)))) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}
#elif _WIN32
			if (!(((*(reinterpret_cast<unsigned int*>(pReference))) >= reinterpret_cast<unsigned int>(pBegin)) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(pReference) + sizeof(int))) >= reinterpret_cast<unsigned int>(pBegin))))) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}
#endif

			void* pLocation = reinterpret_cast<char*>(pReference) - (sizeof(unsigned long) * 3);

			char szLocation[sizeof(void*) + 1];
			memset(szLocation, 0, sizeof(szLocation));
			for (unsigned char i = 0; i < sizeof(void*); ++i) {
				char cByte = reinterpret_cast<char*>(&pLocation)[i];
				if (cByte == '\x00') {
					cByte = '\x2A';
				}
				szLocation[i] = cByte;
			}

			void* pMeta = FindSignature(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szLocation);
			if (!pMeta) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}

			PTYPEDESCRIPTOR pTypeDescriptor = reinterpret_cast<PTYPEDESCRIPTOR>(pType);
			char* pSymbol = &(pTypeDescriptor->Name);

			char* pNewSymbol = pSymbol;
			if (pSymbol[4] == '?') {
				pNewSymbol = pSymbol + 1;
			}
			else if (pSymbol[0] == '.') {
				pNewSymbol = pSymbol + 4;
			}
			else if (pSymbol[0] == '?') {
				pNewSymbol = pSymbol + 2;
			}
			else {
				break;
			}

			memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);
			sprintf_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH, "??_7%s6B@", pNewSymbol);
			if (!((UnDecorateSymbolName(szSymbolBuffer, szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1, UNDNAME_NAME_ONLY | UNDNAME_NO_SPECIAL_SYMS)) != 0)) {
				break;
			}

			size_t unSymbolBufferLength = strnlen_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1);

			void* pPattern1 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "::`anonymous namespace'");
			if (pPattern1) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern1) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 24);
			}

			void* pPattern2 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "::`vftable'");
			if (pPattern2) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern2) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 12);
			}

			void* pPattern3 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "const ");
			if (pPattern3) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern3) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 7);
			}

			if (strcmp(szSymbolBuffer, szClassName) != 0) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}

			uintptr_t unOffset = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(pMeta) + sizeof(void*) - reinterpret_cast<uintptr_t>(pBegin));

			if (m_bCaching && m_bRangesCaching) {
				bool bExistsRange = false;
				for (vecRangesSymbolsOffsets::iterator it = m_vecRangesSymbolsOffsetsCache.begin(); it != m_vecRangesSymbolsOffsetsCache.end(); ++it) {
					RangeOfDataForRTII& dataRange = std::get<0>(*it);
					void*& pcBegin = std::get<0>(dataRange);
					void*& pcEnd = std::get<1>(dataRange);
					if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
						bExistsRange = true;
						vecSymbolsOffsets& vecSymbols = std::get<1>(*it);
						bool bExistsSymbol = false;
						for (vecSymbolsOffsets::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
							uintptr_t& unsOffset = std::get<1>(*sit);
							if (unOffset == unsOffset) {
								bExistsSymbol = true;
							}
						}
						if (!bExistsSymbol) {
							vecSymbols.push_back(SymbolOffset(szSymbolBuffer, unOffset));
						}
					}
				}
				if (!bExistsRange) {
					vecSymbolsOffsets vecSymbols;
					vecSymbols.push_back(SymbolOffset(szSymbolBuffer, unOffset));
					m_vecRangesSymbolsOffsetsCache.push_back(RangeSymbolsOffsets(RangeOfDataForRTII(pBegin, pEnd), vecSymbols));
				}
			}

			return unOffset;
		}

		pLastType = reinterpret_cast<void*>(reinterpret_cast<char*>(pType) + sizeof(void*));
	}

	return 0;
}

void* RTTI::GetVTableAddressFromModule(HMODULE hModule, const char* szClassName) {
	if (!hModule) {
		return nullptr;
	}
	
	if (m_bCaching && m_bModulesCaching) {
		void* pResult = GetVTableAddressFromModuleCache(hModule, szClassName);
		if (pResult) {
			return pResult;
		}
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return nullptr;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	GetRealModuleDimensions(reinterpret_cast<void**>(&pBegin), &pEnd);
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	void* pAddress = GetFastVTableAddressFromRange(reinterpret_cast<void*>(pBegin), pEnd, szClassName);
	if (!pAddress) {
		if (m_bForceFastMethod) {
			return nullptr;
		}
		pAddress = GetVTableAddressFromRange(reinterpret_cast<void*>(pBegin), pEnd, szClassName);
	}

	if (!pAddress) {
		return nullptr;
	}

	if (m_bCaching && m_bModulesCaching) {
		bool bExistsModule = false;
		for (vecModulesSymbolsAddresses::iterator it = m_vecModulesSymbolsAddressesCache.begin(); it != m_vecModulesSymbolsAddressesCache.end(); ++it) {
			HMODULE& hMod = std::get<0>(*it);
			if (hMod == hModule) {
				bExistsModule = true;
				vecSymbolsAddresses& vecSymbols = std::get<1>(*it);
				bool bExistsSymbol = false;
				for (vecSymbolsAddresses::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
					void*& psAddress = std::get<1>(*sit);
					if (pAddress == psAddress) {
						bExistsSymbol = true;
					}
				}
				if (!bExistsSymbol) {
					vecSymbols.push_back(SymbolAddress(szClassName, pAddress));
				}
			}
		}
		if (!bExistsModule) {
			vecSymbolsAddresses vecSymbols;
			vecSymbols.push_back(SymbolAddress(szClassName, pAddress));
			m_vecModulesSymbolsAddressesCache.push_back(ModuleSymbolsAddresses(hModule, vecSymbols));
		}
	}

	return pAddress;
}

uintptr_t RTTI::GetVTableOffsetFromModule(HMODULE hModule, const char* szClassName) {
	if (!hModule) {
		return 0;
	}
	
	if (m_bCaching && m_bModulesCaching) {
		uintptr_t unResult = GetVTableOffsetFromModuleCache(hModule, szClassName);
		if (unResult) {
			return unResult;
		}
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return 0;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	GetRealModuleDimensions(reinterpret_cast<void**>(&pBegin), &pEnd);
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	uintptr_t unOffset = GetFastVTableOffsetFromRange(reinterpret_cast<void*>(pBegin), pEnd, szClassName);
	if (!unOffset) {
		if (m_bForceFastMethod) {
			return 0;
		}
		unOffset = GetVTableOffsetFromRange(reinterpret_cast<void*>(pBegin), pEnd, szClassName);
	}

	if (!unOffset) {
		return 0;
	}

	if (m_bCaching && m_bModulesCaching) {
		bool bExistsModule = false;
		for (vecModulesSymbolsOffsets::iterator it = m_vecModulesSymbolsOffsetsCache.begin(); it != m_vecModulesSymbolsOffsetsCache.end(); ++it) {
			HMODULE& hMod = std::get<0>(*it);
			if (hMod == hModule) {
				bExistsModule = true;
				vecSymbolsOffsets& vecSymbols = std::get<1>(*it);
				bool bExistsSymbol = false;
				for (vecSymbolsOffsets::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
					uintptr_t& unsOffset = std::get<1>(*sit);
					if (unOffset == unsOffset) {
						bExistsSymbol = true;
					}
				}
				if (!bExistsSymbol) {
					vecSymbols.push_back(SymbolOffset(szClassName, unOffset));
				}
			}
		}
		if (!bExistsModule) {
			vecSymbolsOffsets vecSymbols;
			vecSymbols.push_back(SymbolOffset(szClassName, unOffset));
			m_vecModulesSymbolsOffsetsCache.push_back(ModuleSymbolsOffsets(hModule, vecSymbols));
		}
	}

	return unOffset;
}

//  Multiple
vecSymbolsAddresses RTTI::GetVTablesAddressesFromRange(void* pBegin, void* pEnd) {
	vecSymbolsAddresses vecData;

	if (m_bCaching && m_bRangesCaching) {
		for (vecRangesSymbolsAddresses::iterator it = m_vecRangesSymbolsAddressesCache.begin(); it != m_vecRangesSymbolsAddressesCache.end(); ++it) {
			RangeOfDataForRTII& rangeData = std::get<0>(*it);
			void*& pcBegin = std::get<0>(rangeData);
			void*& pcEnd = std::get<1>(rangeData);
			if ((pcBegin == pBegin) && (pcEnd == pEnd)) {
				//return std::get<1>(*it);
				m_vecRangesSymbolsAddressesCache.erase(it);
			}
		}
	}

	void* pTypeInfo = FindTypeInfoAddressFromRange(pBegin, pEnd);
	if (!pTypeInfo) {
		return vecData;
	}

	PTYPEDESCRIPTOR pTypeDesc = reinterpret_cast<PTYPEDESCRIPTOR>(reinterpret_cast<char*>(pTypeInfo) - (sizeof(void*) * 2));

	std::unique_ptr<char[]> mem_szSymbolBuffer(new char[RTTI_DEFAULT_MAX_SYMBOL_LENGTH]); // 0x7FF - Max for MSVC
	char* szSymbolBuffer = mem_szSymbolBuffer.get();
	if (!szSymbolBuffer) {
		return vecData;
	}
	memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);

	// Converting
	char szVTable[sizeof(void*) + 1];
	memset(szVTable, 0, sizeof(szVTable));
	for (unsigned char i = 0; i < sizeof(void*); ++i) {
		char cByte = reinterpret_cast<char*>(&(pTypeDesc->pVTable))[i];
		if (cByte == '\x00') {
			cByte = '\x2A';
		}
		szVTable[i] = cByte;
	}

	// Finding
	void* pLastType = pBegin;
	while (pLastType < pEnd) {
		void* pType = FindSignature(reinterpret_cast<unsigned char*>(pLastType), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szVTable);
		if (!pType) {
			break;
		}

		// Converting
#ifdef _WIN64
		uintptr_t unTypeOffsetTemp = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(pType) - reinterpret_cast<uintptr_t>(pBegin));
		unsigned int unTypeOffset = (*(reinterpret_cast<unsigned int*>(&unTypeOffsetTemp)));

		char szTypeOffset[sizeof(int) + 1];
		memset(szTypeOffset, 0, sizeof(szTypeOffset));
		for (unsigned char i = 0; i < sizeof(int); ++i) {
			char cByte = reinterpret_cast<char*>(&unTypeOffset)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
		}
			szTypeOffset[i] = cByte;
	}
#elif _WIN32
		char szType[sizeof(void*) + 1];
		memset(szType, 0, sizeof(szType));
		for (unsigned char i = 0; i < sizeof(void*); ++i) {
			char cByte = reinterpret_cast<char*>(&pType)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
			}
			szType[i] = cByte;
		}
#endif

		// Finding
		void* pLastReference = pBegin;
		while (pLastReference < pEnd) {
#ifdef _WIN64
			void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szTypeOffset);
#elif _WIN32
			void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szType);
#endif
			if (!pReference) {
				break;
			}

#ifdef _WIN64
			if (!(((*(reinterpret_cast<unsigned int*>(pReference))) != 0) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(pReference) + sizeof(int))) != 0)))) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}
#elif _WIN32
			if (!(((*(reinterpret_cast<unsigned int*>(pReference))) >= reinterpret_cast<unsigned int>(pBegin)) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(pReference) + sizeof(int))) >= reinterpret_cast<unsigned int>(pBegin))))) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}
#endif

			void* pLocation = reinterpret_cast<char*>(pReference) - (sizeof(int) * 3);

			char szLocation[sizeof(void*) + 1];
			memset(szLocation, 0, sizeof(szLocation));
			for (unsigned char i = 0; i < sizeof(void*); ++i) {
				char cByte = reinterpret_cast<char*>(&pLocation)[i];
				if (cByte == '\x00') {
					cByte = '\x2A';
				}
				szLocation[i] = cByte;
			}

			void* pMeta = FindSignature(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szLocation);
			if (!pMeta) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}

			PTYPEDESCRIPTOR pTypeDescriptor = reinterpret_cast<PTYPEDESCRIPTOR>(pType);
			char* pSymbol = &(pTypeDescriptor->Name);

			char* pNewSymbol = pSymbol;
			if (pSymbol[4] == '?') {
				pNewSymbol = pSymbol + 1;
			}
			else if (pSymbol[0] == '.') {
				pNewSymbol = pSymbol + 4;
			}
			else if (pSymbol[0] == '?') {
				pNewSymbol = pSymbol + 2;
			}
			else {
				break;
			}

			memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);
			sprintf_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH, "??_7%s6B@", pNewSymbol);
			if (!((UnDecorateSymbolName(szSymbolBuffer, szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1, UNDNAME_NAME_ONLY | UNDNAME_NO_SPECIAL_SYMS)) != 0)) {
				break;
			}

			size_t unSymbolBufferLength = strnlen_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1);

			void* pPattern1 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "::`anonymous namespace'");
			if (pPattern1) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern1) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 24);
			}

			void* pPattern2 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "::`vftable'");
			if (pPattern2) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern2) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 12);
			}

			void* pPattern3 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "const ");
			if (pPattern3) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern3) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 7);
			}

			vecData.push_back(SymbolAddress(szSymbolBuffer, reinterpret_cast<void*>(reinterpret_cast<unsigned char*>(pMeta) + sizeof(void*))));

			if (m_bMinIters) {
				break;
			}

			pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
		}

		pLastType = reinterpret_cast<void*>(reinterpret_cast<char*>(pType) + sizeof(void*));
	}

	if (m_bCaching && m_bRangesCaching && (vecData.size() > 0)) {
		m_vecRangesSymbolsAddressesCache.push_back(RangeSymbolsAddresses(RangeOfDataForRTII(pBegin, pEnd), vecData));
	}

	return vecData;
}

vecSymbolsOffsets RTTI::GetVTablesOffsetsFromRange(void* pBegin, void* pEnd) {
	vecSymbolsOffsets vecData;

	if (m_bCaching && m_bRangesCaching) {
		for (vecRangesSymbolsOffsets::iterator it = m_vecRangesSymbolsOffsetsCache.begin(); it != m_vecRangesSymbolsOffsetsCache.end(); ++it) {
			RangeOfDataForRTII& rangeData = std::get<0>(*it);
			void*& pcBegin = std::get<0>(rangeData);
			void*& pcEnd = std::get<1>(rangeData);
			if ((pcBegin == pBegin) && (pcEnd == pEnd)) {
				//return std::get<1>(*it);
				m_vecRangesSymbolsOffsetsCache.erase(it);
			}
		}
	}

	void* pTypeInfo = FindTypeInfoAddressFromRange(pBegin, pEnd);
	if (!pTypeInfo) {
		return vecData;
	}

	PTYPEDESCRIPTOR pTypeDesc = reinterpret_cast<PTYPEDESCRIPTOR>(reinterpret_cast<char*>(pTypeInfo) - (sizeof(void*) * 2));

	std::unique_ptr<char[]> mem_szSymbolBuffer(new char[RTTI_DEFAULT_MAX_SYMBOL_LENGTH]); // 0x7FF - Max for MSVC
	char* szSymbolBuffer = mem_szSymbolBuffer.get();
	if (!szSymbolBuffer) {
		return vecData;
	}
	memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);

	// Converting
	char szVTable[sizeof(void*) + 1];
	memset(szVTable, 0, sizeof(szVTable));
	for (unsigned char i = 0; i < sizeof(void*); ++i) {
		char cByte = reinterpret_cast<char*>(&(pTypeDesc->pVTable))[i];
		if (cByte == '\x00') {
			cByte = '\x2A';
		}
		szVTable[i] = cByte;
	}

	// Finding
	void* pLastType = pBegin;
	while (pLastType < pEnd) {
		void* pType = FindSignature(reinterpret_cast<unsigned char*>(pLastType), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szVTable);
		if (!pType) {
			break;
		}

		// Converting
#ifdef _WIN64
		uintptr_t unTypeOffsetTemp = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(pType) - reinterpret_cast<uintptr_t>(pBegin));
		unsigned int unTypeOffset = (*(reinterpret_cast<unsigned int*>(&unTypeOffsetTemp)));

		char szTypeOffset[sizeof(int) + 1];
		memset(szTypeOffset, 0, sizeof(szTypeOffset));
		for (unsigned char i = 0; i < sizeof(int); ++i) {
			char cByte = reinterpret_cast<char*>(&unTypeOffset)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
			}
			szTypeOffset[i] = cByte;
		}
#elif _WIN32
		char szType[sizeof(void*) + 1];
		memset(szType, 0, sizeof(szType));
		for (unsigned char i = 0; i < sizeof(void*); ++i) {
			char cByte = reinterpret_cast<char*>(&pType)[i];
			if (cByte == '\x00') {
				cByte = '\x2A';
			}
			szType[i] = cByte;
		}
#endif

		// Finding
		void* pLastReference = pBegin;
		while (pLastReference < pEnd) {
#ifdef _WIN64
			void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szTypeOffset);
#elif _WIN32
			void* pReference = FindSignature(reinterpret_cast<unsigned char*>(pLastReference), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szType);
#endif
			if (!pReference) {
				break;
			}

#ifdef _WIN64
			if (!(((*(reinterpret_cast<unsigned int*>(pReference))) != 0) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(pReference) + sizeof(int))) != 0)))) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}
#elif _WIN32
			if (!(((*(reinterpret_cast<unsigned int*>(pReference))) >= reinterpret_cast<unsigned int>(pBegin)) && ((*(reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(pReference) + sizeof(int))) >= reinterpret_cast<unsigned int>(pBegin))))) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}
#endif

			void* pLocation = reinterpret_cast<char*>(pReference) - (sizeof(int) * 3);

			char szLocation[sizeof(void*) + 1];
			memset(szLocation, 0, sizeof(szLocation));
			for (unsigned char i = 0; i < sizeof(void*); ++i) {
				char cByte = reinterpret_cast<char*>(&pLocation)[i];
				if (cByte == '\x00') {
					cByte = '\x2A';
				}
				szLocation[i] = cByte;
			}

			void* pMeta = FindSignature(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szLocation);
			if (!pMeta) {
				pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
				continue;
			}

			PTYPEDESCRIPTOR pTypeDescriptor = reinterpret_cast<PTYPEDESCRIPTOR>(pType);
			char* pSymbol = &(pTypeDescriptor->Name);

			char* pNewSymbol = pSymbol;
			if (pSymbol[4] == '?') {
				pNewSymbol = pSymbol + 1;
			}
			else if (pSymbol[0] == '.') {
				pNewSymbol = pSymbol + 4;
			}
			else if (pSymbol[0] == '?') {
				pNewSymbol = pSymbol + 2;
			}
			else {
				break;
			}

			memset(szSymbolBuffer, 0, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH);
			sprintf_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH, "??_7%s6B@", pNewSymbol);
			if (!((UnDecorateSymbolName(szSymbolBuffer, szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1, UNDNAME_NAME_ONLY | UNDNAME_NO_SPECIAL_SYMS)) != 0)) {
				break;
			}

			size_t unSymbolBufferLength = strnlen_s(szSymbolBuffer, sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1);

			void* pPattern1 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "::`anonymous namespace'");
			if (pPattern1) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern1) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 24);
			}

			void* pPattern2 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "::`vftable'");
			if (pPattern2) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern2) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 12);
			}

			void* pPattern3 = FindSignature(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + unSymbolBufferLength)), "const ");
			if (pPattern3) {
				uintptr_t rva = reinterpret_cast<uintptr_t>(pPattern3) - reinterpret_cast<uintptr_t>(szSymbolBuffer);
				szSymbolBuffer[rva] = 0;
				memset(szSymbolBuffer + rva, 0, 7);
			}

			vecData.push_back(SymbolOffset(szSymbolBuffer, reinterpret_cast<uintptr_t>(reinterpret_cast<unsigned char*>(pMeta) + sizeof(void*) - reinterpret_cast<uintptr_t>(pBegin))));

			if (m_bMinIters) {
				break;
			}

			pLastReference = reinterpret_cast<void*>(reinterpret_cast<char*>(pReference) + sizeof(int));
		}

		pLastType = reinterpret_cast<void*>(reinterpret_cast<char*>(pType) + sizeof(void*));
	}

	if (m_bCaching && m_bRangesCaching && (vecData.size() > 0)) {
		m_vecRangesSymbolsOffsetsCache.push_back(RangeSymbolsOffsets(RangeOfDataForRTII(pBegin, pEnd), vecData));
	}

	return vecData;
}

vecSymbolsAddresses RTTI::GetVTablesAddressesFromModule(HMODULE hModule) {
	vecSymbolsAddresses vecData;

	if (!hModule) {
		return vecData;
	}

	if (m_bCaching && m_bModulesCaching) {
		for (vecModulesSymbolsAddresses::iterator it = m_vecModulesSymbolsAddressesCache.begin(); it != m_vecModulesSymbolsAddressesCache.end(); ++it) {
			HMODULE& hMod = std::get<0>(*it);
			if (hMod == hModule) {
				return std::get<1>(*it);
			}
		}
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return vecData;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);
	
#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	GetRealModuleDimensions(reinterpret_cast<void**>(&pBegin), &pEnd);
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	vecData = GetVTablesAddressesFromRange(reinterpret_cast<void*>(pBegin), pEnd);

	if (m_bCaching && m_bModulesCaching && (vecData.size() > 0)) {
		m_vecModulesSymbolsAddressesCache.push_back(ModuleSymbolsAddresses(hModule, vecData));
	}

	return vecData;
}

vecSymbolsOffsets RTTI::GetVTablesOffsetsFromModule(HMODULE hModule) {
	vecSymbolsOffsets vecData;

	if (m_bCaching && m_bModulesCaching) {
		for (vecModulesSymbolsOffsets::iterator it = m_vecModulesSymbolsOffsetsCache.begin(); it != m_vecModulesSymbolsOffsetsCache.end(); ++it) {
			HMODULE& hMod = std::get<0>(*it);
			if (hMod == hModule) {
				return std::get<1>(*it);
			}
		}
	}

	if (!hModule) {
		return vecData;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return vecData;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	GetRealModuleDimensions(reinterpret_cast<void**>(&pBegin), &pEnd);
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	vecData = GetVTablesOffsetsFromRange(reinterpret_cast<void*>(pBegin), pEnd);

	if (m_bCaching && m_bModulesCaching && (vecData.size() > 0)) {
		m_vecModulesSymbolsOffsetsCache.push_back(ModuleSymbolsOffsets(hModule, vecData));
	}

	return vecData;
}

// Finding in cache
void* RTTI::GetVTableAddressFromRangeCache(void* pBegin, void* pEnd, const char* szClassName) {
	for (vecRangesSymbolsAddresses::iterator it = m_vecRangesSymbolsAddressesCache.begin(); it != m_vecRangesSymbolsAddressesCache.end(); ++it) {
		RangeOfDataForRTII& dataRange = std::get<0>(*it);
		void*& pcBegin = std::get<0>(dataRange);
		void*& pcEnd = std::get<1>(dataRange);
		if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
			vecSymbolsAddresses& vecSymbols = std::get<1>(*it);
			for (vecSymbolsAddresses::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
				std::string& str_SymbolName = std::get<0>(*sit);
				if (strcmp(str_SymbolName.data(), szClassName) == 0) {
					return std::get<1>(*sit);
				}
			}
		}
	}
	return nullptr;
}

uintptr_t RTTI::GetVTableOffsetFromRangeCache(void* pBegin, void* pEnd, const char* szClassName) {
	for (vecRangesSymbolsOffsets::iterator it = m_vecRangesSymbolsOffsetsCache.begin(); it != m_vecRangesSymbolsOffsetsCache.end(); ++it) {
		RangeOfDataForRTII& dataRange = std::get<0>(*it);
		void*& pcBegin = std::get<0>(dataRange);
		void*& pcEnd = std::get<1>(dataRange);
		if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
			vecSymbolsOffsets& vecSymbols = std::get<1>(*it);
			for (vecSymbolsOffsets::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
				std::string& str_SymbolName = std::get<0>(*sit);
				if (strcmp(str_SymbolName.data(), szClassName) == 0) {
					return std::get<1>(*sit);
				}
			}
		}
	}
	return 0;
}

void* RTTI::GetVTableAddressFromModuleCache(HMODULE hModule, const char* szClassName) {
	for (vecModulesSymbolsAddresses::iterator it = m_vecModulesSymbolsAddressesCache.begin(); it != m_vecModulesSymbolsAddressesCache.end(); ++it) {
		HMODULE& hMod = std::get<0>(*it);
		if (hMod == hModule) {
			vecSymbolsAddresses& vecSymbols = std::get<1>(*it);
			for (vecSymbolsAddresses::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
				std::string& str_SymbolName = std::get<0>(*sit);
				if (strcmp(str_SymbolName.data(), szClassName) == 0) {
					return std::get<1>(*sit);
				}
			}
		}
	}
	return nullptr;
}

uintptr_t RTTI::GetVTableOffsetFromModuleCache(HMODULE hModule, const char* szClassName) {
	for (vecModulesSymbolsOffsets::iterator it = m_vecModulesSymbolsOffsetsCache.begin(); it != m_vecModulesSymbolsOffsetsCache.end(); ++it) {
		HMODULE& hMod = std::get<0>(*it);
		if (hMod == hModule) {
			vecSymbolsOffsets& vecSymbols = std::get<1>(*it);
			for (vecSymbolsOffsets::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
				std::string& str_SymbolName = std::get<0>(*sit);
				if (strcmp(str_SymbolName.data(), szClassName) == 0) {
					return std::get<1>(*sit);
				}
			}
		}
	}
	return 0;
}
