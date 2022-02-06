#include "RTTI.h"

static void* FindData(void* pBeginAddress, void* pEndAddress, void* pData, size_t unDataSize) {
	unsigned char* pBegin = reinterpret_cast<unsigned char*>(pBeginAddress);
	const unsigned char* pEnd = reinterpret_cast<unsigned char*>(pEndAddress);
	const uintptr_t unEnd = reinterpret_cast<uintptr_t>(pEnd) - unDataSize;
	for (uintptr_t i = 0; (i < reinterpret_cast<uintptr_t>(pEnd)) && (pBegin <= reinterpret_cast<void*>(unEnd)); ++i, ++pBegin) {
		uintptr_t unNextStart = 0;
		uintptr_t unResult = 0;
		bool bSuccess = true;
		for (size_t j = 0; j < unDataSize; ++j) {
			if (reinterpret_cast<unsigned char*>(pData)[j] == 0x2A) {
				continue;
			}
			const unsigned char unSymbol = pBegin[j];
			if (unSymbol == reinterpret_cast<unsigned char*>(pData)[0]) {
				unNextStart = j;
			}
			if (unSymbol != reinterpret_cast<unsigned char*>(pData)[j]) {
				unResult = unNextStart;
				bSuccess = false;
				break;
			}
		}
		if (bSuccess) {
			return reinterpret_cast<void*>(pBegin);
		} else {
			i += unResult;
		}
	}
	return nullptr;
}

void* FindRTTI(void* pBegin, void* pEnd, const char* szName) {
	if (!pBegin || !pEnd || !szName) {
		return nullptr;
	}
	void* pType = FindData(pBegin, pEnd, const_cast<char*>(szName), strnlen_s(szName, 0x7FF));
	if (!pType) {
		return nullptr;
	}
	void* pLastReference = pBegin;
	while (pLastReference < pEnd) {
#ifdef _WIN64
		uintptr_t unTypeOffsetTemp = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(pType) - sizeof(void*) * 2 - reinterpret_cast<uintptr_t>(pBegin));
		uint32_t unTypeOffset = (*(reinterpret_cast<unsigned int*>(&unTypeOffsetTemp)));
		char* pReference = reinterpret_cast<char*>(FindData(pLastReference, pEnd, &unTypeOffset, sizeof(unTypeOffset)));
#elif _WIN32
		char* pTypeDescriptor = reinterpret_cast<char*>(pType) - sizeof(void*) * 2;
		char* pReference = reinterpret_cast<char*>(FindData(pLastReference, pEnd, &pTypeDescriptor, sizeof(pTypeDescriptor)));
#endif
		if (!pReference) {
			break;
		}
#ifdef _WIN64
		if (!(((*(reinterpret_cast<uint32_t*>(pReference))) != 0) && ((*(reinterpret_cast<uint32_t*>(pReference + sizeof(uint32_t))) != 0)))) {
			pLastReference = pReference + sizeof(void*);
			continue;
		}
#elif _WIN32
		if (!(((*(reinterpret_cast<uint32_t*>(pReference))) >= reinterpret_cast<uint32_t>(pBegin)) && ((*(reinterpret_cast<uint32_t*>(pReference + sizeof(uint32_t))) >= reinterpret_cast<uint32_t>(pBegin))))) {
			pLastReference = pReference + sizeof(void*);
			continue;
		}
#endif
		char* pLocation = pReference - sizeof(uint32_t) * 3;
		char* pMeta = reinterpret_cast<char*>(FindData(pBegin, pEnd, &pLocation, sizeof(pLocation)));
		if (!pMeta) {
			pLastReference = pReference + sizeof(void*);
			continue;
		}
		return reinterpret_cast<void*>(pMeta + sizeof(void*));
	}
	return nullptr;
}

void* FindRTTI(HMODULE hModule, const char* szName) {
	if (!hModule || !szName) {
		return nullptr;
	}
	MODULEINFO modinf;
	if (!GetModuleInformation(reinterpret_cast<HANDLE>(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return nullptr;
	}
	char* pBegin = reinterpret_cast<char*>(modinf.lpBaseOfDll);
	return FindRTTI(pBegin, pBegin + modinf.SizeOfImage, szName);
}

void* FindRTTI(const char* szModule, const char* szName) {
	if (!szModule || !szName) {
		return nullptr;
	}
	HMODULE hModule = GetModuleHandleA(szModule);
	if (!hModule) {
		return nullptr;
	}
	return FindRTTI(hModule, szName);
}

void* FindRTTI(const wchar_t* szModule, const char* szName) {
	if (!szModule || !szName) {
		return nullptr;
	}
	HMODULE hModule = GetModuleHandleW(szModule);
	if (!hModule) {
		return nullptr;
	}
	return FindRTTI(hModule, szName);
}
