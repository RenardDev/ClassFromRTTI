#include "RTTI.h"

#ifdef RTTI_EXPERIMENTAL_FEATURES
#define LDR_DLL_NOTIFICATION_REASON_LOADED   1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2

// General definitions
typedef const PUNICODE_STRING PCUNICODE_STRING;
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG Flags;                    // Reserved.
	PCUNICODE_STRING FullDllName;   // The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   // The base file name of the DLL module.
	PVOID DllBase;                  // A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              // The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;
typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG Flags;                    // Reserved.
	PCUNICODE_STRING FullDllName;   // The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   // The base file name of the DLL module.
	PVOID DllBase;                  // A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              // The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;
typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;
typedef const PLDR_DLL_NOTIFICATION_DATA PCLDR_DLL_NOTIFICATION_DATA;
typedef void(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(_In_ ULONG NotificationReason, _In_ PCLDR_DLL_NOTIFICATION_DATA NotificationData, _In_opt_ PVOID Context);
typedef NTSTATUS(NTAPI* fnLdrRegisterDllNotification)(_In_ ULONG Flags, _In_ PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction, _In_opt_ PVOID Context, _Out_ PVOID* Cookie);
typedef NTSTATUS(NTAPI* fnLdrUnregisterDllNotification)(_In_ PVOID Cookie);
#endif // RTTI_EXPERIMENTAL_FEATURES
typedef struct _TYPEDESCRIPTOR {
	void* pVFTable;
	void* pSpare;
	char Name;
} TYPEDESCRIPTOR, *PTYPEDESCRIPTOR;

// Helpful functions
static void* FindSigLinear(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature, uintptr_t unOffset = 0, bool bToAbsoluteAddress = false) {
	size_t unSignatureLength = strlen(reinterpret_cast<const char*>(szSignature));

	for (uintptr_t i = 0; i < reinterpret_cast<uintptr_t>(pEnd); i++, pBegin++) {
		uintptr_t unNextStart = 0;
		uintptr_t unResult = 0;
		bool bSuccess = true;
		for (size_t j = 0; j < unSignatureLength; j++) {
			if (reinterpret_cast<const unsigned char*>(szSignature)[j] == 0x2A) {
				continue;
			}
			unsigned char ucSymbol = pBegin[j];
			if (ucSymbol == reinterpret_cast<const unsigned char*>(szSignature)[0]) {
				unNextStart = j;
			}
			if (ucSymbol != reinterpret_cast<const unsigned char*>(szSignature)[j]) {
				unResult = unNextStart;
				bSuccess = false;
				break;
			}
		}
		if (bSuccess) {
			if (!bToAbsoluteAddress) {
				return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pBegin) + unOffset);
			}
			else {
				return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pBegin) + unOffset + sizeof(uintptr_t) + (*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(pBegin) + unOffset)));
			}
			break;
		}
		else {
			i += unResult;
		}
	}

	return nullptr;
}

static void* FindSigSSE2(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature, uintptr_t unOffset = 0, bool bToAbsoluteAddress = false) {
	size_t unSignatureLength = strlen(reinterpret_cast<const char*>(szSignature));
	uintptr_t unSignaturesCount = static_cast<uintptr_t>(ceil(static_cast<float>(unSignatureLength) / 16.f));
	unsigned int pSignatures[32];
	memset(pSignatures, 0, sizeof(pSignatures));
	for (uintptr_t i = 0; i < unSignaturesCount; ++i) {
		for (char j = static_cast<char>(strnlen(reinterpret_cast<const char*>(szSignature) + i * 16, 16)) - 1; j >= 0; --j) {
			if (reinterpret_cast<const unsigned char*>(szSignature)[i * 16 + j] != 0x2A) {
				pSignatures[i] |= 1 << j;
			}
		}
	}

	__m128i xmm0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(szSignature));

	for (; pBegin != pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 64), _MM_HINT_NTA)) {
		if (pBegin > pEnd) {
			break;
		}
		if (reinterpret_cast<const unsigned char*>(szSignature)[0] == pBegin[0]) {
			if ((_mm_movemask_epi8(_mm_cmpeq_epi8(xmm0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(pBegin)))) & pSignatures[0]) == pSignatures[0]) {
				for (uintptr_t i = 1; i < unSignaturesCount; ++i) {
					if ((_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(pBegin + i * 16)), _mm_loadu_si128(reinterpret_cast<const __m128i*>(szSignature + i * 16)))) & pSignatures[i]) == pSignatures[i]) {
						if ((i + 1) == unSignaturesCount) {
							if (bToAbsoluteAddress) {
								return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pBegin + unOffset) + sizeof(uintptr_t) + (*reinterpret_cast<uintptr_t*>(pBegin + unOffset)));
							}
							return reinterpret_cast<void*>(pBegin + unOffset);
						}
					}
				}
				if (bToAbsoluteAddress) {
					return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pBegin + unOffset) + sizeof(uintptr_t) + (*reinterpret_cast<uintptr_t*>(pBegin + unOffset)));
				}
				return reinterpret_cast<void*>(pBegin + unOffset);
			}
		}
	}

	return nullptr;
}

static void* FindSigAVX2(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature, uintptr_t unOffset = 0, bool bToAbsoluteAddress = false) {
	size_t unSignatureLength = strlen(reinterpret_cast<const char*>(szSignature));
	uintptr_t unSignaturesCount = static_cast<uintptr_t>(ceil(static_cast<float>(unSignatureLength) / 32.f));
	unsigned int pSignatures[64];
	memset(pSignatures, 0, sizeof(pSignatures));
	for (uintptr_t i = 0; i < unSignaturesCount; ++i) {
		for (char j = static_cast<char>(strnlen(reinterpret_cast<const char*>(szSignature) + i * 32, 32)) - 1; j >= 0; --j) {
			if (reinterpret_cast<const unsigned char*>(szSignature)[i * 32 + j] != 0x2A) {
				pSignatures[i] |= 1 << j;
			}
		}
	}

	__m256i xmm0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(szSignature));

	for (; pBegin != pEnd; _mm_prefetch(reinterpret_cast<const char*>(++pBegin + 128), _MM_HINT_NTA)) {
		if (pBegin > pEnd) {
			break;
		}
		if (reinterpret_cast<const unsigned char*>(szSignature)[0] == pBegin[0]) {
			if ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(xmm0, _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pBegin)))) & pSignatures[0]) == pSignatures[0]) {
				for (uintptr_t i = 1; i < unSignaturesCount; ++i) {
					if ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(pBegin + i * 32)), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(szSignature + i * 32)))) & pSignatures[i]) == pSignatures[i]) {
						if ((i + 1) == unSignaturesCount) {
							if (bToAbsoluteAddress) {
								return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pBegin + unOffset) + sizeof(uintptr_t) + (*reinterpret_cast<uintptr_t*>(pBegin + unOffset)));
							}
							return reinterpret_cast<void*>(pBegin + unOffset);
						}
					}
				}
				if (bToAbsoluteAddress) {
					return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pBegin + unOffset) + sizeof(uintptr_t) + (*reinterpret_cast<uintptr_t*>(pBegin + unOffset)));
				}
				return reinterpret_cast<void*>(pBegin + unOffset);
			}
		}
	}

	return nullptr;
}

static bool MapFile(const char* szFilePath, PHANDLE phFile, PHANDLE phFileMap, LPVOID* ppMap) {
	HANDLE hFile = CreateFileA(szFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		return false;
	}

	HANDLE hFileMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (hFileMap == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return false;
	}

	LPVOID pMap = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		CloseHandle(hFileMap);
		CloseHandle(hFile);
		return false;
	}

	if (phFile) {
		*phFile = hFile;
	}
	if (phFileMap) {
		*phFileMap = hFileMap;
	}
	if (ppMap) {
		*ppMap = pMap;
	}

	return true;
}

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
static bool GetRealModuleDimensions(HMODULE hModule, void** ppBegin, void **ppEnd) {
	if (!hModule) {
		return false;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return false;
	}

	uintptr_t unBegin = reinterpret_cast<uintptr_t>(modinf.lpBaseOfDll);
	uintptr_t unEnd = unBegin + modinf.SizeOfImage;

	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(modinf.lpBaseOfDll);
	PIMAGE_NT_HEADERS pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pDH) + pDH->e_lfanew);
	PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
	PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(pFH) + sizeof(IMAGE_FILE_HEADER) + pFH->SizeOfOptionalHeader);

	uintptr_t unLastBegin = unBegin;
	uintptr_t unLastEnd = unEnd;
	for (unsigned long i = 0; i < pFH->NumberOfSections; ++i, ++pFirstSection) {
		if (pFirstSection->Characteristics & (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ)) {
			uintptr_t unSectionBegin = unBegin + pFirstSection->VirtualAddress;
			uintptr_t unSectionEnd = unBegin + pFirstSection->VirtualAddress + pFirstSection->Misc.VirtualSize;

			//unLastBegin = max(unBegin, unSectionBegin);
			if (unBegin > unSectionBegin) {
				unLastBegin = unBegin;
			}
			else {
				unLastBegin = unSectionBegin;
			}
			//unLastEnd = min(unEnd, unSectionEnd);
			if (unEnd < unSectionEnd) {
				unLastEnd = unEnd;
			}
			else {
				unLastEnd = unSectionEnd;
			}
		}
	}

	if (ppBegin) {
		*ppBegin = reinterpret_cast<void*>(unBegin);
	}
	if (ppEnd) {
		*ppEnd = reinterpret_cast<void*>(unEnd);
	}

	return true;
}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

static bool MapNewFile(const char* szFilePath, PHANDLE phFile, PHANDLE phFileMap, LPVOID* ppMap, DWORD dwNumberOfBytesToMap) {
	HANDLE hFile = CreateFileA(szFilePath, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		return false;
	}

	if (SetFilePointer(hFile, dwNumberOfBytesToMap, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		return false;
	}

	if (!SetEndOfFile(hFile)) {
		return false;
	}

	HANDLE hFileMap = CreateFileMappingA(hFile, nullptr, PAGE_READWRITE, 0, 0, nullptr);
	if (hFileMap == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return false;
	}

	LPVOID pMap = MapViewOfFile(hFileMap, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		CloseHandle(hFileMap);
		CloseHandle(hFile);
		return false;
	}

	if (phFile) {
		*phFile = hFile;
	}
	if (phFileMap) {
		*phFileMap = hFileMap;
	}
	if (ppMap) {
		*ppMap = pMap;
	}

	return true;
}

static void UnMapFile(HANDLE hFile, HANDLE hFileMap, LPVOID pMap) {
	if (pMap) {
		UnmapViewOfFile(pMap);
	}
	if (hFileMap) {
		CloseHandle(hFileMap);
	}
	if (hFile) {
		CloseHandle(hFile);
	}
}

// RTTI Processing
#ifdef RTTI_EXPERIMENTAL_FEATURES
typedef struct _SHORT_INFO {
	RTTI* pRTTI;
	HMODULE hActiveModule;
	HANDLE hThread;
} SHORT_INFO, *PSHORT_INFO;

static DWORD WINAPI RTTI_OnLoadDLL(LPVOID lpThreadParameter) {
	PSHORT_INFO pShortInfo = reinterpret_cast<PSHORT_INFO>(lpThreadParameter);
	RTTI* pRTTI = pShortInfo->pRTTI;
	if (pRTTI->IsCacheEnabled()) {
		vecSymbolsAddresses m_vecFullSymbolsAddresses = pRTTI->GetVTablesAddressesFromModule(pShortInfo->hActiveModule);
		pvecModulesSymbolsAddresses m_pvecModulesSymbolsAddresses = pRTTI->GetModulesAddressesCache();
		for (vecModulesSymbolsAddresses::iterator it = m_pvecModulesSymbolsAddresses->begin(); it != m_pvecModulesSymbolsAddresses->end(); ++it) {
			if (std::get<0>(*it) == pShortInfo->hActiveModule) {
				vecSymbolsAddresses& m_vecCurrentSymbolsAddresses = std::get<1>(*it);
				if (m_vecCurrentSymbolsAddresses.size() < m_vecFullSymbolsAddresses.size()) {
					m_vecCurrentSymbolsAddresses.clear();
					m_vecCurrentSymbolsAddresses = m_vecFullSymbolsAddresses;
				}
				break;
			}
		}
		vecSymbolsOffsets m_vecFullSymbolsOffsets = pRTTI->GetVTablesOffsetsFromModule(pShortInfo->hActiveModule);
		pvecModulesSymbolsOffsets m_pvecModulesSymbolsOffsets = pRTTI->GetModulesOffsetsCache();
		for (vecModulesSymbolsOffsets::iterator it = m_pvecModulesSymbolsOffsets->begin(); it != m_pvecModulesSymbolsOffsets->end(); ++it) {
			if (std::get<0>(*it) == pShortInfo->hActiveModule) {
				vecSymbolsOffsets& m_vecCurrentSymbolsOffsets = std::get<1>(*it);
				if (m_vecCurrentSymbolsOffsets.size() < m_vecFullSymbolsOffsets.size()) {
					m_vecCurrentSymbolsOffsets.clear();
					m_vecCurrentSymbolsOffsets = m_vecFullSymbolsOffsets;
				}
				break;
			}
		}
	}
	delete pShortInfo;
	return 0;
}

static DWORD WINAPI RTTI_OnUnloadDLL(LPVOID lpThreadParameter) {
	PSHORT_INFO pShortInfo = reinterpret_cast<PSHORT_INFO>(lpThreadParameter);
	RTTI* pRTTI = pShortInfo->pRTTI;
	if (pRTTI->IsCacheEnabled()) {
		pvecModulesSymbolsAddresses m_pvecModulesSymbolsAddresses = pRTTI->GetModulesAddressesCache();
		for (vecModulesSymbolsAddresses::iterator it = m_pvecModulesSymbolsAddresses->begin(); it != m_pvecModulesSymbolsAddresses->end(); ++it) {
			if (std::get<0>(*it) == pShortInfo->hActiveModule) {
				m_pvecModulesSymbolsAddresses->erase(it);
				break;
			}
		}
		pvecModulesSymbolsOffsets m_pvecModulesSymbolsOffsets = pRTTI->GetModulesOffsetsCache();
		for (vecModulesSymbolsOffsets::iterator it = m_pvecModulesSymbolsOffsets->begin(); it != m_pvecModulesSymbolsOffsets->end(); ++it) {
			if (std::get<0>(*it) == pShortInfo->hActiveModule) {
				m_pvecModulesSymbolsOffsets->erase(it);
				break;
			}
		}
	}

	for (std::vector<HANDLE>::iterator it = pRTTI->m_vecThreads.begin(); it != pRTTI->m_vecThreads.end(); ++it) {
		if (pShortInfo->hThread == *it) {
			pRTTI->m_vecThreads.erase(it);
			//CloseHandle(*it);
		}
	}

	delete pShortInfo;
	return 0;
}

static void CALLBACK RTTI_OnDLLNotification(_In_ ULONG NotificationReason, _In_ PCLDR_DLL_NOTIFICATION_DATA NotificationData, _In_opt_ PVOID Context) {
	RTTI* pRTTI = reinterpret_cast<RTTI*>(Context);

	if (pRTTI->m_vecThreads.size() > 0) {
		return;
	}

	if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED) {
		PSHORT_INFO pShortInfo = new SHORT_INFO;
		pShortInfo->pRTTI = pRTTI;
		pShortInfo->hActiveModule = reinterpret_cast<HMODULE>(NotificationData->Loaded.DllBase);
		HANDLE hThread = CreateThread(nullptr, 0, RTTI_OnLoadDLL, pShortInfo, CREATE_SUSPENDED, nullptr);
		if (hThread) {
			pShortInfo->hThread = hThread;
			pRTTI->m_vecThreads.push_back(hThread);
			ResumeThread(hThread);
		}
		else {
			delete pShortInfo;
		}
		return;
	}

	if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_UNLOADED) {
		PSHORT_INFO pShortInfo = new SHORT_INFO;
		pShortInfo->pRTTI = pRTTI;
		pShortInfo->hActiveModule = reinterpret_cast<HMODULE>(NotificationData->Unloaded.DllBase);
		HANDLE hThread = CreateThread(nullptr, 0, RTTI_OnUnloadDLL, pShortInfo, CREATE_SUSPENDED, nullptr);
		if (hThread) {
			pShortInfo->hThread = hThread;
			pRTTI->m_vecThreads.push_back(hThread);
			ResumeThread(hThread);
		}
		else {
			delete pShortInfo;
		}
		return;
	}
}
#endif // RTTI_EXPERIMENTAL_FEATURES

//---------------------------------------------------------------------------------
// RTTI interface
//---------------------------------------------------------------------------------
#ifdef RTTI_EXPERIMENTAL_FEATURES
RTTI::RTTI(bool bAutoScanIntoCache, bool bCaching, bool bRangeCaching, bool bModulesCaching, bool bFilesCaching) {
#else // RTTI_EXPERIMENTAL_FEATURES
RTTI::RTTI(bool bCaching, bool bRangeCaching, bool bModulesCaching, bool bFilesCaching) {
#endif // !RTTI_EXPERIMENTAL_FEATURES
	m_bAvailableSSE2 = false;
	m_bAvailableAVX2 = false;
#ifdef RTTI_EXPERIMENTAL_FEATURES
	m_pLdrRegisterDllNotification = nullptr;
	m_pLdrUnregisterDllNotification = nullptr;
	m_pCookie = nullptr;
#endif // RTTI_EXPERIMENTAL_FEATURES
	m_bCaching = bCaching;
	m_bRangesCaching = bRangeCaching;
	m_bModulesCaching = bModulesCaching;
#ifdef RTTI_EXPERIMENTAL_FEATURES
	m_bFilesCaching = bFilesCaching;
#endif // RTTI_EXPERIMENTAL_FEATURES
	m_vecRangesSymbolsAddressesCache.clear();
	m_vecModulesSymbolsAddressesCache.clear();
	m_vecRangesSymbolsOffsetsCache.clear();
	m_vecModulesSymbolsOffsetsCache.clear();
#ifdef RTTI_EXPERIMENTAL_FEATURES
	m_vecFilesSymbolsOffsetsCache.clear();
#endif // RTTI_EXPERIMENTAL_FEATURES

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

#ifdef RTTI_EXPERIMENTAL_FEATURES
	if (bAutoScanIntoCache) {
		HMODULE hNTDLL = GetModuleHandle(TEXT("ntdll.dll"));
		if (hNTDLL) {
			m_pLdrRegisterDllNotification = reinterpret_cast<void*>(GetProcAddress(hNTDLL, "LdrRegisterDllNotification"));
			m_pLdrUnregisterDllNotification = reinterpret_cast<void*>(GetProcAddress(hNTDLL, "LdrUnregisterDllNotification"));
		}
		if (m_pLdrRegisterDllNotification) {
			fnLdrRegisterDllNotification LdrRegisterDllNotification = reinterpret_cast<fnLdrRegisterDllNotification>(m_pLdrRegisterDllNotification);
			LdrRegisterDllNotification(0, RTTI_OnDLLNotification, this, &m_pCookie);
		}
	}
#endif // RTTI_EXPERIMENTAL_FEATURES
}

RTTI::~RTTI() {
#ifdef RTTI_EXPERIMENTAL_FEATURES
	if (m_pCookie) {
		if (m_pLdrUnregisterDllNotification) {
			fnLdrUnregisterDllNotification LdrUnregisterDllNotification = reinterpret_cast<fnLdrUnregisterDllNotification>(m_pLdrUnregisterDllNotification);
			LdrUnregisterDllNotification(m_pCookie);
		}
	}
	if (m_vecThreads.size() > 0) {
		for (std::vector<HANDLE>::iterator it = m_vecThreads.begin(); it != m_vecThreads.end(); ++it) {
			WaitForSingleObject(*it, INFINITE);
			CloseHandle(*it);
		}
	}
#endif // RTTI_EXPERIMENTAL_FEATURES
}

// Finding Pattern
void* RTTI::FindPattern(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature, uintptr_t unOffset, bool bToAbsoluteAddress) {
	if (m_bAvailableAVX2) {
		return FindSigAVX2(pBegin, pEnd, szSignature, unOffset, bToAbsoluteAddress);
	}
	else if (m_bAvailableSSE2) {
		return FindSigSSE2(pBegin, pEnd, szSignature, unOffset, bToAbsoluteAddress);
	}
	else {
		return FindSigLinear(pBegin, pEnd, szSignature, unOffset, bToAbsoluteAddress);
	}
}

// Finding TypeInfo
void* RTTI::FindTypeInfoAddressFromRange(void* pBegin, void* pEnd) {
	return FindPattern(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), ".?AVtype_info@@");
}

uintptr_t RTTI::FindTypeInfoOffsetFromRange(void* pBegin, void* pEnd) {
	return reinterpret_cast<uintptr_t>(FindPattern(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), ".?AVtype_info@@")) - reinterpret_cast<uintptr_t>(pBegin);
}

void* RTTI::FindTypeInfoAddressFromModule(HMODULE hModule) {
	if (!hModule) {
		return nullptr;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return nullptr;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindTypeInfoAddressFromRange(reinterpret_cast<void*>(pBegin), pEnd);
}

uintptr_t RTTI::FindTypeInfoOffsetFromModule(HMODULE hModule) {
	if (!hModule) {
		return 0;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return 0;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindTypeInfoOffsetFromRange(reinterpret_cast<void*>(pBegin), pEnd);
}

#ifdef RTTI_EXPERIMENTAL_FEATURES
uintptr_t RTTI::FindTypeInfoOffsetFromFile(const char* szModulePath) {
	HANDLE hFile = nullptr;
	HANDLE hFileMap = nullptr;
	LPVOID pMap = nullptr;
	uintptr_t unResult = 0;
	if (MapFile(szModulePath, &hFile, &hFileMap, &pMap)) {
		DWORD dwFileSize = GetFileSize(hFile, nullptr);
		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pMap);
		unResult = FindTypeInfoOffsetFromRange(reinterpret_cast<void*>(pBegin), reinterpret_cast<void*>(pBegin + dwFileSize));
		UnMapFile(hFile, hFileMap, pMap);
	}
	return unResult;
}
#endif

// Finding references (32 - bits)
//  One
void* RTTI::FindReferenceAddressFromRange32(void* pBegin, void* pEnd, unsigned int unValue) {
	char szValue[sizeof(unValue) + 1];
	memset(szValue, 0, sizeof(szValue));
	for (unsigned char i = 0; i < (sizeof(szValue) - 1); ++i) {
		char ch = reinterpret_cast<char*>(&unValue)[i];
		if (ch == '\x00') {
			ch = '\x2A';
		}
		szValue[i] = ch;
	}
	return FindPattern(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szValue);
}

uintptr_t RTTI::FindReferenceOffsetFromRange32(void* pBegin, void* pEnd, unsigned int unValue) {
	char szValue[sizeof(unValue) + 1];
	memset(szValue, 0, sizeof(szValue));
	for (unsigned char i = 0; i < (sizeof(szValue) - 1); ++i) {
		char ch = reinterpret_cast<char*>(&unValue)[i];
		if (ch == '\x00') {
			ch = '\x2A';
		}
		szValue[i] = ch;
	}
	return reinterpret_cast<uintptr_t>(FindPattern(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szValue)) - reinterpret_cast<uintptr_t>(pBegin);
}

void* RTTI::FindReferenceAddressFromModule32(HMODULE hModule, unsigned int unValue) {
	if (!hModule) {
		return nullptr;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return nullptr;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindReferenceAddressFromRange32(reinterpret_cast<void*>(pBegin), pEnd, unValue);
}

uintptr_t RTTI::FindReferenceOffsetFromModule32(HMODULE hModule, unsigned int unValue) {
	if (!hModule) {
		return 0;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return 0;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindReferenceOffsetFromRange32(reinterpret_cast<void*>(pBegin), pEnd, unValue);
}

#ifdef RTTI_EXPERIMENTAL_FEATURES
uintptr_t RTTI::FindReferenceOffsetFromFile32(const char* szModulePath, unsigned int unValue) {
	HANDLE hFile = nullptr;
	HANDLE hFileMap = nullptr;
	LPVOID pMap = nullptr;
	uintptr_t unResult = 0;
	if (MapFile(szModulePath, &hFile, &hFileMap, &pMap)) {
		DWORD dwFileSize = GetFileSize(hFile, nullptr);
		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pMap);
		unResult = FindReferenceOffsetFromRange32(reinterpret_cast<void*>(pBegin), reinterpret_cast<void*>(pBegin + dwFileSize), unValue);
		UnMapFile(hFile, hFileMap, pMap);
	}
	return unResult;
}
#endif // RTTI_EXPERIMENTAL_FEATURES

//  Multiple
std::vector<void*> RTTI::FindReferencesAddressesFromRange32(void* pBegin, void* pEnd, unsigned int unValue) {
	std::vector<void*> vecData;
	char szValue[sizeof(unValue) + 1];
	memset(szValue, 0, sizeof(szValue));
	for (unsigned char i = 0; i < (sizeof(szValue) - 1); ++i) {
		char ch = reinterpret_cast<char*>(&unValue)[i];
		if (ch == '\x00') {
			ch = '\x2A';
		}
		szValue[i] = ch;
	}
	void* pLastAddress = pBegin;
	while (pLastAddress < pEnd) {
		void* pAddress = FindPattern(reinterpret_cast<unsigned char*>(pLastAddress), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szValue);
		if (!pAddress) {
			break;
		}
		vecData.push_back(pAddress);
		pLastAddress = reinterpret_cast<void*>(reinterpret_cast<char*>(pAddress) + 1);
	}
	return vecData;
}

std::vector<uintptr_t> RTTI::FindReferencesOffsetsFromRange32(void* pBegin, void* pEnd, unsigned int unValue) {
	std::vector<uintptr_t> vecData;
	char szValue[sizeof(unValue) + 1];
	memset(szValue, 0, sizeof(szValue));
	for (unsigned char i = 0; i < (sizeof(szValue) - 1); ++i) {
		char ch = reinterpret_cast<char*>(&unValue)[i];
		if (ch == '\x00') {
			ch = '\x2A';
		}
		szValue[i] = ch;
	}
	void* pLastAddress = pBegin;
	while (pLastAddress < pEnd) {
		void* pAddress = FindPattern(reinterpret_cast<unsigned char*>(pLastAddress), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szValue);
		if (!pAddress) {
			break;
		}
		vecData.push_back(reinterpret_cast<uintptr_t>(pAddress) - reinterpret_cast<uintptr_t>(pBegin));
		pLastAddress = reinterpret_cast<void*>(reinterpret_cast<char*>(pAddress) + 1);
	}
	return vecData;
}

std::vector<void*> RTTI::FindReferencesAddressesFromModule32(HMODULE hModule, unsigned int unValue) {
	std::vector<void*> vecData;

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
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindReferencesAddressesFromRange32(reinterpret_cast<void*>(pBegin), pEnd, unValue);
}

std::vector<uintptr_t> RTTI::FindReferencesOffsetsFromModule32(HMODULE hModule, unsigned int unValue) {
	std::vector<uintptr_t> vecData;

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
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindReferencesOffsetsFromRange32(reinterpret_cast<void*>(pBegin), pEnd, unValue);
}

#ifdef RTTI_EXPERIMENTAL_FEATURES
std::vector<uintptr_t> RTTI::FindReferencesOffsetsFromFile32(const char* szModulePath, unsigned int unValue) {
	HANDLE hFile = nullptr;
	HANDLE hFileMap = nullptr;
	LPVOID pMap = nullptr;
	std::vector<uintptr_t> vecData;
	if (MapFile(szModulePath, &hFile, &hFileMap, &pMap)) {
		DWORD dwFileSize = GetFileSize(hFile, nullptr);
		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pMap);
		vecData = FindReferencesOffsetsFromRange32(reinterpret_cast<void*>(pBegin), reinterpret_cast<void*>(pBegin + dwFileSize), unValue);
		UnMapFile(hFile, hFileMap, pMap);
	}
	return vecData;
}
#endif // RTTI_EXPERIMENTAL_FEATURES

// Finding references (64 - bits)
//  One
void* RTTI::FindReferenceAddressFromRange(void* pBegin, void* pEnd, void* pValue) {
	char szValue[sizeof(pValue) + 1];
	memset(szValue, 0, sizeof(szValue));
	for (unsigned char i = 0; i < (sizeof(szValue) - 1); ++i) {
		char ch = reinterpret_cast<char*>(&pValue)[i];
		if (ch == '\x00') {
			ch = '\x2A';
		}
		szValue[i] = ch;
	}
	return FindPattern(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szValue);
}

uintptr_t RTTI::FindReferenceOffsetFromRange(void* pBegin, void* pEnd, void* pValue) {
	char szValue[sizeof(pValue) + 1];
	memset(szValue, 0, sizeof(szValue));
	for (unsigned char i = 0; i < (sizeof(szValue) - 1); ++i) {
		char ch = reinterpret_cast<char*>(&pValue)[i];
		if (ch == '\x00') {
			ch = '\x2A';
		}
		szValue[i] = ch;
	}
	return reinterpret_cast<uintptr_t>(FindPattern(reinterpret_cast<unsigned char*>(pBegin), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szValue)) - reinterpret_cast<uintptr_t>(pBegin);
}

void* RTTI::FindReferenceAddressFromModule(HMODULE hModule, void* pValue) {
	if (!hModule) {
		return nullptr;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return nullptr;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindReferenceAddressFromRange(reinterpret_cast<void*>(pBegin), pEnd, pValue);
}

uintptr_t RTTI::FindReferenceOffsetFromModule(HMODULE hModule, void* pValue) {
	if (!hModule) {
		return 0;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return 0;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindReferenceOffsetFromRange(reinterpret_cast<void*>(pBegin), pEnd, pValue);
}

#ifdef RTTI_EXPERIMENTAL_FEATURES
uintptr_t RTTI::FindReferenceOffsetFromFile(const char* szModulePath, void* pValue) {
	HANDLE hFile = nullptr;
	HANDLE hFileMap = nullptr;
	LPVOID pMap = nullptr;
	uintptr_t unResult = 0;
	if (MapFile(szModulePath, &hFile, &hFileMap, &pMap)) {
		DWORD dwFileSize = GetFileSize(hFile, nullptr);
		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pMap);
		unResult = FindReferenceOffsetFromRange(reinterpret_cast<void*>(pBegin), reinterpret_cast<void*>(pBegin + dwFileSize), pValue);
		UnMapFile(hFile, hFileMap, pMap);
	}
	return unResult;
}
#endif // RTTI_EXPERIMENTAL_FEATURES

//  Multiple
std::vector<void*> RTTI::FindReferencesAddressesFromRange(void* pBegin, void* pEnd, void* pValue) {
	std::vector<void*> vecData;
	char szValue[sizeof(pValue) + 1];
	memset(szValue, 0, sizeof(szValue));
	for (unsigned char i = 0; i < (sizeof(szValue) - 1); ++i) {
		char ch = reinterpret_cast<char*>(&pValue)[i];
		if (ch == '\x00') {
			ch = '\x2A';
		}
		szValue[i] = ch;
	}
	void* pLastAddress = pBegin;
	while (pLastAddress < pEnd) {
		void* pAddress = FindPattern(reinterpret_cast<unsigned char*>(pLastAddress), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szValue);
		if (!pAddress) {
			break;
		}
		vecData.push_back(pAddress);
		pLastAddress = reinterpret_cast<void*>(reinterpret_cast<char*>(pAddress) + 1);
	}
	return vecData;
}

std::vector<uintptr_t> RTTI::FindReferencesOffsetsFromRange(void* pBegin, void* pEnd, void* pValue) {
	std::vector<uintptr_t> vecData;
	char szValue[sizeof(pValue) + 1];
	memset(szValue, 0, sizeof(szValue));
	for (unsigned char i = 0; i < (sizeof(szValue) - 1); ++i) {
		char ch = reinterpret_cast<char*>(&pValue)[i];
		if (ch == '\x00') {
			ch = '\x2A';
		}
		szValue[i] = ch;
	}
	void* pLastAddress = pBegin;
	while (pLastAddress < pEnd) {
		void* pAddress = FindPattern(reinterpret_cast<unsigned char*>(pLastAddress), reinterpret_cast<const unsigned char*>(const_cast<const void*>(pEnd)), szValue);
		if (!pAddress) {
			break;
		}
		vecData.push_back(reinterpret_cast<uintptr_t>(pAddress) - reinterpret_cast<uintptr_t>(pBegin));
		pLastAddress = reinterpret_cast<void*>(reinterpret_cast<char*>(pAddress) + 1);
	}
	return vecData;
}

std::vector<void*> RTTI::FindReferencesAddressesFromModule(HMODULE hModule, void* pValue) {
	std::vector<void*> vecData;

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
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindReferencesAddressesFromRange(reinterpret_cast<void*>(pBegin), pEnd, pValue);
}

std::vector<uintptr_t> RTTI::FindReferencesOffsetsFromModule(HMODULE hModule, void* pValue) {
	std::vector<uintptr_t> vecData;

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
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return FindReferencesOffsetsFromRange(reinterpret_cast<void*>(pBegin), pEnd, pValue);
}

#ifdef RTTI_EXPERIMENTAL_FEATURES
std::vector<uintptr_t> RTTI::FindReferencesOffsetsFromFile(const char* szModulePath, void* pValue) {
	HANDLE hFile = nullptr;
	HANDLE hFileMap = nullptr;
	LPVOID pMap = nullptr;
	std::vector<uintptr_t> vecData;
	if (MapFile(szModulePath, &hFile, &hFileMap, &pMap)) {
		DWORD dwFileSize = GetFileSize(hFile, nullptr);
		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pMap);
		vecData = FindReferencesOffsetsFromRange(reinterpret_cast<void*>(pBegin), reinterpret_cast<void*>(pBegin + dwFileSize), pValue);
		UnMapFile(hFile, hFileMap, pMap);
	}
	return vecData;
}
#endif // RTTI_EXPERIMENTAL_FEATURES

// Finding VTables
//  Multiple
vecSymbolsAddresses RTTI::GetVTablesAddressesFromRange(void* pBegin, void* pEnd) {
	vecSymbolsAddresses vecData;

	if (m_bCaching && m_bRangesCaching) {
		for (vecRangesSymbolsAddresses::iterator it = m_vecRangesSymbolsAddressesCache.begin(); it != m_vecRangesSymbolsAddressesCache.end(); ++it) {
			RangeOfDataForRTII rangeData = std::get<0>(*it);
			void* pcBegin = std::get<0>(rangeData);
			void* pcEnd = std::get<1>(rangeData);
			if ((pcBegin == pBegin) && (pcEnd == pEnd)) {
				return std::get<1>(*it);
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

	std::vector<void*> vecTypes = FindReferencesAddressesFromRange(pBegin, pEnd, pTypeDesc->pVFTable);
	for (std::vector<void*>::iterator ittype = vecTypes.begin(); ittype != vecTypes.end(); ++ittype) {
		void* pType = reinterpret_cast<void*>(*ittype);
#ifdef _WIN64
		unsigned long long unTypeOffsetTemp = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(pType) - reinterpret_cast<uintptr_t>(pBegin));
		unsigned long unTypeOffset = *(reinterpret_cast<unsigned long*>(&unTypeOffsetTemp));
		std::vector<void*> vecReferences = FindReferencesAddressesFromRange32(pBegin, pEnd, unTypeOffset);
#elif _WIN32
		std::vector<void*> vecReferences = FindReferencesAddressesFromRange(pBegin, pEnd, pType);
#endif
		for (std::vector<void*>::iterator itreference = vecReferences.begin(); itreference != vecReferences.end(); ++itreference) {
			void* pReference = reinterpret_cast<void*>(*itreference);
#ifdef _WIN64
			if (!(((*(reinterpret_cast<unsigned long*>(pReference))) != 0) && ((*(reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(pReference) + sizeof(unsigned long))) != 0)))) {
				continue;
			}
#elif _WIN32
			if (!(((*(reinterpret_cast<unsigned long*>(pReference))) >= reinterpret_cast<unsigned long>(pBegin)) && ((*(reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(pReference) + sizeof(unsigned long))) >= reinterpret_cast<unsigned long>(pBegin))))) {
				continue;
			}
#endif

			void* pLocation = reinterpret_cast<unsigned char*>(pReference) - (sizeof(unsigned long) * 3);
			void* pMeta = FindReferenceAddressFromRange(pBegin, pEnd, pLocation);
			if (!pMeta) {
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

			void* pPattern1 = FindPattern(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + (sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1))), "::`vftable'");
			if (pPattern1) {
				szSymbolBuffer[unSymbolBufferLength - 11] = 0;
			}
			void* pPattern2 = FindPattern(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + (sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1))), "const ");
			if (pPattern2) {
				szSymbolBuffer[unSymbolBufferLength - 6] = 0;
			}
			void* pPattern3 = FindPattern(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + (sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1))), "::`anonymous namespace'");
			if (pPattern3) {
				szSymbolBuffer[unSymbolBufferLength - 23] = 0;
			}

			vecData.push_back(SymbolAddress(szSymbolBuffer, reinterpret_cast<void*>(reinterpret_cast<unsigned char*>(pMeta) + sizeof(void*))));
		}
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
			RangeOfDataForRTII rangeData = std::get<0>(*it);
			void* pcBegin = std::get<0>(rangeData);
			void* pcEnd = std::get<1>(rangeData);
			if ((pcBegin == pBegin) && (pcEnd == pEnd)) {
				return std::get<1>(*it);
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

	std::vector<void*> vecTypes = FindReferencesAddressesFromRange(pBegin, pEnd, pTypeDesc->pVFTable);
	for (std::vector<void*>::iterator ittype = vecTypes.begin(); ittype != vecTypes.end(); ++ittype) {
		void* pType = reinterpret_cast<void*>(*ittype);
#ifdef _WIN64
		unsigned long long unTypeOffsetTemp = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(pType) - reinterpret_cast<uintptr_t>(pBegin));
		unsigned long unTypeOffset = *(reinterpret_cast<unsigned long*>(&unTypeOffsetTemp));
		std::vector<void*> vecReferences = FindReferencesAddressesFromRange32(pBegin, pEnd, unTypeOffset);
#elif _WIN32
		std::vector<void*> vecReferences = FindReferencesAddressesFromRange(pBegin, pEnd, pType);
#endif
		for (std::vector<void*>::iterator itreference = vecReferences.begin(); itreference != vecReferences.end(); ++itreference) {
			void* pReference = reinterpret_cast<void*>(*itreference);
#ifdef _WIN64
			if (!(((*(reinterpret_cast<unsigned long*>(pReference))) != 0) && ((*(reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(pReference) + sizeof(unsigned long))) != 0)))) {
				continue;
			}
#elif _WIN32
			if (!(((*(reinterpret_cast<unsigned long*>(pReference))) >= reinterpret_cast<unsigned long>(pBegin)) && ((*(reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(pReference) + sizeof(unsigned long))) >= reinterpret_cast<unsigned long>(pBegin))))) {
				continue;
			}
#endif

			void* pLocation = reinterpret_cast<unsigned char*>(pReference) - (sizeof(unsigned long) * 3);
			void* pMeta = FindReferenceAddressFromRange(pBegin, pEnd, pLocation);
			if (!pMeta) {
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

			void* pPattern1 = FindPattern(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + (sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1))), "::`vftable'");
			if (pPattern1) {
				szSymbolBuffer[unSymbolBufferLength - 11] = 0;
			}
			void* pPattern2 = FindPattern(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + (sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1))), "const ");
			if (pPattern2) {
				szSymbolBuffer[unSymbolBufferLength - 6] = 0;
			}
			void* pPattern3 = FindPattern(reinterpret_cast<unsigned char*>(szSymbolBuffer), reinterpret_cast<const unsigned char*>(const_cast<const char*>(szSymbolBuffer + (sizeof(char) * RTTI_DEFAULT_MAX_SYMBOL_LENGTH - 1))), "::`anonymous namespace'");
			if (pPattern3) {
				szSymbolBuffer[unSymbolBufferLength - 23] = 0;
			}

			vecData.push_back(SymbolOffset(szSymbolBuffer, reinterpret_cast<uintptr_t>(reinterpret_cast<unsigned char*>(pMeta) + sizeof(void*)) - reinterpret_cast<uintptr_t>(pBegin)));
		}
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
			HMODULE hMod = std::get<0>(*it);
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
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
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
			HMODULE hMod = std::get<0>(*it);
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
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	vecData = GetVTablesOffsetsFromRange(reinterpret_cast<void*>(pBegin), pEnd);

	if (m_bCaching && m_bModulesCaching && (vecData.size() > 0)) {
		m_vecModulesSymbolsOffsetsCache.push_back(ModuleSymbolsOffsets(hModule, vecData));
	}

	return vecData;
}

#ifdef RTTI_EXPERIMENTAL_FEATURES
vecSymbolsOffsets RTTI::GetVTablesOffsetsFromFile(const char* szModulePath) {
	vecSymbolsOffsets vecData;

	if (m_bCaching && m_bFilesCaching) {
		for (vecFilesSymbolsOffsets::iterator it = m_vecFilesSymbolsOffsetsCache.begin(); it != m_vecFilesSymbolsOffsetsCache.end(); ++it) {
			std::string str_ModulePath = std::get<0>(*it);
			if (strcmp(str_ModulePath.data(), szModulePath) == 0) {
				return std::get<1>(*it);
			}
		}
	}

	HANDLE hFile = nullptr;
	HANDLE hFileMap = nullptr;
	LPVOID pMap = nullptr;
	if (MapFile(szModulePath, &hFile, &hFileMap, &pMap)) {
		DWORD dwFileSize = GetFileSize(hFile, nullptr);
		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pMap);
		vecData = GetVTablesOffsetsFromRange(reinterpret_cast<void*>(pBegin), reinterpret_cast<void*>(pBegin + dwFileSize));
		UnMapFile(hFile, hFileMap, pMap);
	}

	if (m_bCaching && m_bFilesCaching && (vecData.size() > 0)) {
		m_vecFilesSymbolsOffsetsCache.push_back(FileSymbolsOffsets(szModulePath, vecData));
	}

	return vecData;
}
#endif // RTTI_EXPERIMENTAL_FEATURES

//  One
void* RTTI::GetVTableAddressFromRange(void* pBegin, void* pEnd, const char* szClassName) {
	if (m_bCaching && m_bRangesCaching) {
		void* pResult = GetVTableAddressFromRangeCache(pBegin, pEnd, szClassName);
		if (pResult) {
			return pResult;
		}
	}
	vecSymbolsAddresses vecData = GetVTablesAddressesFromRange(pBegin, pEnd);
	for (vecSymbolsAddresses::iterator it = vecData.begin(); it != vecData.end(); ++it) {
		std::string str_SymbolName = std::get<0>(*it);
		if (strcmp(str_SymbolName.data(), szClassName) == 0) {
			return std::get<1>(*it);
		}
	}
	return nullptr;
}

uintptr_t RTTI::GetVTableOffsetFromRange(void* pBegin, void* pEnd, const char* szClassName) {
	if (m_bCaching && m_bRangesCaching) {
		uintptr_t unResult = GetVTableOffsetFromRangeCache(pBegin, pEnd, szClassName);
		if (unResult) {
			return unResult;
		}
	}
	vecSymbolsOffsets vecData = GetVTablesOffsetsFromRange(pBegin, pEnd);
	for (vecSymbolsOffsets::iterator it = vecData.begin(); it != vecData.end(); ++it) {
		std::string str_SymbolName = std::get<0>(*it);
		if (strcmp(str_SymbolName.data(), szClassName) == 0) {
			return std::get<1>(*it);
		}
	}
	return 0;
}

void* RTTI::GetVTableAddressFromModule(HMODULE hModule, const char* szClassName) {

	if (m_bCaching && m_bModulesCaching) {
		void* pResult = GetVTableAddressFromModuleCache(hModule, szClassName);
		if (pResult) {
			return pResult;
		}
	}

	if (!hModule) {
		return nullptr;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return nullptr;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return GetVTableAddressFromRange(reinterpret_cast<void*>(pBegin), pEnd, szClassName);
}

uintptr_t RTTI::GetVTableOffsetFromModule(HMODULE hModule, const char* szClassName) {

	if (m_bCaching && m_bModulesCaching) {
		uintptr_t unResult = GetVTableOffsetFromModuleCache(hModule, szClassName);
		if (unResult) {
			return unResult;
		}
	}

	if (!hModule) {
		return 0;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hModule, &modinf, sizeof(MODULEINFO))) {
		return 0;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	void* pEnd = reinterpret_cast<void*>(pBegin + modinf.SizeOfImage);

#ifdef RTTI_EXPERIMENTAL_OPTIMIZATION
	unsigned char* dpBegin = nullptr;
	void* dpEnd = nullptr;
	if (GetRealModuleDimensions(hModule, reinterpret_cast<void**>(&dpBegin), &dpEnd)) {
		pBegin = dpBegin;
		pEnd = dpEnd;
	}
#endif // RTTI_EXPERIMENTAL_OPTIMIZATION

	return GetVTableOffsetFromRange(reinterpret_cast<void*>(pBegin), pEnd, szClassName);
}

#ifdef RTTI_EXPERIMENTAL_FEATURES
uintptr_t RTTI::GetVTableOffsetFromFile(const char* szModulePath, const char* szClassName) {
	uintptr_t unResult = 0;
	if (m_bCaching && m_bFilesCaching) {
		unResult = GetVTableOffsetFromFileCache(szModulePath, szClassName);
		if (unResult) {
			return unResult;
		}
	}
	HANDLE hFile = nullptr;
	HANDLE hFileMap = nullptr;
	LPVOID pMap = nullptr;
	if (MapFile(szModulePath, &hFile, &hFileMap, &pMap)) {
		DWORD dwFileSize = GetFileSize(hFile, nullptr);
		unsigned char* pBegin = reinterpret_cast<unsigned char*>(pMap);
		unResult = GetVTableOffsetFromRange(reinterpret_cast<void*>(pBegin), reinterpret_cast<void*>(pBegin + dwFileSize), szClassName);
		UnMapFile(hFile, hFileMap, pMap);
	}
	return unResult;
}
#endif // RTTI_EXPERIMENTAL_FEATURES

// Finding in cache
void* RTTI::GetVTableAddressFromRangeCache(void* pBegin, void* pEnd, const char* szClassName) {
	for (vecRangesSymbolsAddresses::iterator it = m_vecRangesSymbolsAddressesCache.begin(); it != m_vecRangesSymbolsAddressesCache.end(); ++it) {
		RangeOfDataForRTII dataRange = std::get<0>(*it);
		void* pcBegin = std::get<0>(dataRange);
		void* pcEnd = std::get<1>(dataRange);
		if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
			vecSymbolsAddresses vecSymbols = std::get<1>(*it);
			for (vecSymbolsAddresses::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
				std::string str_SymbolName = std::get<0>(*sit);
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
		RangeOfDataForRTII dataRange = std::get<0>(*it);
		void* pcBegin = std::get<0>(dataRange);
		void* pcEnd = std::get<1>(dataRange);
		if ((pcBegin == pBegin) && (pcBegin == pEnd)) {
			vecSymbolsOffsets vecSymbols = std::get<1>(*it);
			for (vecSymbolsOffsets::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
				std::string str_SymbolName = std::get<0>(*sit);
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
		HMODULE hMod = std::get<0>(*it);
		if (hMod == hModule) {
			vecSymbolsAddresses vecSymbols = std::get<1>(*it);
			for (vecSymbolsAddresses::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
				std::string str_SymbolName = std::get<0>(*sit);
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
		HMODULE hMod = std::get<0>(*it);
		if (hMod == hModule) {
			vecSymbolsOffsets vecSymbols = std::get<1>(*it);
			for (vecSymbolsOffsets::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
				std::string str_SymbolName = std::get<0>(*sit);
				if (strcmp(str_SymbolName.data(), szClassName) == 0) {
					return std::get<1>(*sit);
				}
			}
		}
	}
	return 0;
}

#ifdef RTTI_EXPERIMENTAL_FEATURES
uintptr_t RTTI::GetVTableOffsetFromFileCache(const char* szModulePath, const char* szClassName) {
	for (vecFilesSymbolsOffsets::iterator it = m_vecFilesSymbolsOffsetsCache.begin(); it != m_vecFilesSymbolsOffsetsCache.end(); ++it) {
		std::string str_ModulePath = std::get<0>(*it);
		if (strcmp(str_ModulePath.data(), szModulePath) == 0) {
			vecSymbolsOffsets vecSymbols = std::get<1>(*it);
			for (vecSymbolsOffsets::iterator sit = vecSymbols.begin(); sit != vecSymbols.end(); ++sit) {
				std::string str_SymbolName = std::get<0>(*sit);
				if (strcmp(str_SymbolName.data(), szClassName) == 0) {
					return std::get<1>(*sit);
				}
			}
		}
	}
	return 0;
}
#endif // RTTI_EXPERIMENTAL_FEATURES

// For processing
bool RTTI::IsCacheEnabled() {
	return m_bCaching;
}

#ifdef RTTI_EXPERIMENTAL_FEATURES
pvecRangesSymbolsAddresses RTTI::GetRangesAddressesCache() {
	if (m_bCaching && m_bRangesCaching) {
		return &m_vecRangesSymbolsAddressesCache;
	}
	return nullptr;
}

pvecModulesSymbolsAddresses RTTI::GetModulesAddressesCache() {
	if (m_bCaching && m_bModulesCaching) {
		return &m_vecModulesSymbolsAddressesCache;
	}
	return nullptr;
}

pvecRangesSymbolsOffsets RTTI::GetRangesOffsetsCache() {
	if (m_bCaching && m_bRangesCaching) {
		return &m_vecRangesSymbolsOffsetsCache;
	}
	return nullptr;
}

pvecModulesSymbolsOffsets RTTI::GetModulesOffsetsCache() {
	if (m_bCaching && m_bModulesCaching) {
		return &m_vecModulesSymbolsOffsetsCache;
	}
	return nullptr;
}

pvecFilesSymbolsOffsets RTTI::GetFilesOffsetsCache() {
	if (m_bCaching && m_bFilesCaching) {
		return &m_vecFilesSymbolsOffsetsCache;
	}
	return nullptr;
}
#endif // RTTI_EXPERIMENTAL_FEATURES