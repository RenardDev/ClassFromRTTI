
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <Psapi.h>
#include <DbgHelp.h>

// Default libraries
#pragma comment(lib, "dbghelp.lib")

// STL
#include <vector>
#include <memory>

// Helpful functions
void* FindFirstString(void* pBegin, void* pEnd, const char* szString) {
	size_t unStringLength = strlen(szString);
	unsigned char* ppEnd = reinterpret_cast<unsigned char*>(pEnd) - unStringLength;
	for (unsigned char* pPoint = reinterpret_cast<unsigned char*>(pBegin); pPoint < ppEnd; ++pPoint) {
		bool bSuccess = true;
		for (uintptr_t j = 0; j < unStringLength; ++j)
		{
			if (reinterpret_cast<char*>(pPoint)[j] != szString[j])
			{
				bSuccess = false;
				break;
			}
		}
		if (bSuccess) {
			return pPoint;
		}
	}
	return nullptr;
}

std::vector<void*> FindReferences(void* pBegin, void* pEnd, void* pValue) {
	std::vector<void*> vecData;
	for (unsigned char* pPoint = reinterpret_cast<unsigned char*>(pBegin); pPoint < pEnd; pPoint += sizeof(void*)) {
		void* pCandidate = *(reinterpret_cast<void**>(pPoint));
		if (pCandidate == pValue) {
			vecData.push_back(pPoint);
		}
	}
	return vecData;
}

std::vector<void*> FindReferences32(void* pBegin, void* pEnd, unsigned long unValue) {
	std::vector<void*> vecData;
	for (unsigned char* pPoint = reinterpret_cast<unsigned char*>(pBegin); pPoint < pEnd; pPoint += sizeof(unsigned long)) {
		unsigned long unCandidate = *(reinterpret_cast<unsigned long*>(pPoint));
		if (unCandidate == unValue) {
			vecData.push_back(pPoint);
		}
	}
	return vecData;
}

void* FindFirstReference(void* pBegin, void* pEnd, void* pValue) {
	for (unsigned char* pPoint = reinterpret_cast<unsigned char*>(pBegin); pPoint < pEnd; pPoint += sizeof(void*)) {
		void* pCandidate = *(reinterpret_cast<void**>(pPoint));
		if (pCandidate == pValue) {
			return pPoint;
		}
	}
	return nullptr;
}

// Main function
// szModuleName - Module name
// szName - Class name
// bRVA - RVA or VA
//  RVA usage example: void* address = GetModuleHandleA(...) + RVA;
//  VA usage example: void* address = VA;
void* FindRTTIClass(const char* szModuleName, const char* szName, bool bRVA = false) {
	HMODULE hMod = GetModuleHandleA(szModuleName);
	if (!hMod) {
		return nullptr;
	}

	MODULEINFO modinf;
	if (!GetModuleInformation(HANDLE(-1), hMod, &modinf, sizeof(MODULEINFO))) {
		return nullptr;
	}

	unsigned char* pBegin = reinterpret_cast<unsigned char*>(modinf.lpBaseOfDll);
	const unsigned char* pEnd = pBegin + modinf.SizeOfImage;

	void* pTypeInfo = FindFirstString(pBegin, const_cast<unsigned char*>(pEnd), ".?AVtype_info@@");
	if (!pTypeInfo) {
		return nullptr;
	}

	typedef struct _TYPEDESCRIPTOR
	{
		void* pVFTable;
		void* pSpare;
		char Name;
	} TYPEDESCRIPTOR, * PTYPEDESCRIPTOR;

	PTYPEDESCRIPTOR pTypeDesc = reinterpret_cast<PTYPEDESCRIPTOR>(reinterpret_cast<char*>(pTypeInfo) - (sizeof(void*) * 2));

	std::unique_ptr<char[]> mem_szSymbolBuffer(new char[0x7FF]); // 0x7FF - Max for MSVC
	char* szSymbolBuffer = mem_szSymbolBuffer.get();
	if (!szSymbolBuffer) {
		return nullptr;
	}
	memset(szSymbolBuffer, 0, sizeof(char[0x7FF]));

	std::vector<void*> vecTypes = FindReferences(pBegin, const_cast<unsigned char*>(pEnd), pTypeDesc->pVFTable);
	for (std::vector<void*>::iterator ittype = vecTypes.begin(); ittype != vecTypes.end(); ++ittype) {
		void* pType = reinterpret_cast<void*>(*ittype);
#ifdef _WIN64
		unsigned long long unTypeOffsetTemp = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(pType) - reinterpret_cast<uintptr_t>(pBegin));
		unsigned long unTypeOffset = *(reinterpret_cast<unsigned long*>(&unTypeOffsetTemp));
		std::vector<void*> vecReferences = FindReferences32(pBegin, const_cast<unsigned char*>(pEnd), unTypeOffset);
#elif _WIN32
		std::vector<void*> vecReferences = FindReferences(pBegin, const_cast<unsigned char*>(pEnd), pType);
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
			void* pMeta = FindFirstReference(pBegin, const_cast<unsigned char*>(pEnd), pLocation);
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

			memset(szSymbolBuffer, 0, sizeof(char[0x7FF]));
			sprintf_s(szSymbolBuffer, sizeof(char[0x7FF]), "??_7%s6B@", pNewSymbol);
			if (!((UnDecorateSymbolName(szSymbolBuffer, szSymbolBuffer, sizeof(char[0x7FF]) - 1, UNDNAME_32_BIT_DECODE | UNDNAME_NAME_ONLY | UNDNAME_NO_SPECIAL_SYMS)) != 0)) {

				break;
			}

			size_t unSymbolBufferLength = strnlen_s(szSymbolBuffer, sizeof(char[0x7FF]) - 1);

			void* pPattern1 = FindFirstString(szSymbolBuffer, szSymbolBuffer + (sizeof(char[0x7FF]) - 1), "::`vftable'");
			if (pPattern1) {
				szSymbolBuffer[unSymbolBufferLength - 11] = 0;
			}
			void* pPattern2 = FindFirstString(szSymbolBuffer, szSymbolBuffer + (sizeof(char[0x7FF]) - 1), "const ");
			if (pPattern2) {
				szSymbolBuffer[unSymbolBufferLength - 6] = 0;
			}
			void* pPattern3 = FindFirstString(szSymbolBuffer, szSymbolBuffer + (sizeof(char[0x7FF]) - 1), "::`anonymous namespace'");
			if (pPattern3) {
				szSymbolBuffer[unSymbolBufferLength - 23] = 0;
			}

			if (strcmp(szName, szSymbolBuffer) == 0) {
				if (!bRVA) {
					return reinterpret_cast<void*>(reinterpret_cast<unsigned char*>(pMeta) + sizeof(void*));
				}
				else {
					return reinterpret_cast<void*>(reinterpret_cast<unsigned char*>(pMeta) + sizeof(void*) - pBegin);
				}
			}
		}
	}
	return nullptr;
}

// ecx - this
// edx - unused
typedef bool(__fastcall* fnIsTrue)(void* ecx, void* edx);
typedef const char* (__fastcall* fnHelloWorld)(void* ecx, void* edx);

int main() {
	HMODULE hTestDLL = LoadLibrary(TEXT("TestDLL.dll"));
	if (!hTestDLL) {
		printf("Err: TestDLL.dll not found.\n");
		return -1;
	}

	void* pTestingDLL = FindRTTIClass("TestDLL.dll", "TestingDLL", true);
	if (!pTestingDLL) {
		printf("Err: TestingDLL RVA VTable not found.\n");
		return -1;
	}

	void** pTestingDLL_VT = reinterpret_cast<void**>(reinterpret_cast<char*>(hTestDLL) + reinterpret_cast<uintptr_t>(pTestingDLL));

	fnIsTrue IsTrue = reinterpret_cast<fnIsTrue>(pTestingDLL_VT[0]);
	fnHelloWorld HelloWorld = reinterpret_cast<fnHelloWorld>(pTestingDLL_VT[1]);
	
	printf("IsTrue = %s\n", IsTrue(pTestingDLL_VT, nullptr) ? "true" : "false");
	printf("HelloWorld = %s\n", HelloWorld(pTestingDLL_VT, nullptr));

	return 0;
}