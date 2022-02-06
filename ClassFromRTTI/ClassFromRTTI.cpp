
// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// STL
#include <chrono>
using namespace std::chrono;

// Custom
#include "RTTI.h"

#define BENCHMARK_TEST

// __thiscall
//  > ecx - this
// __fastcall (alternative for __thiscall)
//  > ecx - this
//  > edx - (unused)
typedef bool(__fastcall* fnIsTrue)(void* ecx, void* edx);
typedef const char*(__fastcall* fnHelloWorld)(void* ecx, void* edx);

int main() {
	HMODULE hTestDLL = LoadLibrary(TEXT("TestDLL.dll"));
	if (!hTestDLL) {
		printf("Error: TestDLL.dll not found.\n");
		return -1;
	}

	void* pTesting = FindRTTI(hTestDLL, ".?AVTestingDLL@@"); // ".?AV<NAME>@@"
	if (!pTesting) {
		printf("Error: TestingDLL VTable not found.\n");
		return -1;
	}

	void** pTestingVTable = reinterpret_cast<void**>(pTesting);
	fnIsTrue IsTrue = reinterpret_cast<fnIsTrue>(pTestingVTable[0]);
	fnHelloWorld HelloWorld = reinterpret_cast<fnHelloWorld>(pTestingVTable[1]);
	
	printf("RESULT:\n");
	printf(" > hTestDLL (0x%IX)\n", reinterpret_cast<uintptr_t>(hTestDLL));
	printf("  > pTestingVTable (0x%IX)\n", reinterpret_cast<uintptr_t>(pTestingVTable));
	printf("   > IsTrue (0x%IX) = %s\n", reinterpret_cast<uintptr_t>(&(pTestingVTable[0])), IsTrue(pTestingVTable, nullptr) ? "true" : "false");
	printf("   > HelloWorld (0x%IX) = %s\n", reinterpret_cast<uintptr_t>(&(pTestingVTable[1])), HelloWorld(pTestingVTable, nullptr));

	return 0;
}