
// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// STL
#include <chrono>
using namespace std::chrono;

// Custom
#include "RTTI.h"

// General definitions

// ecx - this
// edx - (unused)
typedef bool(__fastcall* fnIsTrue)(void* ecx, void* edx);
typedef const char*(__fastcall* fnHelloWorld)(void* ecx, void* edx);


int main() {
	RTTI cRTTI1(true, true, true, true); // With caching
	RTTI cRTTI2; // Without caching
	
	HMODULE hTestDLL = LoadLibrary(TEXT("TestDLL.dll"));
	if (!hTestDLL) {
		printf("Error: TestDLL.dll not found.\n");
		return -1;
	}

	printf("For start press <Enter>\n");
	_CRT_UNUSED(getchar());

	uintptr_t unTestingRVA = cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL");
	printf("TestingDLL (RVA) = 0x%IX\n", unTestingRVA);

	high_resolution_clock::time_point t1;
	high_resolution_clock::time_point t2;
	t1 = high_resolution_clock::now();
	for (unsigned char i = 0; i < 10; i++) {
		if (unTestingRVA != cRTTI1.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (10 calls)                  = %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());
	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 10'000; i++) {
		if (unTestingRVA != cRTTI1.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (10 000 calls)              = %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());
	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 500'000; i++) {
		if (unTestingRVA != cRTTI1.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (500 000 calls)             = %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());
	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 1'000'000; i++) {
		if (unTestingRVA != cRTTI1.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (1 000 000 calls)           = %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());
	t1 = high_resolution_clock::now();
	for (unsigned char i = 0; i < 10; i++) {
		if (unTestingRVA != cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (10 calls + NoCache)        = %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());
	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 10'000; i++) {
		if (unTestingRVA != cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (10 000 calls + NoCache)    = %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());
	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 50'000; i++) {
		if (unTestingRVA != cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (50 000 calls + NoCache)    = %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());
	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 100'000; i++) {
		if (unTestingRVA != cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (100 000 calls + NoCache)   = %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	if (!unTestingRVA) {
		printf("Error: TestingDLL RVA VTable not found.\n");
		return -1;
	}

	void** pTestingDLL_VT = reinterpret_cast<void**>(reinterpret_cast<char*>(hTestDLL) + unTestingRVA);

	fnIsTrue IsTrue = reinterpret_cast<fnIsTrue>(pTestingDLL_VT[0]);
	fnHelloWorld HelloWorld = reinterpret_cast<fnHelloWorld>(pTestingDLL_VT[1]);
	
	printf("IsTrue = %s\n", IsTrue(pTestingDLL_VT, nullptr) ? "true" : "false");
	printf("HelloWorld = %s\n", HelloWorld(pTestingDLL_VT, nullptr));

	return 0;
}