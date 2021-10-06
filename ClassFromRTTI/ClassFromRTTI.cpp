
// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// STL
#include <chrono>
using namespace std::chrono;

// Custom
#include "RTTI.h"

#define BENCHMARK_TEST

// ecx - this
// edx - (unused)
typedef bool(__fastcall* fnIsTrue)(void* ecx, void* edx);
typedef const char*(__fastcall* fnHelloWorld)(void* ecx, void* edx);

int main() {
	RTTI cRTTI1; // Default
	RTTI cRTTI2(false, true, true, true); // With caching
	RTTI cRTTI3(true); // With min iterations
	RTTI cRTTI4(true, true, true, true); // With cache and min iterations
	
	HMODULE hTestDLL = LoadLibrary(TEXT("TestDLL.dll"));
	if (!hTestDLL) {
		printf("Error: TestDLL.dll not found.\n");
		return -1;
	}

	printf("For start press <Enter>\n");
	_CRT_UNUSED(getchar());

	uintptr_t unTestingRVA = cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL");
	printf("TestingDLL (RVA) = 0x%IX\n", unTestingRVA);

#ifdef BENCHMARK_TEST
	high_resolution_clock::time_point t1;
	high_resolution_clock::time_point t2;

	// Stage 1
	t1 = high_resolution_clock::now();
	for (unsigned char i = 0; i < 100; ++i) {
		if (unTestingRVA != cRTTI1.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (100 calls)...............................= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned short i = 0; i < 1'000; ++i) {
		if (unTestingRVA != cRTTI1.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (1 000 calls).............................= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 10'000; ++i) {
		if (unTestingRVA != cRTTI1.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (10 000 calls)............................= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 50'000; i++) {
		if (unTestingRVA != cRTTI1.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (50 000 calls)............................= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	// Stage 2
	t1 = high_resolution_clock::now();
	for (unsigned char i = 0; i < 100; ++i) {
		if (unTestingRVA != cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (100 calls + Cache).......................= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned short i = 0; i < 1'000; ++i) {
		if (unTestingRVA != cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (1 000 calls + Cache).....................= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 10'000; ++i) {
		if (unTestingRVA != cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (10 000 calls + Cache)....................= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 50'000; i++) {
		if (unTestingRVA != cRTTI2.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (50 000 calls + Cache)....................= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	// Stage 3
	t1 = high_resolution_clock::now();
	for (unsigned char i = 0; i < 100; ++i) {
		if (unTestingRVA != cRTTI3.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (100 calls + MinIterations)...............= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned short i = 0; i < 1'000; ++i) {
		if (unTestingRVA != cRTTI3.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (1 000 calls + MinIterations).............= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 10'000; ++i) {
		if (unTestingRVA != cRTTI3.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (10 000 calls + MinIterations)............= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 50'000; i++) {
		if (unTestingRVA != cRTTI3.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (50 000 calls + MinIterations)............= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());
	
	// Stage 4
	t1 = high_resolution_clock::now();
	for (unsigned char i = 0; i < 100; ++i) {
		if (unTestingRVA != cRTTI4.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (100 calls + Cache + MinIterations).......= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned short i = 0; i < 1'000; ++i) {
		if (unTestingRVA != cRTTI4.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (1 000 calls + Cache + MinIterations).....= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 10'000; ++i) {
		if (unTestingRVA != cRTTI4.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (10 000 calls + Cache + MinIterations)....= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());

	t1 = high_resolution_clock::now();
	for (unsigned int i = 0; i < 50'000; i++) {
		if (unTestingRVA != cRTTI4.GetVTableOffsetFromModule(hTestDLL, "TestingDLL")) {
			printf("Error: Data error!\n");
		}
	}
	t2 = high_resolution_clock::now();
	printf("Bench (50 000 calls + Cache + MinIterations)....= %lld ms\n", duration_cast<std::chrono::milliseconds>(t2 - t1).count());
	
#endif // BENCHMARK_TEST

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