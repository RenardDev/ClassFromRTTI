#include "pch.h"

class TestingDLL
{
public:
	TestingDLL();
	~TestingDLL();
public:
	virtual bool IsTrue();
	virtual const char* HelloWorld();
};

TestingDLL::TestingDLL() {
	// Nothing...
}

TestingDLL::~TestingDLL() {
	// Nothing...
}

bool TestingDLL::IsTrue() {
	return true;
}

const char* TestingDLL::HelloWorld() {
	return "Hello, World!";
}

__declspec(dllexport) TestingDLL* g_pTestingDLL = nullptr;

BOOL APIENTRY DllMain( HMODULE hModule,
					   DWORD  ul_reason_for_call,
					   LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_pTestingDLL = new TestingDLL;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		if (g_pTestingDLL) {
			delete g_pTestingDLL;
		}
		break;
	}
	return TRUE;
}

