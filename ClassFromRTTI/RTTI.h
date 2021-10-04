#pragma once

#ifndef _RTTI_H_
#define _RTTI_H_

#define DEFAULT_MAX_SYMBOL_LENGTH 0x7FF // 0x7FF - Max for MSVC
//#define EXPERIMENTAL_FEATURES

// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <NTSecAPI.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif // !NT_SUCCESS

// Advanced
#include <xmmintrin.h> // SSE
#include <emmintrin.h> // SSE2
#include <immintrin.h> // AVX, AVX2, FMA, FXSR, POPCNT, RDRAND, XSAVE
#include <intrin.h>    // Default

// Default libraries
#pragma comment(lib, "dbghelp.lib")

// STL
#include <tuple>
#include <string>
#include <memory>
#include <vector>

// General definitions

//  <ranges/modules/files>
//   <module>
//    <symbols>
//     <symbol>:<address/offset>

// Range of data
typedef std::tuple<void*, void*> RangeOfDataForRTII;

// Address
typedef std::tuple<std::string, void*> SymbolAddress; // <symbol>:<address/offset>
typedef std::vector<SymbolAddress> vecSymbolsAddresses; // <symbols>
typedef std::tuple<RangeOfDataForRTII, vecSymbolsAddresses> RangeSymbolsAddresses; // <range>
typedef std::tuple<HMODULE, vecSymbolsAddresses> ModuleSymbolsAddresses; // <module>
typedef std::vector<RangeSymbolsAddresses> vecRangesSymbolsAddresses, * pvecRangesSymbolsAddresses; // <ranges>
typedef std::vector<ModuleSymbolsAddresses> vecModulesSymbolsAddresses, * pvecModulesSymbolsAddresses; // <modules>

// Offset
typedef std::tuple<std::string, uintptr_t> SymbolOffset; // <symbol>:<address/offset>
typedef std::vector<SymbolOffset> vecSymbolsOffsets; // <symbols>
typedef std::tuple<RangeOfDataForRTII, vecSymbolsOffsets> RangeSymbolsOffsets; // <range>
typedef std::tuple<HMODULE, vecSymbolsOffsets> ModuleSymbolsOffsets; // <module>
typedef std::tuple<std::string, vecSymbolsOffsets> FileSymbolsOffsets; // <file>
typedef std::vector<RangeSymbolsOffsets> vecRangesSymbolsOffsets, * pvecRangesSymbolsOffsets; // <ranges>
typedef std::vector<ModuleSymbolsOffsets> vecModulesSymbolsOffsets, * pvecModulesSymbolsOffsets; // <modules>
typedef std::vector<FileSymbolsOffsets> vecFilesSymbolsOffsets, * pvecFilesSymbolsOffsets; // <files>

//---------------------------------------------------------------------------------
// RTTI interface
//---------------------------------------------------------------------------------
class RTTI {
public:
#ifdef EXPERIMENTAL_FEATURES
	RTTI(bool bAutoScanIntoCache = false, bool bCaching = false, bool bRangeCaching = false, bool bModulesCaching = false, bool bFilesCaching = false);
#else // EXPERIMENTAL_FEATURES
	RTTI(bool bCaching = false, bool bRangeCaching = false, bool bModulesCaching = false, bool bFilesCaching = false);
#endif // !EXPERIMENTAL_FEATURES
	~RTTI();
private:
	// Finding Pattern
	void* FindPattern(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature, uintptr_t unOffset = 0, bool bToAbsoluteAddress = false);
private:
	// Finding TypeInfo
	void* FindTypeInfoAddressFromRange(void* pBegin, void* pEnd);
	uintptr_t FindTypeInfoOffsetFromRange(void* pBegin, void* pEnd);
	void* FindTypeInfoAddressFromModule(HMODULE hModule);
	uintptr_t FindTypeInfoOffsetFromModule(HMODULE hModule);
	uintptr_t FindTypeInfoOffsetFromFile(const char* szModulePath);
private:
	// Finding references (32 - bits)
	//  One
	void* FindReferenceAddressFromRange32(void* pBegin, void* pEnd, unsigned int unValue);
	uintptr_t FindReferenceOffsetFromRange32(void* pBegin, void* pEnd, unsigned int unValue);
	void* FindReferenceAddressFromModule32(HMODULE hModule, unsigned int unValue);
	uintptr_t FindReferenceOffsetFromModule32(HMODULE hModule, unsigned int unValue);
	uintptr_t FindReferenceOffsetFromFile32(const char* szModulePath, unsigned int unValue);
	//  Multiple
	std::vector<void*> FindReferencesAddressesFromRange32(void* pBegin, void* pEnd, unsigned int unValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromRange32(void* pBegin, void* pEnd, unsigned int unValue);
	std::vector<void*> FindReferencesAddressesFromModule32(HMODULE hModule, unsigned int unValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromModule32(HMODULE hModule, unsigned int unValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromFile32(const char* szModulePath, unsigned int unValue);
	// Finding references (64 - bits)
	//  One
	void* FindReferenceAddressFromRange(void* pBegin, void* pEnd, void* pValue);
	uintptr_t FindReferenceOffsetFromRange(void* pBegin, void* pEnd, void* pValue);
	void* FindReferenceAddressFromModule(HMODULE hModule, void* pValue);
	uintptr_t FindReferenceOffsetFromModule(HMODULE hModule, void* pValue);
	uintptr_t FindReferenceOffsetFromFile(const char* szModulePath, void* pValue);
	//  Multiple
	std::vector<void*> FindReferencesAddressesFromRange(void* pBegin, void* pEnd, void* pValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromRange(void* pBegin, void* pEnd, void* pValue);
	std::vector<void*> FindReferencesAddressesFromModule(HMODULE hModule, void* pValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromModule(HMODULE hModule, void* pValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromFile(const char* szModulePath, void* pValue);
public:
	// Finding VTables
	//  Multiple
	vecSymbolsAddresses GetVTablesAddressesFromRange(void* pBegin, void* pEnd);
	vecSymbolsOffsets GetVTablesOffsetsFromRange(void* pBegin, void* pEnd);
	vecSymbolsAddresses GetVTablesAddressesFromModule(HMODULE hModule);
	vecSymbolsOffsets GetVTablesOffsetsFromModule(HMODULE hModule);
	vecSymbolsOffsets GetVTablesOffsetsFromFile(const char* szModulePath);
	//  One
	void* GetVTableAddressFromRange(void* pBegin, void* pEnd, const char* szClassName);
	uintptr_t GetVTableOffsetFromRange(void* pBegin, void* pEnd, const char* szClassName);
	void* GetVTableAddressFromModule(HMODULE hModule, const char* szClassName);
	uintptr_t GetVTableOffsetFromModule(HMODULE hModule, const char* szClassName);
	uintptr_t GetVTableOffsetFromFile(const char* szModulePath, const char* szClassName);
private:
	// Finding in cache
	void* GetVTableAddressFromRangeCache(void* pBegin, void* pEnd, const char* szClassName);
	uintptr_t GetVTableOffsetFromRangeCache(void* pBegin, void* pEnd, const char* szClassName);
	void* GetVTableAddressFromModuleCache(HMODULE hModule, const char* szClassName);
	uintptr_t GetVTableOffsetFromModuleCache(HMODULE hModule, const char* szClassName);
	uintptr_t GetVTableOffsetFromFileCache(const char* szModulePath, const char* szClassName);
public:
	// For processing
	bool IsCacheEnabled();
#ifdef EXPERIMENTAL_FEATURES
	pvecRangesSymbolsAddresses GetRangesAddressesCache();
	pvecModulesSymbolsAddresses GetModulesAddressesCache();
	pvecRangesSymbolsOffsets GetRangesOffsetsCache();
	pvecModulesSymbolsOffsets GetModulesOffsetsCache();
	pvecFilesSymbolsOffsets GetFilesOffsetsCache();
#endif // EXPERIMENTAL_FEATURES
private:
	bool m_bAvailableSSE2;
	bool m_bAvailableAVX2;
#ifdef EXPERIMENTAL_FEATURES
	void* m_pLdrRegisterDllNotification;
	void* m_pLdrUnregisterDllNotification;
	PVOID m_pCookie;
#endif // EXPERIMENTAL_FEATURES
	bool m_bCaching;
	bool m_bRangesCaching;
	bool m_bModulesCaching;
	bool m_bFilesCaching;
	vecRangesSymbolsAddresses m_vecRangesSymbolsAddressesCache;
	vecModulesSymbolsAddresses m_vecModulesSymbolsAddressesCache;
	vecRangesSymbolsOffsets m_vecRangesSymbolsOffsetsCache;
	vecModulesSymbolsOffsets m_vecModulesSymbolsOffsetsCache;
	vecFilesSymbolsOffsets m_vecFilesSymbolsOffsetsCache;
#ifdef EXPERIMENTAL_FEATURES
public:
	// For processing
	std::vector<HANDLE> m_vecThreads;
#endif // EXPERIMENTAL_FEATURES
};

#endif // !_RTTI_H_