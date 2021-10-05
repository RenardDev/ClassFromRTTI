#pragma once

#ifndef _RTTI_H_
#define _RTTI_H_

#define RTTI_DEFAULT_MAX_SYMBOL_LENGTH 0x7FF // 0x7FF - Max for MSVC
//#define RTTI_EXPERIMENTAL_FEATURES
#define RTTI_EXPERIMENTAL_OPTIMIZATION

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
#ifdef RTTI_EXPERIMENTAL_FEATURES
typedef std::tuple<std::string, vecSymbolsOffsets> FileSymbolsOffsets; // <file>
#endif // RTTI_EXPERIMENTAL_FEATURES
typedef std::vector<RangeSymbolsOffsets> vecRangesSymbolsOffsets, * pvecRangesSymbolsOffsets; // <ranges>
typedef std::vector<ModuleSymbolsOffsets> vecModulesSymbolsOffsets, * pvecModulesSymbolsOffsets; // <modules>
#ifdef RTTI_EXPERIMENTAL_FEATURES
typedef std::vector<FileSymbolsOffsets> vecFilesSymbolsOffsets, * pvecFilesSymbolsOffsets; // <files>
#endif // RTTI_EXPERIMENTAL_FEATURES

//---------------------------------------------------------------------------------
// RTTI interface
//---------------------------------------------------------------------------------
class RTTI {
public:
#ifdef RTTI_EXPERIMENTAL_FEATURES
	RTTI(bool bAutoScanIntoCache = false, bool bCaching = false, bool bRangeCaching = false, bool bModulesCaching = false, bool bFilesCaching = false);
#else // RTTI_EXPERIMENTAL_FEATURES
	RTTI(bool bCaching = false, bool bRangeCaching = false, bool bModulesCaching = false, bool bFilesCaching = false);
#endif // !RTTI_EXPERIMENTAL_FEATURES
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
#ifdef RTTI_EXPERIMENTAL_FEATURES
	uintptr_t FindTypeInfoOffsetFromFile(const char* szModulePath);
#endif // RTTI_EXPERIMENTAL_FEATURES
private:
	// Finding references (32 - bits)
	//  One
	void* FindReferenceAddressFromRange32(void* pBegin, void* pEnd, unsigned int unValue);
	uintptr_t FindReferenceOffsetFromRange32(void* pBegin, void* pEnd, unsigned int unValue);
	void* FindReferenceAddressFromModule32(HMODULE hModule, unsigned int unValue);
	uintptr_t FindReferenceOffsetFromModule32(HMODULE hModule, unsigned int unValue);
#ifdef RTTI_EXPERIMENTAL_FEATURES
	uintptr_t FindReferenceOffsetFromFile32(const char* szModulePath, unsigned int unValue);
#endif // RTTI_EXPERIMENTAL_FEATURES
	//  Multiple
	std::vector<void*> FindReferencesAddressesFromRange32(void* pBegin, void* pEnd, unsigned int unValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromRange32(void* pBegin, void* pEnd, unsigned int unValue);
	std::vector<void*> FindReferencesAddressesFromModule32(HMODULE hModule, unsigned int unValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromModule32(HMODULE hModule, unsigned int unValue);
#ifdef RTTI_EXPERIMENTAL_FEATURES
	std::vector<uintptr_t> FindReferencesOffsetsFromFile32(const char* szModulePath, unsigned int unValue);
#endif // RTTI_EXPERIMENTAL_FEATURES
	// Finding references (64 - bits)
	//  One
	void* FindReferenceAddressFromRange(void* pBegin, void* pEnd, void* pValue);
	uintptr_t FindReferenceOffsetFromRange(void* pBegin, void* pEnd, void* pValue);
	void* FindReferenceAddressFromModule(HMODULE hModule, void* pValue);
	uintptr_t FindReferenceOffsetFromModule(HMODULE hModule, void* pValue);
#ifdef RTTI_EXPERIMENTAL_FEATURES
	uintptr_t FindReferenceOffsetFromFile(const char* szModulePath, void* pValue);
#endif // RTTI_EXPERIMENTAL_FEATURES
	//  Multiple
	std::vector<void*> FindReferencesAddressesFromRange(void* pBegin, void* pEnd, void* pValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromRange(void* pBegin, void* pEnd, void* pValue);
	std::vector<void*> FindReferencesAddressesFromModule(HMODULE hModule, void* pValue);
	std::vector<uintptr_t> FindReferencesOffsetsFromModule(HMODULE hModule, void* pValue);
#ifdef RTTI_EXPERIMENTAL_FEATURES
	std::vector<uintptr_t> FindReferencesOffsetsFromFile(const char* szModulePath, void* pValue);
#endif // RTTI_EXPERIMENTAL_FEATURES
public:
	// Finding VTables
	//  Multiple
	vecSymbolsAddresses GetVTablesAddressesFromRange(void* pBegin, void* pEnd);
	vecSymbolsOffsets GetVTablesOffsetsFromRange(void* pBegin, void* pEnd);
	vecSymbolsAddresses GetVTablesAddressesFromModule(HMODULE hModule);
	vecSymbolsOffsets GetVTablesOffsetsFromModule(HMODULE hModule);
#ifdef RTTI_EXPERIMENTAL_FEATURES
	vecSymbolsOffsets GetVTablesOffsetsFromFile(const char* szModulePath);
#endif // RTTI_EXPERIMENTAL_FEATURES
	//  One
	void* GetVTableAddressFromRange(void* pBegin, void* pEnd, const char* szClassName);
	uintptr_t GetVTableOffsetFromRange(void* pBegin, void* pEnd, const char* szClassName);
	void* GetVTableAddressFromModule(HMODULE hModule, const char* szClassName);
	uintptr_t GetVTableOffsetFromModule(HMODULE hModule, const char* szClassName);
#ifdef RTTI_EXPERIMENTAL_FEATURES
	uintptr_t GetVTableOffsetFromFile(const char* szModulePath, const char* szClassName);
#endif // RTTI_EXPERIMENTAL_FEATURES
private:
	// Finding in cache
	void* GetVTableAddressFromRangeCache(void* pBegin, void* pEnd, const char* szClassName);
	uintptr_t GetVTableOffsetFromRangeCache(void* pBegin, void* pEnd, const char* szClassName);
	void* GetVTableAddressFromModuleCache(HMODULE hModule, const char* szClassName);
	uintptr_t GetVTableOffsetFromModuleCache(HMODULE hModule, const char* szClassName);
#ifdef RTTI_EXPERIMENTAL_FEATURES
	uintptr_t GetVTableOffsetFromFileCache(const char* szModulePath, const char* szClassName);
#endif // RTTI_EXPERIMENTAL_FEATURES
public:
	// For processing
	bool IsCacheEnabled();
#ifdef RTTI_EXPERIMENTAL_FEATURES
	pvecRangesSymbolsAddresses GetRangesAddressesCache();
	pvecModulesSymbolsAddresses GetModulesAddressesCache();
	pvecRangesSymbolsOffsets GetRangesOffsetsCache();
	pvecModulesSymbolsOffsets GetModulesOffsetsCache();
	pvecFilesSymbolsOffsets GetFilesOffsetsCache();
#endif // RTTI_EXPERIMENTAL_FEATURES
private:
	bool m_bAvailableSSE2;
	bool m_bAvailableAVX2;
#ifdef RTTI_EXPERIMENTAL_FEATURES
	void* m_pLdrRegisterDllNotification;
	void* m_pLdrUnregisterDllNotification;
	PVOID m_pCookie;
#endif // RTTI_EXPERIMENTAL_FEATURES
	bool m_bCaching;
	bool m_bRangesCaching;
	bool m_bModulesCaching;
#ifdef RTTI_EXPERIMENTAL_FEATURES
	bool m_bFilesCaching;
#endif // RTTI_EXPERIMENTAL_FEATURES
	vecRangesSymbolsAddresses m_vecRangesSymbolsAddressesCache;
	vecModulesSymbolsAddresses m_vecModulesSymbolsAddressesCache;
	vecRangesSymbolsOffsets m_vecRangesSymbolsOffsetsCache;
	vecModulesSymbolsOffsets m_vecModulesSymbolsOffsetsCache;
#ifdef RTTI_EXPERIMENTAL_FEATURES
	vecFilesSymbolsOffsets m_vecFilesSymbolsOffsetsCache;
public:
	// For processing
	std::vector<HANDLE> m_vecThreads;
#endif // RTTI_EXPERIMENTAL_FEATURES
};

#endif // !_RTTI_H_