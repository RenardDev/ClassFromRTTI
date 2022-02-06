#pragma once

#ifndef _RTTI_H_
#define _RTTI_H_

#define RTTI_DEFAULT_MAX_SYMBOL_LENGTH 0x7FF // 0x7FF - Max for MSVC

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
typedef std::vector<RangeSymbolsAddresses> vecRangesSymbolsAddresses, *pvecRangesSymbolsAddresses; // <ranges>
typedef std::vector<ModuleSymbolsAddresses> vecModulesSymbolsAddresses, *pvecModulesSymbolsAddresses; // <modules>

// Offset
typedef std::tuple<std::string, uintptr_t> SymbolOffset; // <symbol>:<address/offset>
typedef std::vector<SymbolOffset> vecSymbolsOffsets; // <symbols>
typedef std::tuple<RangeOfDataForRTII, vecSymbolsOffsets> RangeSymbolsOffsets; // <range>
typedef std::tuple<HMODULE, vecSymbolsOffsets> ModuleSymbolsOffsets; // <module>
typedef std::vector<RangeSymbolsOffsets> vecRangesSymbolsOffsets, *pvecRangesSymbolsOffsets; // <ranges>
typedef std::vector<ModuleSymbolsOffsets> vecModulesSymbolsOffsets, *pvecModulesSymbolsOffsets; // <modules>

//---------------------------------------------------------------------------------
// RTTI interface
//---------------------------------------------------------------------------------
class RTTI {
public:
	RTTI(bool bCaching = false, bool bRangeCaching = false, bool bModulesCaching = false, bool bForceFastMethod = false, bool bMinIters = false);
private:
	// Finding Pattern
	void* FindSignature(unsigned char* pBegin, const unsigned char* pEnd, const char* szSignature);
private:
	// Finding TypeInfo
	void* FindTypeInfoAddressFromRange(void* pBegin, void* pEnd);
public:
	// Finding VTables
	//  One
	void* GetFastVTableAddressFromRange(void* pBegin, void* pEnd, const char* szClassName);
	void* GetVTableAddressFromRange(void* pBegin, void* pEnd, const char* szClassName);
	uintptr_t GetFastVTableOffsetFromRange(void* pBegin, void* pEnd, const char* szClassName);
	uintptr_t GetVTableOffsetFromRange(void* pBegin, void* pEnd, const char* szClassName);
	void* GetVTableAddressFromModule(HMODULE hModule, const char* szClassName);
	uintptr_t GetVTableOffsetFromModule(HMODULE hModule, const char* szClassName);
	//  Multiple
	vecSymbolsAddresses GetVTablesAddressesFromRange(void* pBegin, void* pEnd);
	vecSymbolsOffsets GetVTablesOffsetsFromRange(void* pBegin, void* pEnd);
	vecSymbolsAddresses GetVTablesAddressesFromModule(HMODULE hModule);
	vecSymbolsOffsets GetVTablesOffsetsFromModule(HMODULE hModule);
private:
	// Finding in cache
	void* GetVTableAddressFromRangeCache(void* pBegin, void* pEnd, const char* szClassName);
	uintptr_t GetVTableOffsetFromRangeCache(void* pBegin, void* pEnd, const char* szClassName);
	void* GetVTableAddressFromModuleCache(HMODULE hModule, const char* szClassName);
	uintptr_t GetVTableOffsetFromModuleCache(HMODULE hModule, const char* szClassName);
private:
	bool m_bAvailableSSE2;
	bool m_bAvailableAVX2;
	bool m_bCaching;
	bool m_bRangesCaching;
	bool m_bModulesCaching;
	bool m_bForceFastMethod;
	bool m_bMinIters;
	vecRangesSymbolsAddresses m_vecRangesSymbolsAddressesCache;
	vecModulesSymbolsAddresses m_vecModulesSymbolsAddressesCache;
	vecRangesSymbolsOffsets m_vecRangesSymbolsOffsetsCache;
	vecModulesSymbolsOffsets m_vecModulesSymbolsOffsetsCache;
};

#endif // !_RTTI_H_
