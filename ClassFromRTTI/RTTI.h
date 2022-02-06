#pragma once

#ifndef _RTTI_H_
#define _RTTI_H_

// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

// C++
#include <cstdint>

// API
void* FindRTTI(void* pBegin, void* pEnd, const char* szName);
void* FindRTTI(HMODULE hModule, const char* szName);
void* FindRTTI(const char* szModule, const char* szName);
void* FindRTTI(const wchar_t* szModule, const char* szName);

#endif // !_RTTI_H_
