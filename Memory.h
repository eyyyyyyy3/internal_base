#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <iostream>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

using namespace std;

class Memory
{
public:
	struct Module
	{
		uintptr_t lpBaseOfDll;
		uintptr_t SizeOfImage;
	};
private:
	HANDLE _Process;
	uintptr_t _ProcessID;
public:
	Memory() { _Process = GetCurrentProcess(); _ProcessID = GetCurrentProcessId(); }
	uintptr_t trampolineHook(uintptr_t _Dst, uintptr_t _Src);
	uintptr_t trampolineHook(uintptr_t _Dst, uintptr_t _Src, size_t _Size);
	uintptr_t trampolineHook(uintptr_t _Dst, uintptr_t _Src, size_t _Size, size_t _SkipBytes);
	uintptr_t VTableFunctionSwap(uintptr_t _Dst, uintptr_t _Src, size_t _Offset);
	uintptr_t VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset);
	uintptr_t VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset, size_t _Size);
	uintptr_t VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset, size_t _Size, size_t _SkipBytes);
	Memory::Module LoadModule(char* _Module);
	bool CompareData(const BYTE* _PDATA, const BYTE* _PMASK, const char* _PSZMASK);
	uintptr_t FindPattern(char* _Module, const char* _Signature, const char* _Mask);
	uintptr_t FindPattern(const char* _Signature, const char* _Mask, uintptr_t _Protect);
	uintptr_t FindArray(char* _Module, const char* _Mask, int argCount, ...);
	size_t GetThreadList(uintptr_t _ThreadArray[]);
	HANDLE GetProcess();
	uintptr_t GetProcessID();
	size_t GetInstructionLenght(uintptr_t address);

	template <typename Mem>
	Mem Read(uintptr_t dwAddress)
	{
		Mem value;
		ReadProcessMemory(_Process, (LPVOID)dwAddress, &value, sizeof(Mem), NULL);
		return value;
	}

	template <typename Mem>
	void Write(uintptr_t dwAddress, Mem value)
	{
		WriteProcessMemory(_Process, (LPVOID)dwAddress, &value, sizeof(Mem), NULL);
	}

	template<typename Mem>
	Mem GetVTableFunction(uintptr_t _Src, size_t _Offset)
	{
		uintptr_t ptrVtable = *((uintptr_t*)_Src);
		uintptr_t ptrFunction = ptrVtable + sizeof(uintptr_t) * _Offset;
		uintptr_t ptrOriginal = *((uintptr_t*)ptrFunction);
		return(Mem)(ptrOriginal);
	}

};

extern Memory memory;

