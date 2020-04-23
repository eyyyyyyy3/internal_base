#include "Memory.h"
#ifdef _WIN32 
#define _KernelMemory  0x80000000
#else 
#define _KernelMemory 0x7FFFFFFFFFFF
#endif

uintptr_t Memory::trampolineHook(uintptr_t _Dst, uintptr_t _Src, size_t _Size)
{
	DWORD oldProtection, newProtection;

	if (_Size > 4)
	{
		VirtualProtect((LPVOID)_Src, _Size, PAGE_EXECUTE_READWRITE, &oldProtection);

		uintptr_t gate = (uintptr_t)VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		for (size_t i = 0; i < _Size; i++)
		{
			if (*(BYTE*)(_Src + i) == (BYTE)0xE8)
			{
				uintptr_t relative_offset_redirect = ((*((uintptr_t*)(_Src + i + 1)) + (uintptr_t)(_Src + i + 5)) - (gate + i + 5));

				*(BYTE*)(gate + i) = *(BYTE*)(_Src + i); *(uintptr_t*)(gate + i + 1) = relative_offset_redirect; i += 4;
			}
			else
			{
				*(BYTE*)(gate + i) = *(BYTE*)(_Src + i);
			}
		}

		uintptr_t relative_offset_gate = ((_Src - gate) - 5);
		*(BYTE*)(gate + _Size) = 0xE9; *(uintptr_t*)(gate + _Size + 1) = relative_offset_gate;


		memset((LPVOID)_Src, 0x90, _Size);
		uintptr_t relative_offset = ((_Dst - _Src) - 5);
		*(BYTE*)_Src = 0xE9; *(uintptr_t*)(_Src + 1) = relative_offset;
		VirtualProtect((LPVOID)_Src, _Size, oldProtection, &newProtection);

		return gate;
	}
	return NULL;
}

uintptr_t Memory::trampolineHook(uintptr_t _Dst, uintptr_t _Src, size_t _Size, size_t _SkipBytes)
{
	DWORD oldProtection, newProtection;

	if (_Size > 4 && (_SkipBytes + _Size) <= sizeof(MEMORY_BASIC_INFORMATION))
	{
		VirtualProtect((LPVOID)(_Src + _SkipBytes), _Size, PAGE_EXECUTE_READWRITE, &oldProtection);

		uintptr_t gate = (uintptr_t)VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		for (size_t i = 0; i < _Size; i++)
		{
			if (*(BYTE*)(_Src + _SkipBytes + i) == (BYTE)0xE8)
			{
				uintptr_t relative_offset_redirect = ((*((uintptr_t*)(_Src + _SkipBytes + i + 1)) + (uintptr_t)(_Src + _SkipBytes + i + 5)) - (gate + i + 5));

				*(BYTE*)(gate + i) = *(BYTE*)(_Src + _SkipBytes + i); *(uintptr_t*)(gate + i + 1) = relative_offset_redirect; i += 4;
			}
			else
			{
				*(BYTE*)(gate + i) = *(BYTE*)(_Src + _SkipBytes + i);
			}
		}

		uintptr_t relative_offset_gate = (((_Src + _SkipBytes) - gate) - 5);
		*(BYTE*)(gate + _Size) = 0xE9; *(uintptr_t*)(gate + _Size + 1) = relative_offset_gate;


		memset((LPVOID)(_Src + _SkipBytes), 0x90, _Size);
		uintptr_t relative_offset = ((_Dst - (_Src + _SkipBytes)) - 5);
		*(BYTE*)(_Src + _SkipBytes) = 0xE9; *(uintptr_t*)((_Src + _SkipBytes) + 1) = relative_offset;
		VirtualProtect((LPVOID)(_Src + _SkipBytes), _Size, oldProtection, &newProtection);

		return gate;
	}
	return NULL;
}

uintptr_t  Memory::VTableFunctionSwap(uintptr_t _Dst, uintptr_t _Src, size_t _Offset) {
	uintptr_t ptrVtable = *((uintptr_t*)_Src);
	uintptr_t ptrFunction = ptrVtable + sizeof(uintptr_t) * _Offset;
	uintptr_t ptrOriginal = *((uintptr_t*)ptrFunction);

	MEMORY_BASIC_INFORMATION _MemoryInfo;
	VirtualQuery((LPCVOID)ptrFunction, &_MemoryInfo, sizeof(_MemoryInfo));
	VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, PAGE_EXECUTE_READWRITE, &_MemoryInfo.Protect);
	*((uintptr_t*)ptrFunction) = _Dst;
	VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, _MemoryInfo.Protect, &_MemoryInfo.Protect);
	return ptrOriginal;
}

uintptr_t Memory::VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset, size_t _Size)
{
	if (_Size > 4)
	{
		uintptr_t ptrVtable = *((uintptr_t*)_Src);
		uintptr_t ptrFunction = ptrVtable + sizeof(uintptr_t) * _Offset;
		uintptr_t ptrOriginal = *((uintptr_t*)ptrFunction);

		MEMORY_BASIC_INFORMATION _MemoryInfo;
		VirtualQuery((LPCVOID)ptrOriginal, &_MemoryInfo, sizeof(_MemoryInfo));
		VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, PAGE_EXECUTE_READWRITE, &_MemoryInfo.Protect);

		uintptr_t gate = (uintptr_t)VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		for (size_t i = 0; i < _Size; i++)
		{
			if (*(BYTE*)(ptrOriginal + i) == (BYTE)0xE8)
			{
				uintptr_t relative_offset_redirect = ((*((uintptr_t*)(ptrOriginal + i + 1)) + (uintptr_t)(ptrOriginal + i + 5)) - (gate + i + 5));

				*(BYTE*)(gate + i) = *(BYTE*)(ptrOriginal + i); *(uintptr_t*)(gate + i + 1) = relative_offset_redirect; i += 4;
			}
			else
			{
				*(BYTE*)(gate + i) = *(BYTE*)(ptrOriginal + i);
			}
		}


		uintptr_t relative_offset_gate = ((ptrOriginal - gate) - 5);
		*(BYTE*)(gate + _Size) = 0xE9; *(uintptr_t*)(gate + _Size + 1) = relative_offset_gate;


		memset((LPVOID)ptrOriginal, 0x90, _Size);
		uintptr_t relative_offset = ((_Dst - ptrOriginal) - 5);
		*(BYTE*)ptrOriginal = 0xE9; *(uintptr_t*)(ptrOriginal + 1) = relative_offset;
		VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, _MemoryInfo.Protect, &_MemoryInfo.Protect);
		return gate;
	}
	return NULL;
}

uintptr_t Memory::VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset, size_t _Size, size_t _SkipBytes)
{
	//if (_Size > 4) // maybe < instead of <=
	if (_Size > 4 && (_SkipBytes + _Size) <= sizeof(MEMORY_BASIC_INFORMATION)) // maybe < instead of <=
	{
		uintptr_t ptrVtable = *((uintptr_t*)_Src);
		uintptr_t ptrFunction = ptrVtable + sizeof(uintptr_t) * _Offset;
		uintptr_t ptrOriginal = *((uintptr_t*)ptrFunction);

		MEMORY_BASIC_INFORMATION _MemoryInfo;
		VirtualQuery((LPCVOID)ptrOriginal, &_MemoryInfo, sizeof(_MemoryInfo));
		//VirtualQuery((LPCVOID)(ptrOriginal + _SkipBytes), &_MemoryInfo, sizeof(_MemoryInfo));
		VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, PAGE_EXECUTE_READWRITE, &_MemoryInfo.Protect);

		uintptr_t gate = (uintptr_t)VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		for (size_t i = 0; i < _Size; i++)
		{
			if (*(BYTE*)(ptrOriginal + _SkipBytes + i) == (BYTE)0xE8)
			{
				uintptr_t relative_offset_redirect = ((*((uintptr_t*)(ptrOriginal + _SkipBytes + i + 1)) + (uintptr_t)(ptrOriginal + _SkipBytes + i + 5)) - (gate + i + 5));

				*(BYTE*)(gate + i) = *(BYTE*)(ptrOriginal + _SkipBytes + i); *(uintptr_t*)(gate + i + 1) = relative_offset_redirect; i += 4;
			}
			else
			{
				*(BYTE*)(gate + i) = *(BYTE*)(ptrOriginal + _SkipBytes + i);
			}
		}

		uintptr_t relative_offset_gate = (((ptrOriginal + _SkipBytes) - gate) - 5);
		*(BYTE*)(gate + _Size) = 0xE9; *(uintptr_t*)(gate + _Size + 1) = relative_offset_gate;


		memset((LPVOID)(ptrOriginal + _SkipBytes), 0x90, _Size);
		uintptr_t relative_offset = ((_Dst - (ptrOriginal + _SkipBytes)) - 5);
		*(BYTE*)(ptrOriginal + _SkipBytes) = 0xE9; *(uintptr_t*)(ptrOriginal + _SkipBytes + 1) = relative_offset;
		VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, _MemoryInfo.Protect, &_MemoryInfo.Protect);
		return gate;
	}
	return NULL;
}

Memory::Module Memory::LoadModule(char* _Module)
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Memory::_ProcessID);
	if (hModule != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 _ME;
		_ME.dwSize = sizeof(_ME);
		if (Module32First(hModule, &_ME))
		{
			do
			{
				if (!strcmp(_ME.szModule, _Module))
				{
					CloseHandle(hModule);
					return { (uintptr_t)_ME.hModule, _ME.modBaseSize };
				}
			} while (Module32Next(hModule, &_ME));
		}
	}
	return { (uintptr_t)false, (uintptr_t)false };
}

bool Memory::CompareData(const BYTE* _PDATA, const BYTE* _PMASK, const char* _PSZMASK)
{
	for (; *_PSZMASK; ++_PDATA, ++_PMASK, ++_PSZMASK)
	{
		if (*_PSZMASK == 'x' && *_PDATA != *_PMASK)
			return false;
	}

	return (*_PSZMASK == NULL);
}

uintptr_t Memory::FindPattern(char* _Module, const char* _Signature, const char* _Mask)
{
	Memory::Module _ModuleInfo;
	_ModuleInfo = Memory::LoadModule(_Module);
	if (_ModuleInfo.lpBaseOfDll != NULL || _ModuleInfo.SizeOfImage != NULL)
	{
		BYTE* data = new BYTE[_ModuleInfo.SizeOfImage];

		unsigned long bytesRead;

		if (!ReadProcessMemory(Memory::_Process, (LPCVOID)_ModuleInfo.lpBaseOfDll, data, _ModuleInfo.SizeOfImage, &bytesRead))
		{
			return NULL;
		}

		for (uintptr_t i = 0; i < _ModuleInfo.SizeOfImage; i++)
		{
			if (Memory::CompareData((const BYTE*)(data + i), (const BYTE*)_Signature, _Mask))
			{
				return ((uintptr_t)_ModuleInfo.lpBaseOfDll + i);
			}
		}
	}
	return NULL;
}

uintptr_t Memory::FindPattern(const char* _Signature, const char* _Mask, uintptr_t _Protect)
{
	for (uintptr_t i = 0; i < _KernelMemory; i++)
	{
		MEMORY_BASIC_INFORMATION _MemoryInfo = { 0 };
		if (!VirtualQuery((LPCVOID)i, &_MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			continue;
		}
		if (_MemoryInfo.Protect & _Protect)
		{
			BYTE* data = new BYTE[_MemoryInfo.RegionSize];
			for (uintptr_t k = 0; k < _MemoryInfo.RegionSize; k++)
			{
				if (Memory::CompareData((const BYTE*)(data + k), (const BYTE*)_Signature, _Mask))
				{
					return i;
				}
			}
		}
		i += _MemoryInfo.RegionSize;
	}
	return 0;
}

uintptr_t Memory::FindArray(char* _Module, const char* _Mask, int argCount, ...)
{
	char* signature = new char[argCount + 1];

	va_list ap;
	va_start(ap, argCount);

	for (int i = 0; i < argCount; i++)
	{
		char argument = va_arg(ap, char);
		signature[i] = argument;
	}

	signature[argCount] = '\0';

	va_end(ap);

	return Memory::FindPattern(_Module, signature, _Mask);
}

int Memory::GetThreadList(uintptr_t _ThreadArray[])
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, Memory::_ProcessID);
	int _TC = 0;
	if (hModule != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 _TE;
		_TE.dwSize = sizeof(_TE);
		if (Thread32First(hModule, &_TE))
		{
			do {
				if (_TE.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(_TE.th32OwnerProcessID)) {
					_ThreadArray[_TC] = _TE.th32OwnerProcessID;
					_TC += 1;
				}
			} while (Thread32Next(hModule, &_TE));
		}
		CloseHandle(hModule);
	}
	return _TC;
}

HANDLE Memory::GetProcess()
{
	return Memory::_Process;
}

uintptr_t Memory::GetProcessID()
{
	return Memory::_ProcessID;
}



