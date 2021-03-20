#include "Memory.h"
#ifdef _WIN32 
#define _KernelMemory  0x80000000
#else 
#define _KernelMemory 0x7FFFFFFFFFFF
#endif

#define R (*b >> 4)
#define C (*b & 0xF)

#define MaxRecalcArray 5

static const uint8_t prefixes[] = { 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67 };
static const uint8_t op1modrm[] = { 0x62, 0x63, 0x69, 0x6B, 0xC0, 0xC1, 0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7, 0xFE, 0xFF };
static const uint8_t op1imm8[] = { 0x6A, 0x6B, 0x80, 0x82, 0x83, 0xA8, 0xC0, 0xC1, 0xC6, 0xCD, 0xD4, 0xD5, 0xEB };
static const uint8_t op1imm32[] = { 0x68, 0x69, 0x81, 0xA9, 0xC7, 0xE8, 0xE9 };
static const uint8_t op2modrm[] = { 0x0D, 0xA3, 0xA4, 0xA5, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };


uintptr_t Memory::trampolineHook(uintptr_t _Dst, uintptr_t _Src)
{
	size_t _Size = 0;
	size_t _RecalcArray[MaxRecalcArray];
	int _Index = 0;

	do {
		if (_Index < MaxRecalcArray && (*(BYTE*)(_Src + _Size) == (BYTE)0xE8))
		{
			_RecalcArray[_Index] = _Size;
			_Index += 1;
		}
		_Size += Memory::GetInstructionLenght(_Src + _Size);
	} while (_Size < 4);	DWORD oldProtection, newProtection;

	VirtualProtect(reinterpret_cast<void*>(_Src), _Size, PAGE_EXECUTE_READWRITE, &oldProtection);

	uintptr_t gate = reinterpret_cast<uintptr_t>(VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	memcpy(reinterpret_cast<void*>(gate), reinterpret_cast<const void*>(_Src), _Size);

	if (_Index)
	{
		for (int i = 0; i < _Index; i++)
		{
			*(uintptr_t*)(gate + _RecalcArray[i] + 1) = (*(uintptr_t*)(_Src + _RecalcArray[i] + 1) + (uintptr_t)(_Src + _RecalcArray[i] + 5)) - (gate + _RecalcArray[i] + 5);
			/*uintptr_t relative_offset_redirect = (*(uintptr_t*)(function_address + _RecalcArray[i] + 1) + (uintptr_t)(function_address + _RecalcArray[i] + 5)) - (gate + _RecalcArray[i] + 5);
			memcpy(reinterpret_cast<void*>(gate + _RecalcArray[i] + 1), reinterpret_cast<void*>(&relative_offset_redirect), sizeof(relative_offset_redirect));*/
		}
	}

	uintptr_t relative_offset_gate = ((_Src - gate) - 5);
	memset(reinterpret_cast<void*>(gate + _Size), 0xE9, 1);
	memcpy(reinterpret_cast<void*>(gate + _Size + 1), reinterpret_cast<const void*>(&relative_offset_gate), sizeof(relative_offset_gate));


	memset(reinterpret_cast<void*>(_Src), 0x90, _Size);
	uintptr_t relative_offset = ((_Dst - _Src) - 5);
	memset(reinterpret_cast<void*>(_Src), 0xE9, 1);
	memcpy(reinterpret_cast<void*>(_Src + 1), reinterpret_cast<const void*>(&relative_offset), sizeof(relative_offset));
	VirtualProtect(reinterpret_cast<void*>(_Src), _Size, oldProtection, &newProtection);

	return gate;

}

uintptr_t Memory::trampolineHook(uintptr_t _Dst, uintptr_t _Src, size_t _Size)
{
	DWORD oldProtection, newProtection;

	if (_Size > 4)
	{
		VirtualProtect(reinterpret_cast<void*>(_Src), _Size, PAGE_EXECUTE_READWRITE, &oldProtection);

		uintptr_t gate = reinterpret_cast<uintptr_t>(VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		memcpy(reinterpret_cast<void*>(gate), reinterpret_cast<const void*>(_Src), _Size);

		for (size_t i = 0; i < _Size; i += Memory::GetInstructionLenght(_Src + i))
		{
			if (Memory::RecalculateInstruction(*(BYTE*)(_Src + i)))
			{
				*(uintptr_t*)(gate + i + 1) = (*(uintptr_t*)(_Src + i + 1) + (uintptr_t)(_Src + i + 5)) - (gate + i + 5);
			}
		}

		uintptr_t relative_offset_gate = ((_Src - gate) - 5);
		memset(reinterpret_cast<void*>(gate + _Size), 0xE9, 1);
		memcpy(reinterpret_cast<void*>(gate + _Size + 1), reinterpret_cast<const void*>(&relative_offset_gate), sizeof(relative_offset_gate));


		memset(reinterpret_cast<void*>(_Src), 0x90, _Size);
		uintptr_t relative_offset = ((_Dst - _Src) - 5);
		memset(reinterpret_cast<void*>(_Src), 0xE9, 1);
		memcpy(reinterpret_cast<void*>(_Src + 1), reinterpret_cast<const void*>(&relative_offset), sizeof(relative_offset));
		VirtualProtect(reinterpret_cast<void*>(_Src), _Size, oldProtection, &newProtection);

		return gate;
	}
	return NULL;
}

uintptr_t Memory::trampolineHook(uintptr_t _Dst, uintptr_t _Src, size_t _Size, size_t _SkipBytes)
{
	DWORD oldProtection, newProtection;

	if (_Size > 4)
	{
		VirtualProtect(reinterpret_cast<void*>(_Src + _SkipBytes), _Size, PAGE_EXECUTE_READWRITE, &oldProtection);

		uintptr_t gate = reinterpret_cast<uintptr_t>(VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		memcpy(reinterpret_cast<void*>(gate), reinterpret_cast<const void*>(_Src + _SkipBytes), _Size);

		for (size_t i = 0; i < _Size; i += Memory::GetInstructionLenght(_Src + _SkipBytes + i))
		{
			if (Memory::RecalculateInstruction(*(BYTE*)(_Src + _SkipBytes + i)))
			{
				*(uintptr_t*)(gate + i + 1) = (*(uintptr_t*)(_Src + _SkipBytes + i + 1) + (uintptr_t)(_Src + _SkipBytes + i + 5)) - (gate + i + 5);
			}
		}

		uintptr_t relative_offset_gate = (((_Src + _SkipBytes) - gate) - 5);
		memset(reinterpret_cast<void*>(gate + _Size), 0xE9, 1);
		memcpy(reinterpret_cast<void*>(gate + _Size + 1), reinterpret_cast<const void*>(&relative_offset_gate), sizeof(relative_offset_gate));


		memset(reinterpret_cast<void*>(_Src + _SkipBytes), 0x90, _Size);
		uintptr_t relative_offset = ((_Dst - (_Src + _SkipBytes)) - 5);
		memset(reinterpret_cast<void*>(_Src + _SkipBytes), 0xE9, 1);
		memcpy(reinterpret_cast<void*>(_Src + _SkipBytes + 1), reinterpret_cast<const void*>(&relative_offset), sizeof(relative_offset));
		VirtualProtect(reinterpret_cast<void*>(_Src + _SkipBytes), _Size, oldProtection, &newProtection);

		return gate;
	}
	return NULL;
}

uintptr_t  Memory::VTableFunctionSwap(uintptr_t _Dst, uintptr_t _Src, size_t _Offset)
{
	uintptr_t ptrVtable = *reinterpret_cast<uintptr_t*>(_Src);
	uintptr_t ptrFunction = ptrVtable + sizeof(uintptr_t) * _Offset;
	uintptr_t ptrOriginal = *reinterpret_cast<uintptr_t*>(ptrFunction);

	MEMORY_BASIC_INFORMATION _MemoryInfo;
	VirtualQuery(reinterpret_cast<LPCVOID>(ptrFunction), &_MemoryInfo, sizeof(_MemoryInfo));
	VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, PAGE_EXECUTE_READWRITE, &_MemoryInfo.Protect);
	memcpy(reinterpret_cast<void*>(ptrFunction), reinterpret_cast<const void*>(_Dst), sizeof(_Dst));
	VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, _MemoryInfo.Protect, &_MemoryInfo.Protect);
	return ptrOriginal;
}

uintptr_t Memory::VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset)
{
	size_t _Size = 0;
	size_t _RecalcArray[MaxRecalcArray];
	int _Index = 0;
	uintptr_t function_address = Memory::GetVTableFunction<uintptr_t>(_Src, _Offset);
	do {
		if (_Index < MaxRecalcArray && Memory::RecalculateInstruction(*(BYTE*)(function_address + _Size)))
		{
			_RecalcArray[_Index] = _Size;
			_Index += 1;
		}
		_Size += Memory::GetInstructionLenght(function_address + _Size);
	} while (_Size < 4);
	cout << _Size << endl;
	MEMORY_BASIC_INFORMATION _MemoryInfo;
	VirtualQuery(reinterpret_cast<LPCVOID>(function_address), &_MemoryInfo, sizeof(_MemoryInfo));
	VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, PAGE_EXECUTE_READWRITE, &_MemoryInfo.Protect);

	uintptr_t gate = reinterpret_cast<uintptr_t>(VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	memcpy(reinterpret_cast<void*>(gate), reinterpret_cast<const void*>(function_address), _Size);

	if (_Index)
	{
		for (int i = 0; i < _Index; i++)
		{
			*(uintptr_t*)(gate + _RecalcArray[i] + 1) = (*(uintptr_t*)(function_address + _RecalcArray[i] + 1) + (uintptr_t)(function_address + _RecalcArray[i] + 5)) - (gate + _RecalcArray[i] + 5);
			/*uintptr_t relative_offset_redirect = (*(uintptr_t*)(function_address + _RecalcArray[i] + 1) + (uintptr_t)(function_address + _RecalcArray[i] + 5)) - (gate + _RecalcArray[i] + 5);
			memcpy(reinterpret_cast<void*>(gate + _RecalcArray[i] + 1), reinterpret_cast<void*>(&relative_offset_redirect), sizeof(relative_offset_redirect));*/
		}
	}


	uintptr_t relative_offset_gate = ((function_address - gate) - 5);
	memset(reinterpret_cast<void*>(gate + _Size), 0xE9, 1);
	memcpy(reinterpret_cast<void*>(gate + _Size + 1), reinterpret_cast<const void*>(&relative_offset_gate), sizeof(relative_offset_gate));

	memset(reinterpret_cast<void*>(function_address), 0x90, _Size);
	uintptr_t relative_offset = ((_Dst - function_address) - 5);
	memset(reinterpret_cast<void*>(function_address), 0xE9, 1);
	memcpy(reinterpret_cast<void*>(function_address + 1), reinterpret_cast<const void*>(&relative_offset), sizeof(relative_offset));
	VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, _MemoryInfo.Protect, &_MemoryInfo.Protect);
	return gate;
}

uintptr_t Memory::VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset, size_t _Size)
{
	if (_Size > 4)
	{
		uintptr_t function_address = Memory::GetVTableFunction<uintptr_t>(_Src, _Offset);

		MEMORY_BASIC_INFORMATION _MemoryInfo;
		VirtualQuery(reinterpret_cast<LPCVOID>(function_address), &_MemoryInfo, sizeof(_MemoryInfo));
		VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, PAGE_EXECUTE_READWRITE, &_MemoryInfo.Protect);

		uintptr_t gate = reinterpret_cast<uintptr_t>(VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		memcpy(reinterpret_cast<void*>(gate), reinterpret_cast<const void*>(function_address), _Size);

		for (size_t i = 0; i < _Size; i += Memory::GetInstructionLenght(function_address + i))
		{
			if (Memory::RecalculateInstruction(*(BYTE*)(function_address + i)))
			{
				*(uintptr_t*)(gate + i + 1) = (*(uintptr_t*)(function_address + i + 1) + (uintptr_t)(function_address + i + 5)) - (gate + i + 5);
			}
		}

		uintptr_t relative_offset_gate = ((function_address - gate) - 5);
		memset(reinterpret_cast<void*>(gate + _Size), 0xE9, 1);
		memcpy(reinterpret_cast<void*>(gate + _Size + 1), reinterpret_cast<const void*>(&relative_offset_gate), sizeof(relative_offset_gate));


		memset(reinterpret_cast<void*>(function_address), 0x90, _Size);
		uintptr_t relative_offset = ((_Dst - function_address) - 5);
		memset(reinterpret_cast<void*>(function_address), 0xE9, 1);
		memcpy(reinterpret_cast<void*>(function_address + 1), reinterpret_cast<const void*>(&relative_offset), sizeof(relative_offset));
		VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, _MemoryInfo.Protect, &_MemoryInfo.Protect);
		return gate;
	}
	return NULL;
}

uintptr_t Memory::VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset, size_t _Size, size_t _SkipBytes)
{
	if (_Size > 4)//&& (_SkipBytes + _Size) <= sizeof(MEMORY_BASIC_INFORMATION)) // maybe < instead of <=
	{

		uintptr_t function_address = Memory::GetVTableFunction<uintptr_t>(_Src, _Offset);

		MEMORY_BASIC_INFORMATION _MemoryInfo;
		VirtualQuery(reinterpret_cast<LPCVOID>(function_address + _SkipBytes), &_MemoryInfo, sizeof(_MemoryInfo));
		//VirtualQuery((LPCVOID)(function_address + _SkipBytes), &_MemoryInfo, sizeof(_MemoryInfo));
		VirtualProtect(_MemoryInfo.BaseAddress, _MemoryInfo.RegionSize, PAGE_EXECUTE_READWRITE, &_MemoryInfo.Protect);

		uintptr_t gate = reinterpret_cast<uintptr_t>(VirtualAlloc(NULL, (_Size + 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		memcpy(reinterpret_cast<void*>(gate), reinterpret_cast<const void*>(function_address + _SkipBytes), _Size);

		for (size_t i = 0; i < _Size; i += Memory::GetInstructionLenght(function_address + _SkipBytes + i))
		{
			if (Memory::RecalculateInstruction(*(BYTE*)(function_address + _SkipBytes + i)))
			{
				*(uintptr_t*)(gate + i + 1) = (*(uintptr_t*)(function_address + _SkipBytes + i + 1) + (uintptr_t)(function_address + _SkipBytes + i + 5)) - (gate + i + 5);
			}
		}


		uintptr_t relative_offset_gate = (((function_address + _SkipBytes) - gate) - 5);
		memset(reinterpret_cast<void*>(gate + _Size), 0xE9, 1);
		memcpy(reinterpret_cast<void*>(gate + _Size + 1), reinterpret_cast<const void*>(&relative_offset_gate), sizeof(relative_offset_gate));


		memset(reinterpret_cast<void*>(function_address + _SkipBytes), 0x90, _Size);
		uintptr_t relative_offset = ((_Dst - (function_address + _SkipBytes)) - 5);
		memset(reinterpret_cast<void*>(function_address), 0xE9, 1);
		memcpy(reinterpret_cast<void*>(function_address + _SkipBytes + 1), reinterpret_cast<const void*>(&relative_offset), sizeof(relative_offset));
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
					return { reinterpret_cast<uintptr_t>(_ME.hModule), _ME.modBaseSize };
				}
			} while (Module32Next(hModule, &_ME));
		}
	}
	return { static_cast<uintptr_t>(false), static_cast<uintptr_t>(false) };
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

		if (!ReadProcessMemory(Memory::_Process, reinterpret_cast<LPCVOID>(_ModuleInfo.lpBaseOfDll), data, _ModuleInfo.SizeOfImage, &bytesRead))
		{
			return NULL;
		}

		for (uintptr_t i = 0; i < _ModuleInfo.SizeOfImage; i++)
		{
			if (Memory::CompareData(reinterpret_cast<const BYTE*>(data + i), reinterpret_cast<const BYTE*>(_Signature), _Mask))
			{
				return _ModuleInfo.lpBaseOfDll + i;
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
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(i), &_MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			continue;
		}
		if (_MemoryInfo.Protect & _Protect)
		{
			BYTE* data = new BYTE[_MemoryInfo.RegionSize];
			for (uintptr_t k = 0; k < _MemoryInfo.RegionSize; k++)
			{
				if (Memory::CompareData(reinterpret_cast<const BYTE*>(data + k), reinterpret_cast<const BYTE*>(_Signature), _Mask))
				{
					return i;
				}
			}
		}
		i += _MemoryInfo.RegionSize;
	}
	return NULL;
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

size_t Memory::GetThreadList(uintptr_t _ThreadArray[])
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, Memory::_ProcessID);
	size_t _TC = 0;
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

bool findByte(const uint8_t* arr, const size_t N, const uint8_t x) { for (size_t i = 0; i < N; i++) { if (arr[i] == x) { return true; } }; return false; }

void parseModRM(uint8_t** b, const bool addressPrefix)
{
	uint8_t modrm = *++ * b;

	if (!addressPrefix || (addressPrefix && **b >= 0x40))
	{
		bool hasSIB = false; //Check for SIB byte
		if (**b < 0xC0 && (**b & 0b111) == 0b100 && !addressPrefix)
			hasSIB = true, (*b)++;

		if (modrm >= 0x40 && modrm <= 0x7F) // disp8 (ModR/M)
			(*b)++;
		else if ((modrm <= 0x3F && (modrm & 0b111) == 0b101) || (modrm >= 0x80 && modrm <= 0xBF)) //disp16,32 (ModR/M)
			*b += (addressPrefix) ? 2 : 4;
		else if (hasSIB && (**b & 0b111) == 0b101) //disp8,32 (SIB)
			*b += (modrm & 0b01000000) ? 1 : 4;
	}
	else if (addressPrefix && modrm == 0x26)
		*b += 2;
};

size_t Memory::GetInstructionLenght(uintptr_t address)
{
	if (_KernelMemory == 0x80000000)//if we are x32 bit
	{
		size_t offset = 0;
		bool operandPrefix = false, addressPrefix = false, rexW = false;
		uint8_t* b = (uint8_t*)(address);

		//Parse legacy prefixes & REX prefixes		  ||					    true if we are x64 bit
		for (int i = 0; i < 14 && findByte(prefixes, sizeof(prefixes), *b) || ((false) ? (R == 4) : false); i++, b++)
		{
			if (*b == 0x66)
				operandPrefix = true;
			else if (*b == 0x67)
				addressPrefix = true;
			else if (R == 4 && C >= 8)
				rexW = true;
		}

		//Parse opcode(s)
		if (*b == 0x0F) // 2,3 bytes
		{
			b++;
			if (*b == 0x38 || *b == 0x3A) // 3 bytes
			{
				if (*b++ == 0x3A)
					offset++;

				parseModRM(&b, addressPrefix);
			}
			else // 2 bytes
			{
				if (R == 8) //disp32
					offset += 4;
				else if ((R == 7 && C < 4) || *b == 0xA4 || *b == 0xC2 || (*b > 0xC3 && *b <= 0xC6) || *b == 0xBA || *b == 0xAC) //imm8
					offset++;

				//Check for ModR/M, SIB and displacement
				if (findByte(op2modrm, sizeof(op2modrm), *b) || (R != 3 && R > 0 && R < 7) || *b >= 0xD0 || (R == 7 && C != 7) || R == 9 || R == 0xB || (R == 0xC && C < 8) || (R == 0 && C < 4))
					parseModRM(&b, addressPrefix);
			}
		}
		else // 1 byte
		{
			//Check for immediate field
			if ((R == 0xE && C < 8) || (R == 0xB && C < 8) || R == 7 || (R < 4 && (C == 4 || C == 0xC)) || (*b == 0xF6 && !(*(b + 1) & 48)) || findByte(op1imm8, sizeof(op1imm8), *b)) //imm8
				offset++;
			else if (*b == 0xC2 || *b == 0xCA) //imm16
				offset += 2;
			else if (*b == 0xC8) //imm16 + imm8
				offset += 3;
			else if ((R < 4 && (C == 5 || C == 0xD)) || (R == 0xB && C >= 8) || (*b == 0xF7 && !(*(b + 1) & 48)) || findByte(op1imm32, sizeof(op1imm32), *b)) //imm32,16
				offset += (rexW) ? 8 : (operandPrefix ? 2 : 4);
			else if (R == 0xA && C < 4)
				offset += (rexW) ? 8 : (addressPrefix ? 2 : 4);
			else if (*b == 0xEA || *b == 0x9A) //imm32,48
				offset += operandPrefix ? 4 : 6;

			//Check for ModR/M, SIB and displacement
			if (findByte(op1modrm, sizeof(op1modrm), *b) || (R < 4 && (C < 4 || (C >= 8 && C < 0xC))) || R == 8 || (R == 0xD && C >= 8))
				parseModRM(&b, addressPrefix);
		}

		return (size_t)((ptrdiff_t)(++b + offset) - (ptrdiff_t)(address));
	}
}

bool Memory::RecalculateInstruction(BYTE _Byte)
{
	if (_Byte == (BYTE)0xE8)
	{
		return true;
	}
	return false;
}

Memory memory;