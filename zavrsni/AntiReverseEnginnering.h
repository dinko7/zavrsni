/*
Copyright 2018, Dinko Marinac

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions :

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*
	This header contains several anti-reverse tehniques implemented as functions.
*/


#pragma once

#include <windows.h>
#include <wchar.h>
#include <iostream>
#include "REutility.h"
using namespace std;

/*
	Sources used to create this header:
	https://www.codeproject.com/Articles/1090943/Anti-Debug-Protection-Techniques-Implementation-an
	https://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide
*/

/*
 HideThread will attempt to use NtSetInformationThread to hide a thread
 from the debugger. Function returns true if thread is successfully hidden
 and false otherwise.
*/
inline bool HideThread(HANDLE hThread)
{
	typedef NTSTATUS (NTAPI *pNtSetInformationThread)
		(HANDLE, UINT, PVOID, ULONG);
	NTSTATUS Status;

	// Get NtSetInformationThread
	pNtSetInformationThread NtSIT = (pNtSetInformationThread)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
		               "NtSetInformationThread");

	//if info is null or there is no thread in argument
	if (NtSIT == nullptr || hThread == nullptr)
		return false;

	Status = NtSIT(hThread, 0x11, nullptr, 0);
	//0x11 -> HideThreadFromDebugger

	return (Status == 0x00000000);
}

/*
Checks if program is being debugged using standard Windows API and performs actions
to stop or slow down the reverse enginnering process.
*/
inline void DetectDebugger()
{
	if (IsDebuggerPresent())
	{
		/*if program is being debugged, mess with its behavior to confuse or irritate
		  the person debugging it.*/

		JUNK_CODE_1
		wait(getRandomTime());
		//wait function instead of sleep so it is harder to trace
		exit(0); //exit with code 0 to mess with OS
	}
}

/*
 CheckProcessDebugFlags will return true if the EPROCESS->NoDebugInherit is == FALSE, 
 the reason we check for false is because the NtQueryProcessInformation function returns the
 inverse of EPROCESS->NoDebugInherit so (!TRUE == FALSE)
 */
inline bool CheckProcessDebugFlags()
{
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD NoDebugInherit = 0;
	NTSTATUS Status;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
		               "NtQueryInformationProcess");

	Status = NtQIP(GetCurrentProcess(),
	               0x1f, // ProcessDebugFlags
	               &NoDebugInherit, 4, nullptr);

	if (Status != 0x00000000)
		return false;

	if (NoDebugInherit == FALSE)
		return true;
	return false;
}

/*
 This function uses NtQuerySystemInformation to try to retrieve a handle to the current
 process's debug object handle. If the function is successful it'll return true which means we're
 being debugged or it'll return false if it fails or the process isn't being debugged.
 */
inline bool DebugObjectCheck()
{
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	HANDLE hDebugObject = nullptr;
	NTSTATUS Status;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
		               "NtQueryInformationProcess");

	Status = NtQIP(GetCurrentProcess(),
	               0x1e, // ProcessDebugObjectHandle
	               &hDebugObject, 4, nullptr);

	if (Status != 0x00000000)
		return false;

	if (hDebugObject)
		return true;
	return false;
}

/*
	Time attack function uses ticks to count if some part of code is taking
	too long to execute and exits the program if it is true because there is
	very high change that the code is being debugged. Parameter is pointer
	to a void fucntion with no arguments, thats the part of the code that
	is being protected.
*/

typedef void (*timeAttackFunction)(void); // type for conciseness

inline void TimeAttack(timeAttackFunction protectedFunction)
{
#define SERIAL_THRESHOLD 0x10000 //10000h ticks

	DWORD Counter = GetTickCount();

	protectedFunction();

	Counter = GetTickCount() - Counter;
	if (Counter >= SERIAL_THRESHOLD)
		exit(0);
}
