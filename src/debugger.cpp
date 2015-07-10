
/* ********************************************************** 
 *
 * wtrace
 * 2014 - Alan Gonzalez
 *
 * ********************************************************** */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <string>
#include <Dbghelp.h>

#include <iostream>

#include "output.h"
#include "Utils.h"
#include "Main.h"
#include "Debugger.h"

#define WIDE2(x) L##x
#define WIDE1(x) WIDE2(x)
#define ENTER_FN \
			dFunctionDepth++; \
			Write(WriteLevel::Debug, L"ENTERING FUNCTION " WIDE1(__FUNCTION__)); \
			dFunctionDepth++; \
			HRESULT hr = S_OK;


#define EXIT_FN \
			if (0,0) goto Exit; \
			Exit: \
			dFunctionDepth--; \
			Write(WriteLevel::Debug, L"EXITING  FUNCTION " WIDE1(__FUNCTION__)); \
			dFunctionDepth--; \
			return hr;


int gAnalysisLevel;
BYTE m_OriginalInstruction;
DWORD processNameLen;
int nSpawnedProcess;
bool bSyminitialized;
bool firstDebugEvent = 1;
std::string lastFunctionName;
long lnFunctionCalls = 0;


void Interactive()
{
	//std::cout << "input>";
	//std::string cmd;
	//std::cin >> cmd;
}

//#define UILD_WOW64_ENABLED 1 //?
#define STACKWALK_MAX_NAMELEN 1024
typedef struct CallstackEntry
{
	DWORD64 offset;  // if 0, we have no valid entry
	CHAR name[STACKWALK_MAX_NAMELEN];
	CHAR undName[STACKWALK_MAX_NAMELEN];
	CHAR undFullName[STACKWALK_MAX_NAMELEN];
	DWORD64 offsetFromSmybol;
	DWORD offsetFromLine;
	DWORD lineNumber;
	CHAR lineFileName[STACKWALK_MAX_NAMELEN];
	DWORD symType;
	LPCSTR symTypeString;
	CHAR moduleName[STACKWALK_MAX_NAMELEN];
	DWORD64 baseOfImage;
	CHAR loadedImageName[STACKWALK_MAX_NAMELEN];
} CallstackEntry;

HRESULT DumpContext(const CONTEXT& lcContext)
{
	ENTER_FN

#ifdef _X86_
	Write(WriteLevel::Debug,  L"eax=%08X ebx=%08X ecx=%08X edx=%08X esi=%08X edi=%08X",
			lcContext.Eax, lcContext.Ebx, lcContext.Ecx,
			lcContext.Edx, lcContext.Esi, lcContext.Edi);

	Write(WriteLevel::Debug,  L"eip=%08X esp=%08X ebp=%08X",
			lcContext.Eip, lcContext.Esp, lcContext.Ebp);

	Write(WriteLevel::Debug, L"eflags = %08X",
			lcContext.EFlags);

	//Write(WriteLevel::Debug,  L"cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202", );

#else
	Write(WriteLevel::Debug,  L"RIP = %08X EAX = %08X EBX = %08X ECX = %08X "
			L"RDX = %08X RSI = %08X RDI = %08X "
			L"RSP = %08X RBP = %08X "
			L"RFL = %08X",
			lcContext.Rip,
			lcContext.Rax, lcContext.Rbx, lcContext.Rcx,
			lcContext.Rdx, lcContext.Rsi, lcContext.Rdi,
			lcContext.Rsp, lcContext.Rbp,
			lcContext.EFlags
		 );
#endif

	EXIT_FN
}

HRESULT Run()
{
	ENTER_FN

	DEBUG_EVENT de = {0};
	int bCreateProcRes;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	bSyminitialized = FALSE;

	// Ref count of processes created
	nSpawnedProcess = 0;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	Write(WriteLevel::Debug, L"Creating process %s", gpCommandLine);

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	DWORD StartTicks = GetTickCount();

	bCreateProcRes = CreateProcess(NULL, gpCommandLine, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi );

	if (!bCreateProcRes)
	{
		Write(WriteLevel::Error, L"Unable to create process. hr=0x%x", GetLastError());
		goto Exit;
	}
	Write(WriteLevel::Debug, L"CreateProcess OK: "
									L"(hProcess = 0x%08LX"
									L" hThread = 0x%08LX"
									L" dwProcessId = 0x%08LX)",
									pi.hProcess,
									pi.hThread,
									pi.dwProcessId);
	nSpawnedProcess++;

	int bContinue = TRUE;
	while (bContinue)
	{
		WaitForDebugEvent(&de, INFINITE);

		Write(WriteLevel::Debug, L"EXCEPTION_DEBUG_EVENT "
									L"(dwProcessId = 0x%08LX"
									L" dwThreadId = 0x%08LX"
									L" dwDebugEventCode = 0x%08LX %s %x)",
									de.dwProcessId,
									de.dwThreadId,
									de.dwDebugEventCode,
									de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? L"ExceptionCode = 0x" : L"",
									de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? de.u.Exception.ExceptionRecord.ExceptionCode : 0);

		switch (de.dwDebugEventCode)
		{
			case EXCEPTION_DEBUG_EVENT:

				switch (de.u.Exception.ExceptionRecord.ExceptionCode)
				{
					case EXCEPTION_ACCESS_VIOLATION:
					// First chance: Pass this on to the system. 
					// Last chance: Display an appropriate error. 
					Write(WriteLevel::Debug, L"EXCEPTION_ACCESS_VIOLATION");
					// This happens when amd64 debugs x86
					break;

					case EXCEPTION_BREAKPOINT:
						ExceptionBreakpoint(pi.hThread, pi.hProcess);
					break;

					case EXCEPTION_DATATYPE_MISALIGNMENT: 
					// First chance: Pass this on to the system. 
					// Last chance: Display an appropriate error. 
					Write(WriteLevel::Debug, L"EXCEPTION_DATATYPE_MISALIGNMENT");

					break;

					case EXCEPTION_SINGLE_STEP:
						hr = ExceptionSingleStep(pi.hProcess, pi.hThread);
						if (FAILED(hr))
						{
							goto Exit;
						}
					break;

					case DBG_CONTROL_C:
					// First chance: Pass this on to the system. 
					// Last chance: Display an appropriate error. 
					Write(WriteLevel::Debug, L"\tDBG_CONTROL_C");
					break;

					case 0xc000001d:
					Write(WriteLevel::Debug, L"\tIllegal Instruction  An attempt was made to execute an illegal instruction.");
					break;

					default:
					// Handle other exceptions. 
					Write(WriteLevel::Debug, L"Unknown debug event : %x ? ", de.u.Exception.ExceptionRecord.ExceptionCode);
					break;
				}

				break;

			default:
				// Handle other exceptions. 
				Write(WriteLevel::Debug, L"    nothing to do ? ");
				break;

			 case CREATE_THREAD_DEBUG_EVENT: 
				// As needed, examine or change the thread's registers 
				// with the GetThreadContext and SetThreadContext functions; 
				// and suspend and resume thread execution with the 
				// SuspendThread and ResumeThread functions. 
				Write(WriteLevel::Debug, L"CREATE_THREAD_DEBUG_EVENT");
				break;

			 case CREATE_PROCESS_DEBUG_EVENT: 
				CreateProcessDebugEvent(de);
				break;

			 case EXIT_THREAD_DEBUG_EVENT: 
			 // Display the thread's exit code. 
				Write(WriteLevel::Debug, L"EXIT_THREAD_DEBUG_EVENT");
				break;

			 case EXIT_PROCESS_DEBUG_EVENT: 
			 // Display the process's exit code. 
				nSpawnedProcess--;

				if (nSpawnedProcess == 1)  bContinue = false;

				Write(WriteLevel::Debug, L"EXIT_PROCESS_DEBUG_EVENT");
				break;

			 case LOAD_DLL_DEBUG_EVENT: 
				LoadDllDebugEvent(de, pi.hProcess); // this is wrong for any process other than the 1 we started
				break;

			 case UNLOAD_DLL_DEBUG_EVENT: 
			 // Display a message that the DLL has been unloaded. 
				Write(WriteLevel::Debug, L"UNLOAD_DLL_DEBUG_EVENT");
				break;

			 case OUTPUT_DEBUG_STRING_EVENT: 
				// Display the output debugging string. 
				DebugStringEvent(de);

				break;

			 case RIP_EVENT:
				Write(WriteLevel::Debug, L"RIP_EVENT");
				break;
		}

		hr = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);

		if(FAILED(hr))
		{
			Write(WriteLevel::Error, L"Error.");
			break;
		}
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	DWORD TickDiff = GetTickCount() - StartTicks;

	Write(WriteLevel::Info, L"Finished after %d seconds ", TickDiff/1000 );

	EXIT_FN
}

HRESULT DebugStringEvent(const DEBUG_EVENT& de)
{
	ENTER_FN

	HANDLE hProcess = NULL;// THis will not work!

	OUTPUT_DEBUG_STRING_INFO DebugString = de.u.DebugString;

	WCHAR *msg = new WCHAR[DebugString.nDebugStringLength];
	//// Don't care if string is ANSI, and we allocate double...

	ReadProcessMemory(
			hProcess,					// HANDLE to Debuggee
			DebugString.lpDebugStringData,	// Target process' valid pointer
			msg,							// Copy to this address space
			DebugString.nDebugStringLength,
			NULL);

	if (DebugString.fUnicode)
	{
		Write(WriteLevel::Info, L"OUTPUT_DEBUG_STRING_EVENT: %s", msg);
	}
	else
	{
		Write(WriteLevel::Info, L"OUTPUT_DEBUG_STRING_EVENT: ");
	
	}

	delete [] msg;

	EXIT_FN
}

HRESULT ExceptionSingleStepWow64(HANDLE hProcess, HANDLE hThread)
{
	ENTER_FN

	WOW64_CONTEXT lcWowContext = {0};
	BOOL bResult = FALSE;

	if (gAnalysisLevel >= 3)
	{
		lcWowContext.ContextFlags = CONTEXT_ALL;

		bResult = Wow64GetThreadContext(hThread, &lcWowContext);
		if (!bResult)
		{
			Write(WriteLevel::Error, L"Wow64GetThreadContext failed 0x%x", GetLastError());
			goto Exit;
		}

		DumpContext(*((CONTEXT*)&lcWowContext));

		hr = GetCurrentFunctionName(hThread, hProcess, *((CONTEXT*)&lcWowContext));
		Write(WriteLevel::Debug, L"GetCurrentFunctionName result 0x%x", hr);
		if (FAILED(hr))
		{
			goto Exit;
		}

		Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");

		lcWowContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
		if (0 == Wow64SetThreadContext(hThread, &lcWowContext))
		{
			hr = GetLastError();
			Write(WriteLevel::Error, L"Wow64SetThreadContext failed with 0x%x.", hr);
			goto Exit;
		}

//		bResult = Wow64GetThreadContext(hThread, &lcWowContext);
//		if (!bResult)
//		{
//			Write(WriteLevel::Error, L"Wow64GetThreadContext failed 0x%x", GetLastError());
//			goto Exit;
//		}
//		DumpContext(*((CONTEXT*)&lcWowContext));
	}

	EXIT_FN

}

HRESULT ExceptionSingleStepX64(HANDLE hProcess, HANDLE hThread)
{
	ENTER_FN

	CONTEXT lcContext = {0};

	if (gAnalysisLevel >= 3)
	{
		lcContext.ContextFlags = CONTEXT_ALL;

		BOOL bResult = GetThreadContext(hThread, &lcContext);
		if (!bResult)
		{
			Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", GetLastError());
			goto Exit;
		}

		DumpContext(lcContext);

		hr = GetCurrentFunctionName(hThread, hProcess, lcContext);
		Write(WriteLevel::Debug, L"GetCurrentFunctionName result 0x%x", hr);
		if (FAILED(hr))
		{
			goto Exit;
		}

		Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");

		lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception

		if (0 == SetThreadContext(hThread, &lcContext))
		{
			hr = GetLastError();
			Write(WriteLevel::Error, L"SetThreadContext failed with 0x%x.", hr);
			goto Exit;
		}

	}

	EXIT_FN
}

HRESULT ExceptionSingleStep(HANDLE hProcess, HANDLE hThread)
{
	ENTER_FN

	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	BOOL bIsWow64 = FALSE;

	//IsWow64Process is not available on all supported versions of Windows.
	//Use GetModuleHandle to get a handle to the DLL that contains the function
	//and GetProcAddress to get a pointer to the function if available.
	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
			GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

	if(NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(hProcess, &bIsWow64))
		{
			hr = GetLastError();
			goto Exit;
		}
	}


	Write(WriteLevel::Debug, L"hProcess=0x%d is %s wow64 process",
			hProcess,
			bIsWow64 ? L"" : L"NOT");

	if (bIsWow64)
	{
		ExceptionSingleStepWow64(hProcess, hThread);
	}
	else
	{
		ExceptionSingleStepX64(hProcess, hThread);
	}

	EXIT_FN
}

HRESULT LoadDllDebugEvent(const DEBUG_EVENT& de, HANDLE hProcess)
{
	ENTER_FN

	// Read the debugging information included in the newly loaded DLL.
	WCHAR pszFilename[MAX_PATH+1];
	DWORD64 dwBase;

	GetFileNameFromHandle(de.u.LoadDll.hFile, (WCHAR *)&pszFilename);

//	IMAGEHLP_MODULE64 module_info;
//	BOOL bSuccess;

	//BOOL bRes = SymInitialize(hProcess, NULL, FALSE);

	Write(WriteLevel::Debug, L"SymLoadModuleEx on hProcess 0x%x", hProcess);
	dwBase = SymLoadModuleEx(
			hProcess,//_In_  HANDLE hProcess,
			de.u.LoadDll.hFile,//_In_  HANDLE hFile,
			NULL,//_In_  PCTSTR ImageName,
			NULL,//_In_  PCTSTR ModuleName,
			0, //(DWORD64)de.u.LoadDll.lpBaseOfDll,//_In_  DWORD64 BaseOfDll,
			0,//_In_  DWORD DllSize,
			NULL,//_In_  PMODLOAD_DATA Data,
			0);//_In_  DWORD Flags

	Write(WriteLevel::Info, L"Loaded %s at %x, symbols %s loaded",
			pszFilename,
			de.u.LoadDll.lpBaseOfDll,
			 L" NOT ");

//	if (0 == dwBase)
//	{
//		Write(WriteLevel::Error, L"SymLoadModuleEx failed with 0x%x", GetLastError());
//		goto Exit;
//	}
//
//	module_info.SizeOfStruct = sizeof(module_info);
//	bSuccess = SymGetModuleInfo64(
//			hProcess,
//			dwBase,
//			&module_info);
//
//
//	if (!bSuccess)
//	{
//		Write(WriteLevel::Error, L"SymGetModuleInfo64 failed with %x", GetLastError());
//		goto Exit;
//	}

	EXIT_FN
}

HRESULT CreateProcessDebugEvent(const DEBUG_EVENT& de)
{
	ENTER_FN

	LPCREATE_PROCESS_DEBUG_INFO pCreateProcessDebugInfo = (LPCREATE_PROCESS_DEBUG_INFO)&de.u.CreateProcessInfo;

	BYTE cInstruction;
	HANDLE hProcess = de.u.CreateProcessInfo.hProcess;
	IMAGEHLP_MODULE64 module_info;
	SIZE_T lpNumberOfBytesRead;
	LPWSTR processName = new WCHAR[MAX_PATH];

	DWORD64 dw64StartAddress = 0;
	DWORD dwStartAddress = 0;

	Write(WriteLevel::Debug, L"CREATE_PROCESS_DEBUG_INFO = {"
			L"hFile= 0x%08LX"
			L" hProcess= 0x%08LX"
			L" hThread= 0x%08LX"
			L" lpBaseOfImage= 0x%08LX }",
			pCreateProcessDebugInfo->hFile,
			pCreateProcessDebugInfo->hProcess,
			pCreateProcessDebugInfo->hThread,
			pCreateProcessDebugInfo->lpBaseOfImage);

#ifdef _X86_
	Write(WriteLevel::Debug, L"lpStartAddress=0x%08x", (DWORD)de.u.CreateProcessInfo.lpStartAddress);
#else
	Write(WriteLevel::Debug, L"lpStartAddress=0x%016x", (DWORD64)de.u.CreateProcessInfo.lpStartAddress);
#endif

	dw64StartAddress = (DWORD64)de.u.CreateProcessInfo.lpStartAddress;
	dwStartAddress = (DWORD)de.u.CreateProcessInfo.lpStartAddress;

	nSpawnedProcess++;

	processNameLen = GetFinalPathNameByHandleW(
						de.u.CreateProcessInfo.hFile,
						processName,
						MAX_PATH,
						0);
	if (processNameLen == 0)
	{
		Write(WriteLevel::Error, L"GetFinalPathNameByHandleW failed: %x", GetLastError());
		goto Exit;
	}

	//
	// Initializes the symbol handler for a process.
	//
	Write(WriteLevel::Debug, L"SymInitialize on hProcess=0x%x ...", hProcess);
	BOOL bRes = SymInitialize(hProcess, NULL, FALSE);
	if (FALSE == bRes)
	{
		DWORD error = GetLastError();
		if (error != ERROR_SUCCESS)
		{
			Write(WriteLevel::Error, L"SymInitialize failed 0x%x", error);
			goto Exit;
		}
	}

	//
	// Loads the symbol table for the specified module.
	//
	Write(WriteLevel::Debug , L"SymLoadModuleEx on hProcess=0x%x", hProcess);
	DWORD64 dwBase = SymLoadModuleEx(
						hProcess,
						de.u.CreateProcessInfo.hFile,
						NULL, //"wtrace.exe",
						NULL,
						0, //dw64StartAddress /*BaseOfDll*/,
						0,//_In_  DWORD DllSize,
						NULL,//_In_  PMODLOAD_DATA Data,
						0);//_In_  DWORD Flags

	if (dwBase == 0)
	{
		DWORD error = GetLastError();
		if (error != ERROR_SUCCESS)
		{
			Write(WriteLevel::Error, L"SymLoadModuleEx failed 0x%x", error);
			goto Exit;
		}

		Write(WriteLevel::Debug, L"SymLoadModuleEx: Module already loaded.");
	}
	else
	{
		Write(WriteLevel::Debug , L"SymLoadModuleEx OK returned dwBase=0x%x", dwBase);
		// why are we doing this ?
		//dw64StartAddress = dwBase;
	}

	module_info.SizeOfStruct = sizeof(module_info);

	//
	// Retrieves the module information of the specified module.
	//
	Write(WriteLevel::Debug , L"SymGetModuleInfo64 on hProcess=0x%x, dwStartAddress=0x%x", hProcess, dwBase);
	BOOL bSuccess = SymGetModuleInfo64(
			hProcess,
			dwBase,
			&module_info);

	if (!bSuccess)
	{
		Write(WriteLevel::Error, L"SymGetModuleInfo64 failed with 0x%x", GetLastError());
		goto Exit;
	}


	if (de.u.CreateProcessInfo.lpImageName)
	{
		if (de.u.CreateProcessInfo.fUnicode)
		{
			Write(WriteLevel::Debug, L"Image name is %s ", (de.u.CreateProcessInfo.lpImageName));
		}
		else
		{
			Write(WriteLevel::Debug, L"Image name is present but not in unicode.");
		}
	}

	Write(WriteLevel::Info, L"CreateProcessDebugEvent process %s at 0x%x, symbols %sloaded",
			processName,
			de.u.CreateProcessInfo.lpStartAddress,
			(bSuccess && module_info.SymType == SymPdb) ? L"" : L"NOT ");

	//
	// Insert a break point by replacing the first instruction
	//
	BOOL bInsertBreakPoint = TRUE;
	if (bInsertBreakPoint)
	{
		// Read the first instruction and save it
		int result = ReadProcessMemory(
						hProcess,
#ifdef _X86_
						(void*)dwStartAddress,
#else
						(void*)dw64StartAddress,
#endif
						&cInstruction,
						1,
						&lpNumberOfBytesRead);

		if (result == 0)
		{
			hr = GetLastError();
			Write(WriteLevel::Error, L"ReadProcessMemory failed 0x%x", hr);
			goto Exit;
		}

		if (cInstruction != 0xCC)
		{
			Write(WriteLevel::Debug, L"Replacing first instruction '%x' at 0x%08x with 0xCC", cInstruction, dwStartAddress);

			m_OriginalInstruction = cInstruction;

			// Replace it with Breakpoint
			cInstruction = 0xCC;

			WriteProcessMemory(hProcess, (void*)dwStartAddress, &cInstruction, 1, &lpNumberOfBytesRead);

			FlushInstructionCache(hProcess, (void*)dwStartAddress, 1);
		}
	}

	EXIT_FN
}

HRESULT ExceptionBreakpoint(HANDLE hThread, HANDLE hProcess)
{
	ENTER_FN

	CONTEXT lcContext;
	DWORD dwStartAddress;
	DWORD64 dw64StartAddress;
	lcContext.ContextFlags = CONTEXT_ALL;

	Write(WriteLevel::Info, L"EXCEPTION_BREAKPOINT");

	BOOL bResult = GetThreadContext(hThread, &lcContext);
	if (!bResult)
	{
		Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", GetLastError());
		goto Exit;
	}

	DumpContext(lcContext);

#ifdef _X86_
	if (firstDebugEvent)
	{
		// First chance: Display the current instruction and register values.
		Write(WriteLevel::Info, L"EXCEPTION_BREAKPOINT (first) ignoring...");
		firstDebugEvent = 0;
	}
	else
#endif
	{
		GetCurrentFunctionName(hThread, hProcess, lcContext);

		// This does not work when you have a physical DebugBreak() in the code
		//Write(WriteLevel::Debug, L"Instruction pointer minus 1");

		Interactive();

		if (m_OriginalInstruction != 0)
		{
			Write(WriteLevel::Debug, L"Writing back original instruction ");

			SIZE_T lNumberOfBytesRead;

#ifdef _X86_
			lcContext.Eip--;
			dwStartAddress = lcContext.Eip;
			WriteProcessMemory(hProcess, (LPVOID)dwStartAddress, &m_OriginalInstruction, 1, &lNumberOfBytesRead);
			FlushInstructionCache(hProcess, (LPVOID)dwStartAddress, 1);
#else
			lcContext.Rip--;
			dw64StartAddress = lcContext.Rip;
			WriteProcessMemory(hProcess, (LPVOID)dw64StartAddress, &m_OriginalInstruction, 1, &lNumberOfBytesRead);
			FlushInstructionCache(hProcess, (LPVOID)dw64StartAddress, 1);
#endif

			m_OriginalInstruction = 0;
		}

		Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");
		lcContext.EFlags |= 0x100;

		//A 64-bit application can set the context of a WOW64 thread using the Wow64SetThreadContext function.
		if (0 == SetThreadContext(hThread, &lcContext))
		{
			hr = GetLastError();
			Write(WriteLevel::Error, L"SetThreadContext failed with 0x%x.", hr);
			goto Exit;
		}
	}

	EXIT_FN
}

HRESULT GetCurrentFunctionName(HANDLE hThread, HANDLE hProcess, const CONTEXT& context)
{
	ENTER_FN

	std::string sFuntionName;
	std::wstring wsFuctionName;
	DWORD64 instructionPointer;

	hr = RetrieveCallstack(hThread, hProcess, context, 1 /* 1 frame */, &sFuntionName, &instructionPointer);
	if (FAILED(hr))
	{
		goto Exit;
	}

	if (gAnalysisLevel >= 4)
	{
		lastFunctionName = sFuntionName;
	}
	else // gAnalysisLevel == 3
	{
		if (sFuntionName.compare(lastFunctionName) == 0)
		{
			goto Exit;
		}
		else
		{
			lastFunctionName = sFuntionName;
		}
	}

	lnFunctionCalls++;

#if 0
#ifdef _X86_
	//instructionPointer -= 1; //instruction pointer minus 1 is the reaal deal; but why ?
	printf("%p ", (DWORD)instructionPointer);

	if ((DWORD)instructionPointer != 0xFFFFFFFF)
	{
		int* pcontent = (int*)instructionPointer;
		int content = *pcontent;

		printf(" %2x ", content);
	}

#else
	printf("0x%016x ", instructionPointer);
	//printf("%5x ", *instructionPointer);
#endif
#endif


	wsFuctionName.assign(sFuntionName.begin(), sFuntionName.end());

	//Write(WriteLevel::Info, L"0x%x 0x%03x %4d %s", instructionPointer, hThread, lnFunctionCalls, wsFuctionName.c_str());
	Write(WriteLevel::Info, L"0x%03x %4d %s", hThread, lnFunctionCalls, wsFuctionName.c_str());

	EXIT_FN
}

HRESULT RetrieveCallstack(HANDLE hThread, HANDLE hProcess, const CONTEXT& context, int nFramesToRead, std::string* sFuntionName, DWORD64 * ip)
{
	ENTER_FN

	STACKFRAME64 stack = {0};
	IMAGEHLP_SYMBOL64 *pSym = NULL;
	CallstackEntry csEntry;

	if (hThread == INVALID_HANDLE_VALUE
			|| hProcess == INVALID_HANDLE_VALUE)
	{
		Write(WriteLevel::Error, L"Handles are invalid");
		goto Exit;
	}

#ifdef _X86_
	stack.AddrPC.Offset = context.Eip;    // EIP - Instruction Pointer
	stack.AddrFrame.Offset = context.Ebp; // EBP
	stack.AddrStack.Offset = context.Esp; // ESP - Stack Pointer
#else
	stack.AddrPC.Offset = context.Rip;    // EIP - Instruction Pointer
	stack.AddrFrame.Offset = context.Rbp; // EBP
	stack.AddrStack.Offset = context.Rsp; // ESP - Stack Pointer
#endif

	*ip = stack.AddrPC.Offset;

	// Must be like this
	stack.AddrPC.Mode = AddrModeFlat;
	stack.AddrFrame.Mode = AddrModeFlat;
	stack.AddrStack.Mode = AddrModeFlat;

	pSym = (IMAGEHLP_SYMBOL64*) malloc(sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
	pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
	pSym->MaxNameLength = STACKWALK_MAX_NAMELEN;

	Write(WriteLevel::Debug, L"SymInitialize on hProcess=0x%x ...", hProcess);

	if (FALSE == bSyminitialized)
	{
		bSyminitialized = TRUE;
		BOOL bRes = SymInitialize(hProcess, NULL, TRUE);
		if (FALSE == bRes)
		{
			DWORD error = GetLastError();
			if (error != ERROR_SUCCESS)
			{
				Write(WriteLevel::Error, L"SymInitialize failed 0x%x", error);
				goto Exit;
			}
		}
	}

	for (int frameNum = 0; (nFramesToRead ==0) || (frameNum < nFramesToRead); ++frameNum)
	{
		Write(WriteLevel::Debug, L"About to walk the stack hProcess=0x%x hThread=0x%x", hProcess, hThread);

		//
		// StackWalk64 only needs context when image is IMAGE_FILE_MACHINE_I386, the 
		// context might be modified.
		//
		BOOL bResult = StackWalk64(
#ifdef _X86_
				IMAGE_FILE_MACHINE_I386,
#else
				IMAGE_FILE_MACHINE_AMD64,
#endif
				hProcess,
				hThread,
				&stack,
				(PVOID)(&context), // only pass for x86
				NULL,
				SymFunctionTableAccess64,
				SymGetModuleBase64,
				NULL);

		if (FALSE == bResult)
		{
			// INFO: "StackWalk64" does not set "GetLastError"...
			Write(WriteLevel::Error, L"StackWalk64 failed, the following hr must not be trusted: hr=%x", GetLastError());
			goto Exit;
		}

		csEntry.offset = stack.AddrPC.Offset;
		csEntry.name[0] = 0;
		csEntry.undName[0] = 0;
		csEntry.undFullName[0] = 0;
		csEntry.offsetFromSmybol = 0;
		csEntry.offsetFromLine = 0;
		csEntry.lineFileName[0] = 0;
		csEntry.lineNumber = 0;
		csEntry.loadedImageName[0] = 0;
		csEntry.moduleName[0] = 0;

		if (stack.AddrPC.Offset != 0)
		{
			// we seem to have a valid PC
			if (SymGetSymFromAddr64(hProcess,
										stack.AddrPC.Offset,
										&(csEntry.offsetFromSmybol),
										pSym) != FALSE)
			{
				// Undecorate names:
				//UnDecorateSymbolName(pSym->Name, csEntry.undName, STACKWALK_MAX_NAMELEN, UNDNAME_NAME_ONLY );
				//UnDecorateSymbolName(pSym->Name, csEntry.undFullName, STACKWALK_MAX_NAMELEN, UNDNAME_COMPLETE );

				if (sFuntionName != NULL)
				{
					// Copy into caller
					*sFuntionName = pSym->Name;
				}
				else
				{
					Write(WriteLevel::Error, L"SymGetSymFromAddr64 returned null function name ");
				}
			}
			else
			{
				hr = GetLastError();
				Write(WriteLevel::Error,
							L"SymGetSymFromAddr64 failed 0x%x, s.AddrPC.Offset=0x%x",
							hr,
							stack.AddrPC.Offset);
				goto Exit;
			}
		}
	}

	// leaking on failure
	delete pSym;

	EXIT_FN
}

