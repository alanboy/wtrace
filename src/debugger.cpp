
/* ********************************************************** 
 *
 * wtrace
 * 2014 - Alan Gonzalez
 *
 * ********************************************************** */
#define UNICODE
#define _UNICODE

//#undef WIN32_NO_STATUS
#include <windows.h>

//#define WIN32_NO_STATUS
//#define _AMD64_
//#include <ntstatus.h>
//#include <winnt.h>

#include <stdio.h>
#include <string>
#include <Dbghelp.h>

#include <iostream>

#include "output.h"
#include "Utils.h"
#include "Main.h"
#include "Debugger.h"
#include "wow64.h"

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

#define BREAK_IF_DEBUGGER_PRESENT() if (IsDebuggerPresent()) DebugBreak();

int gAnalysisLevel;
BYTE m_OriginalInstruction;
DWORD processNameLen;
int nSpawnedProcess;
bool bSyminitialized;
bool firstDebugEvent = 1;
std::string lastFunctionName;
long lnFunctionCalls = 0;



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
		hr =  HRESULT_FROM_WIN32(GetLastError());
		Write(WriteLevel::Error, L"Unable to create process. hr=0x%x", hr);
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
					//////////////////////////////////////////////
					//			NATIVE EXCEPTIONS
					//////////////////////////////////////////////
					case EXCEPTION_ACCESS_VIOLATION:
						// First chance: Pass this on to the system. 
						// Last chance: Display an appropriate error. 
						ExceptionAccessViolation(pi.hProcess, pi.hThread, de.u.Exception.ExceptionRecord);
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


					//////////////////////////////////////////////
					//				WOW Exceptions
					//////////////////////////////////////////////
					case STATUS_WX86_BREAKPOINT:
						Wow64Breakpoint(pi.hProcess, pi.hThread);
					break;

					case STATUS_WX86_SINGLE_STEP:
						//0x4000001EL
						// http://reverseengineering.stackexchange.com/questions/9313/opening-program-via-ollydbg-immunity-in-win7-causes-exception-unless-in-xp-compa
						Wow64SingleStep(pi.hProcess, pi.hThread);
					break;

					case STATUS_WX86_UNSIMULATE:
						Write(WriteLevel::Info, L"STATUS_WX86_UNSIMULATE");
					break;

					case STATUS_WX86_CONTINUE:
						Write(WriteLevel::Info, L"STATUS_WX86_CONTINUE");
					break;

					case STATUS_WX86_EXCEPTION_CONTINUE:
						Write(WriteLevel::Info, L"STATUS_WX86_EXCEPTION_CONTINUE");
					break;

					case STATUS_WX86_EXCEPTION_LASTCHANCE:
						Write(WriteLevel::Info, L"STATUS_WX86_EXCEPTION_LASTCHANCE");
					break;

					case STATUS_WX86_EXCEPTION_CHAIN:
					break;

					//
					// Missing/Unknown values
					//
					//#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     STATUS_ARRAY_BOUNDS_EXCEEDED
					//#define EXCEPTION_FLT_DENORMAL_OPERAND      STATUS_FLOAT_DENORMAL_OPERAND
					//#define EXCEPTION_FLT_DIVIDE_BY_ZERO        STATUS_FLOAT_DIVIDE_BY_ZERO
					//#define EXCEPTION_FLT_INEXACT_RESULT        STATUS_FLOAT_INEXACT_RESULT
					//#define EXCEPTION_FLT_INVALID_OPERATION     STATUS_FLOAT_INVALID_OPERATION
					//#define EXCEPTION_FLT_OVERFLOW              STATUS_FLOAT_OVERFLOW
					//#define EXCEPTION_FLT_STACK_CHECK           STATUS_FLOAT_STACK_CHECK
					//#define EXCEPTION_FLT_UNDERFLOW             STATUS_FLOAT_UNDERFLOW
					//#define EXCEPTION_INT_DIVIDE_BY_ZERO        STATUS_INTEGER_DIVIDE_BY_ZERO
					//#define EXCEPTION_INT_OVERFLOW              STATUS_INTEGER_OVERFLOW
					//#define EXCEPTION_PRIV_INSTRUCTION          STATUS_PRIVILEGED_INSTRUCTION
					//#define EXCEPTION_IN_PAGE_ERROR             STATUS_IN_PAGE_ERROR
					//#define EXCEPTION_ILLEGAL_INSTRUCTION       STATUS_ILLEGAL_INSTRUCTION
					//#define EXCEPTION_NONCONTINUABLE_EXCEPTION  STATUS_NONCONTINUABLE_EXCEPTION
					//#define EXCEPTION_STACK_OVERFLOW            STATUS_STACK_OVERFLOW
					//#define EXCEPTION_INVALID_DISPOSITION       STATUS_INVALID_DISPOSITION
					//#define EXCEPTION_GUARD_PAGE                STATUS_GUARD_PAGE_VIOLATION
					//#define EXCEPTION_INVALID_HANDLE            STATUS_INVALID_HANDLE
					//#define EXCEPTION_POSSIBLE_DEADLOCK         STATUS_POSSIBLE_DEADLOCK
					//#define CONTROL_C_EXIT                      STATUS_CONTROL_C_EXIT

					default:
						// Handle other exceptions.
						Write(WriteLevel::Info, L"Unknown debug event : %x ", de.u.Exception.ExceptionRecord.ExceptionCode);
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
				Write(WriteLevel::Info, L"CREATE_THREAD_DEBUG_EVENT");
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

HRESULT ExceptionAccessViolation(HANDLE hProcess, HANDLE hThread, const EXCEPTION_RECORD& exception)
{
	ENTER_FN

	Write(WriteLevel::Info, L"EXCEPTION_ACCESS_VIOLATION at 0x%x while %s 0x%x",
			exception.ExceptionAddress,
			exception.ExceptionInformation[0] ? L"writing to " : L"reading from ",
			(PVOID)exception.ExceptionInformation[1]);

	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	BOOL bIsWow64 = FALSE;
	BOOL bResult = FALSE;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
			GetModuleHandle(TEXT("kernel32")),"IsWow64Process");


	if(NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(hProcess, &bIsWow64))
		{
			hr =  HRESULT_FROM_WIN32(GetLastError());
			goto Exit;
		}
	}

	Write(WriteLevel::Debug, L"Process is wow64: %d", bIsWow64);

	if (bIsWow64)
	{
//		WOW64_CONTEXT lcWowContext = {0};
//		lcWowContext.ContextFlags = CONTEXT_ALL;
//
//		bResult = Wow64GetThreadContext(hThread, &lcWowContext);
//		if (!bResult)
//		{
//			Write(WriteLevel::Error, L"Wow64GetThreadContext failed 0x%x", GetLastError());
//			goto Exit;
//		}
//
//		DumpWowContext(lcWowContext);
//
//		std::string sFuntionName;
//		std::wstring wsFuctionName;
//		DWORD64 instructionPointer;
//		hr = RetrieveWoWCallstack(hThread, hProcess, lcWowContext, 1 /* 1 frame */, &sFuntionName, &instructionPointer);
//
//		Write(WriteLevel::Debug, L"GetCurrentFunctionName result 0x%x", hr);
//		if (FAILED(hr))
//		{
//			Write(WriteLevel::Error, L"GetCurrentFunctionName failed 0x%x", hr);
//			goto Exit;
//		}
//
//		wsFuctionName.assign(sFuntionName.begin(), sFuntionName.end());
//		Write(WriteLevel::Info, L"0x%08x %s", (DWORD)instructionPointer, wsFuctionName.c_str());
	}
	else
	{
		CONTEXT lcContext = {0};
		lcContext.ContextFlags = CONTEXT_ALL;

		bResult = GetThreadContext(hThread, &lcContext);
		if (!bResult)
		{
			hr =  HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", hr);
			goto Exit;
		}

		DumpContext(lcContext);

		hr = GetCurrentFunctionName(hThread, hProcess, lcContext);
		if (FAILED(hr))
		{
			Write(WriteLevel::Error, L"GetCurrentFunctionName failed 0x%x", hr);
			goto Exit;
		}
	}

	Interactive();

	EXIT_FN
}

HRESULT DebugStringEvent(const DEBUG_EVENT& de)
{
	ENTER_FN

	OUTPUT_DEBUG_STRING_INFO DebugString = de.u.DebugString;


	// @TODO Allocat based on unicode 
	CHAR *msg = new CHAR[DebugString.nDebugStringLength];

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, de.dwProcessId);
	if (hProcess == NULL)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		Write(WriteLevel::Error, L"OpenProcess failed 0x%x", hr);
		goto Exit;
	}

	int result = ReadProcessMemory(
			hProcess,
			DebugString.lpDebugStringData,	// Target process' valid pointer
			msg,							// Copy to this address space
			DebugString.nDebugStringLength,
			NULL);

	if (result == 0)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());

		Write(WriteLevel::Error, L"ReadProcessMemory failed 0x%x", hr);

		hr = S_OK;
		goto Release;
	}

	if (msg)
	{
		if (msg[0] == 0xd && msg[1] == 0xa)
		{
			// <CR><LF> - Carriage regurn & New line, if we dont do this, Acces Violation when trying to print this 
			goto Release;
		}
	}

	if (DebugString.fUnicode)
	{
		Write(WriteLevel::Info, L"OUTPUT_DEBUG_STRING_EVENT: %s", msg);
	}
	else
	{
		std::string sOutput(msg);
		std::wstring wsOuput;
		wsOuput.assign(sOutput.begin(), sOutput.end());
		Write(WriteLevel::Info, L"OUTPUT_DEBUG_STRING_EVENT: %s ", wsOuput);
	}

Release:
	// Leaked on exit
	delete [] msg;

	if (hProcess)
	{
		CloseHandle(hProcess);
		hProcess = NULL;
	}

	EXIT_FN
}
#if 0
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
			hr =  HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"Wow64GetThreadContext failed 0x%x", hr);
			goto Exit;
		}

		hr = DumpContext(*((CONTEXT*)&lcWowContext));

		hr = GetCurrentFunctionName(hThread, hProcess, *((CONTEXT*)&lcWowContext));
		Write(WriteLevel::Debug, L"GetCurrentFunctionName result 0x%x", hr);
		if (FAILED(hr))
		{
			Write(WriteLevel::Error, L"GetCurrentFunctionName failed 0x%x", hr);
			goto Exit;
		}

		Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");

		lcWowContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
		if (0 == Wow64SetThreadContext(hThread, &lcWowContext))
		{
			hr =  HRESULT_FROM_WIN32(GetLastError());
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
#endif

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
			hr = HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", hr);
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
			hr =  HRESULT_FROM_WIN32(GetLastError());
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
			hr =  HRESULT_FROM_WIN32(GetLastError());
			goto Exit;
		}
	}

	Write(WriteLevel::Debug, L"hProcess=0x%d is %s wow64 process",
			hProcess,
			bIsWow64 ? L"" : L"NOT");

	if (bIsWow64)
	{
		//hr = ExceptionSingleStepWow64(hProcess, hThread);
		hr= ExceptionSingleStepX64(hProcess, hThread);
	}
	else
	{
		hr= ExceptionSingleStepX64(hProcess, hThread);
	}

	EXIT_FN
}

HRESULT LoadDllDebugEvent(const DEBUG_EVENT& de, HANDLE hProcess)
{
	ENTER_FN

	// LOAD_DLL_DEBUG_INFO structure
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680351(v=vs.85).aspx

	// Read the debugging information included in the newly loaded DLL.
	WCHAR pszFilename[MAX_PATH+1];
	DWORD64 dwBase;

	BOOL bSuccess = GetFileNameFromHandle(de.u.LoadDll.hFile, (WCHAR *)&pszFilename);
	if (!bSuccess)
	{
		Write(WriteLevel::Error, L"GetFileNameFromHandle failed ");
		goto Exit;
	}

	Write(WriteLevel::Debug, L"SymLoadModuleEx on hProcess0x%x", hProcess);
// For upcoming LOAD_DLL_DEBUG_EVENTs, we also need to call this function for the respective DLL being loaded.
	dwBase = SymLoadModuleEx(
			hProcess,
			de.u.LoadDll.hFile,
			NULL,//_In_  PCTSTR ImageName,
			NULL,//_In_  PCTSTR ModuleName,
			(DWORD64)de.u.LoadDll.lpBaseOfDll,//_In_  DWORD64 BaseOfDll,
			0,//_In_  DWORD DllSize,
			NULL,//_In_  PMODLOAD_DATA Data,
			0);//_In_  DWORD Flags

	if (dwBase == 0)
	{
//If the function succeeds, the return value is the base address of the loaded module.
//If the function fails, the return value is zero. To retrieve extended error information, call GetLastError.
//If the module is already loaded, the return value is zero and GetLastError returns ERROR_SUCCESS.
		Write(WriteLevel::Debug, L"SymLoadModuleEx returnd 0x%x", dwBase);
	}

	// lpImageName -A pointer to the file name associated with hFile. This member may 
	// be NULL, or it may contain the address of a string pointer in the address space
	// of the process being debugged. That address may, in turn, either be NULL or point
	// to the actual filename. If fUnicode is a nonzero value, the name string is
	// Unicode; otherwise, it is ANSI.
	if (de.u.LoadDll.lpImageName)
	{
		BYTE cInstruction[100];
		SIZE_T lpNumberOfBytesRead;

		int result = ReadProcessMemory(
				hProcess,
#ifdef _X86_
				(void*)de.u.LoadDll.lpImageName,
#else
				(void*)de.u.LoadDll.lpImageName,
#endif
				&cInstruction,
				100,
				&lpNumberOfBytesRead);

		if (result == 0)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());

			if (hr != HRESULT_FROM_WIN32(ERROR_PARTIAL_COPY))
			{
				Write(WriteLevel::Error, L"ReadProcessMemory failed 0x%x", hr);
				goto Exit;
			}

			hr = S_OK;
		}

		//Write(WriteLevel::Info, L"ReadProcessMemory read 0x%x bytes %s ", lpNumberOfBytesRead, cInstruction);
	}

	Write(WriteLevel::Info, L" %p - %p \t (%sdebug info) \t %s",
			de.u.LoadDll.lpBaseOfDll,
			de.u.LoadDll.lpBaseOfDll,
			//imageName,
			de.u.LoadDll.nDebugInfoSize == 0 ? L"no " : L"",
			pszFilename);



	CloseHandle(de.u.LoadDll.hFile);

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

	nSpawnedProcess++;

	processNameLen = GetFinalPathNameByHandleW(
						de.u.CreateProcessInfo.hFile,
						processName,
						MAX_PATH,
						0);
	if (processNameLen == 0)
	{
			hr =  HRESULT_FROM_WIN32(GetLastError());
		Write(WriteLevel::Error, L"GetFinalPathNameByHandleW failed: %x", hr);
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
			hr = HRESULT_FROM_WIN32(error);
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
			hr = HRESULT_FROM_WIN32(error);
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
		hr = HRESULT_FROM_WIN32(GetLastError());
		Write(WriteLevel::Error, L"SymGetModuleInfo64 failed with 0x%x", hr);
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

#ifdef _AMD64_
	Write(WriteLevel::Info, L" %p - %p \t (%sdebug info) \t %s",
			de.u.CreateProcessInfo.lpBaseOfImage,
			de.u.CreateProcessInfo.lpStartAddress,
			(bSuccess && module_info.SymType == SymPdb) ? L"" : L"no ",
			processName);
#else
	Write(WriteLevel::Info, L" %p - %p \t (%sdebug info) \t %s",
			de.u.CreateProcessInfo.lpStartAddress,
			de.u.CreateProcessInfo.lpStartAddress,
			(bSuccess && module_info.SymType == SymPdb) ? L"" : L"no ",
			processName);
#endif


	//
	// Insert a break point by replacing the first instruction
	//
	//DWORD64 dw64StartAddress = (DWORD64)de.u.CreateProcessInfo.lpStartAddress;
	DWORD64 dwStartAddress = 0;
	dwStartAddress = (DWORD64)de.u.CreateProcessInfo.lpStartAddress;

	// Insert breakpoint for native
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	BOOL bIsWow64 = FALSE;
	BOOL bResult = FALSE;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
			GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(hProcess, &bIsWow64))
		{
			hr =  HRESULT_FROM_WIN32(GetLastError());
			goto Exit;
		}
	}

	Write(WriteLevel::Debug, L"Process is wow64: %d", bIsWow64);

	BOOL bInsertBreakPoint = !bIsWow64; 

#ifdef _X86_
	bInsertBreakPoint = TRUE;
#endif

	if (bInsertBreakPoint)
	{
		// Read the first instruction and save it
		int result = ReadProcessMemory(
						hProcess,
						(void*)dwStartAddress,
						&cInstruction,
						1,
						&lpNumberOfBytesRead);

		if (result == 0)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
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
	DWORD64 dw64StartAddress;
	lcContext.ContextFlags = CONTEXT_ALL;

	BOOL bResult = GetThreadContext(hThread, &lcContext);
	if (!bResult)
	{
		hr =  HRESULT_FROM_WIN32(GetLastError());
		Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", hr);
		goto Exit;
	}

	DumpContext(lcContext);

//#ifdef _X86_
	if (firstDebugEvent)
	{
		// First chance: Display the current instruction and register values.
		Write(WriteLevel::Info, L"EXCEPTION_BREAKPOINT (first) ignoring...");
		firstDebugEvent = 0;
	}
	else
//#endif
	{
		Write(WriteLevel::Info, L"EXCEPTION_BREAKPOINT");

		GetCurrentFunctionName(hThread, hProcess, lcContext);

		// This does not work when you have a physical DebugBreak() in the code
		//Write(WriteLevel::Debug, L"Instruction pointer minus 1");


		if (m_OriginalInstruction != 0)
		{
			Write(WriteLevel::Debug, L"Writing back original instruction ");

			SIZE_T lNumberOfBytesRead;

#ifdef _X86_
			lcContext.Eip--;
			DWORD dwStartAddress;
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
			hr = HRESULT_FROM_WIN32(GetLastError());
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

	if (hr == HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND))
	{
		sFuntionName = "<unknown>";
		hr = S_OK;
	}
	else if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_ADDRESS))
	{
		sFuntionName = "<unknown>";
		hr = S_OK;
	}
	else if (FAILED(hr))
	{
		Write(WriteLevel::Error, L"RetrieveCallstack failed with 0x%x.", hr);
		goto Exit;
	}

	if (gAnalysisLevel >= 4) // 4 means all code
	{

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

#ifdef _X86_
	Write(WriteLevel::Info, L"0x%p %4d %s", (DWORD)instructionPointer, lnFunctionCalls, wsFuctionName.c_str());
#else
	Write(WriteLevel::Info, L"0x%p %4d %s", instructionPointer, lnFunctionCalls, wsFuctionName.c_str());
#endif

	EXIT_FN
}

DWORD GetStartAddress(HANDLE hProcess, HANDLE hThread)
{
	SYMBOL_INFO *pSymbol;
	pSymbol = (SYMBOL_INFO *)new BYTE[sizeof(SYMBOL_INFO )+MAX_SYM_NAME];
	pSymbol->SizeOfStruct= sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	SymFromName(hProcess,"wWinMainCRTStartup",pSymbol);

	// Store address, before deleting pointer  
	DWORD dwAddress = pSymbol->Address;

	delete [](BYTE*)pSymbol; // Valid syntax!

	return dwAddress;
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

	// @TODO make this work with wow
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
				hr = HRESULT_FROM_WIN32(error);
				Write(WriteLevel::Error, L"SymInitialize failed 0x%x", error);
				goto Exit;
			}
		}
	}

//IMAGEHLP_MODULE64 module={0};
//module.SizeOfStruct = sizeof(module);
//SymGetModuleInfo64(hProcess, (DWORD64)stack.AddrPC.Offset, &module);
//DebugBreak();

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
				//IMAGE_FILE_MACHINE_I386,
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
			hr = HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"StackWalk64 failed, the following hr must not be trusted: hr=%x", hr);
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
#if 0
			if (FALSE == SymRefreshModuleList(hProcess))
			{
					Write(WriteLevel::Error, L"SymRefreshModuleList failed :(");
			}
#endif

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
				hr = HRESULT_FROM_WIN32(GetLastError());
				Write(WriteLevel::Error,
							L"SymGetSymFromAddr64 failed 0x%x, address=0x%p",
							hr,
							stack.AddrPC.Offset);

				BREAK_IF_DEBUGGER_PRESENT();

				goto Exit;
			}
		}
	}

	// leaking on failure
	delete pSym;

	EXIT_FN
}

