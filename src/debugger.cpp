/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>
#include <string>
#include <Dbghelp.h>

#include <iostream>
#include <map>

#include "output.h"
#include "Utils.h"
#include "Main.h"
#include "Debugger.h"
#include "wow64.h"
#include "html.h"


DWORD gStartTicks = 0;
int gAnalysisLevel = 0;
#define STACKWALK_MAX_NAMELEN 1024

#define WIDE2(x) L##x
#define WIDE1(x) WIDE2(x)
#define ENTER_FN \
			dFunctionDepth++; \
			Write(WriteLevel::Debug, L"ENTERING FUNCTION " WIDE1(__FUNCTION__) L" at %d",  GetTickCount() - gStartTicks); \
			dFunctionDepth++; \
			HRESULT hr = S_OK;


#define EXIT_FN \
			if (0,0) goto Exit; \
			Exit: \
			dFunctionDepth--; \
			Write(WriteLevel::Debug, L"EXITING  FUNCTION " WIDE1(__FUNCTION__) L" at %d",  GetTickCount() - gStartTicks); \
			dFunctionDepth--; \
			return hr;

#define BREAK_IF_DEBUGGER_PRESENT() if (IsDebuggerPresent()) DebugBreak();

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

HRESULT DebugEngine::GetRegisters(
		std::map<std::string, DWORD> *mapRegisters
		)
{
	ENTER_FN;

	CONTEXT lcContext;
	DWORD64 dw64StartAddress;
	lcContext.ContextFlags = CONTEXT_ALL;

	BOOL bResult = GetThreadContext(m_hCurrentThread, &lcContext);
	if (!bResult)
	{
		hr =  HRESULT_FROM_WIN32(GetLastError());
		Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", hr);
		goto Exit;
	}

#define make_pair(X,Y) std::pair<std::string, DWORD>(X, (DWORD)Y) 

#ifdef _X86_
	mapRegisters->insert(make_pair("eax", lcContext.Eax));
	mapRegisters->insert(make_pair("ebp", lcContext.Ebp));
	mapRegisters->insert(make_pair("ebx", lcContext.Ebx));
	mapRegisters->insert(make_pair("ecx", lcContext.Ecx));
	mapRegisters->insert(make_pair("edi", lcContext.Edi));
	mapRegisters->insert(make_pair("edx", lcContext.Edx));
	mapRegisters->insert(make_pair("eflags" , lcContext.EFlags));
	mapRegisters->insert(make_pair("eip", lcContext.Eip));
	mapRegisters->insert(make_pair("esi", lcContext.Esi));
	mapRegisters->insert(make_pair("esp", lcContext.Esp));
#else
	mapRegisters->insert(make_pair("eax" , lcContext.Rax));
	mapRegisters->insert(make_pair("ebx" , lcContext.Rbx));
	mapRegisters->insert(make_pair("ecx" , lcContext.Rcx));
	mapRegisters->insert(make_pair("eflags" , lcContext.EFlags));
	mapRegisters->insert(make_pair("rbp" , lcContext.Rbp));
	mapRegisters->insert(make_pair("rdi" , lcContext.Rdi));
	mapRegisters->insert(make_pair("rdx" , lcContext.Rdx));
	mapRegisters->insert(make_pair("rip" , lcContext.Rip));
	mapRegisters->insert(make_pair("rsi" , lcContext.Rsi));
	mapRegisters->insert(make_pair("rsp" , lcContext.Rsp));
#endif

	EXIT_FN;
}

HRESULT DebugEngine::Run()
{
	ENTER_FN

	DEBUG_EVENT de = {0};
	int bCreateProcRes;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	WowDebugEngine wow64engine;

	m_bSymInitialized = FALSE;
	m_iSpawnedProcess = 0;

	HtmlOutput html;

	// Ref count of processes created

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	Write(WriteLevel::Debug, L"Creating process %s", gpCommandLine);

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	DWORD StartTicks = GetTickCount();
	gStartTicks = StartTicks;

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
	m_iSpawnedProcess++;

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

		// @TODO update with real data, this works with 
		// only 1 process as this is right now.
		m_hCurrentThread = pi.hThread;
		m_hCurrentProcess = pi.hProcess;
		//m_hCurrentContext = nullptr;

		if (m_InteractiveSessionObject != nullptr)
		{
			m_InteractiveSessionObject->DebugEvent();
		}

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
						wow64engine.SetStartAddress(m_dw64StartAddress);
						wow64engine.Wow64Breakpoint(pi.hProcess, pi.hThread);
					break;

					case STATUS_WX86_SINGLE_STEP:
						// 0x4000001EL
						// http://reverseengineering.stackexchange.com/questions/9313/opening-program-via-ollydbg-immunity-in-win7-causes-exception-unless-in-xp-compa
						hr = wow64engine.Wow64SingleStep(pi.hProcess, pi.hThread);
						if (FAILED(hr))
						{
							goto Exit;
						}
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
					// When using notepad in wow64, go to page setup, and you'll see this:
					// Unknown debug event : c0020043
					// Unknown debug event : 3e6
					//
					// Other missing values:
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
				m_iSpawnedProcess--;

				if (m_iSpawnedProcess == 1)  bContinue = false;

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

HRESULT DebugEngine::ExceptionAccessViolation(HANDLE hProcess, HANDLE hThread, const EXCEPTION_RECORD& exception)
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

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(hProcess, &bIsWow64))
		{
			hr =  HRESULT_FROM_WIN32(GetLastError());
			goto Exit;
		}
	}

	Write(WriteLevel::Debug, L"Process is WoW64: %d", bIsWow64);

	if (!bIsWow64)
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

	EXIT_FN
}

HRESULT DebugEngine::DebugStringEvent(const DEBUG_EVENT& de)
{
	ENTER_FN

	OUTPUT_DEBUG_STRING_INFO DebugString = de.u.DebugString;

	// @TODO Allocate based on unicode
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
		goto Cleanup;
	}

	if (msg)
	{
		if (msg[0] == 0xd && msg[1] == 0xa)
		{
			// <CR><LF> - Carriage regurn & New line, if we dont do this, Acces Violation when trying to print this 
			goto Cleanup;
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

Cleanup:
	delete [] msg;

	if (hProcess)
	{
		CloseHandle(hProcess);
		hProcess = NULL;
	}

	EXIT_FN
}



HRESULT DebugEngine::InsertBreakpoint(HANDLE hProcess, DWORD64 dw64Address)
{
	ENTER_FN;

	BYTE bInstruction;
	SIZE_T nNumberOfBytesRead;

	int iResult = ReadProcessMemory(
			hProcess,
			(void*)dw64Address,
			&bInstruction,
			1,
			&nNumberOfBytesRead);

	if (iResult == 0)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		Write(WriteLevel::Error, L"Unable to insert breakpoint. ReadProcessMemory failed 0x%x", hr);
		goto Exit;
	}

	if (bInstruction == 0xCC)
	{
		Write(WriteLevel::Info, L"Insertint a BP where there is alreay a BP instruction");
		hr = S_OK;
		goto Exit;
	}

	Write(WriteLevel::Debug, L"Inserting BP at 0x%08x ", dw64Address);

	m_mBreakpointsOriginalInstruction.insert(
			std::pair<DWORD64, BYTE>(dw64Address, bInstruction));

	m_bOriginalInstruction = bInstruction;

	// Write new instruction
	bInstruction = 0xCC;
	WriteProcessMemory(hProcess, (void*)dw64Address, &bInstruction, 1, &nNumberOfBytesRead);
	FlushInstructionCache(hProcess, (void*)dw64Address, 1);

	EXIT_FN;
}

HRESULT DebugEngine::ExceptionSingleStep(HANDLE hProcess, HANDLE hThread)
{
	ENTER_FN

	CONTEXT lcContext = {0};

	//
	// Wow has its own single step, this is always native 
	//
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

HRESULT DebugEngine::LoadDllDebugEvent(const DEBUG_EVENT& de, HANDLE hProcess)
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
			NULL,
			NULL,
			(DWORD64)de.u.LoadDll.lpBaseOfDll,
			0,
			NULL,
			0);

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
				goto Cleanup;
			}

			hr = S_OK;
		}

		//Write(WriteLevel::Info, L"ReadProcessMemory read 0x%x bytes %s ", lpNumberOfBytesRead, cInstruction);
	}

	Write(WriteLevel::Info, L" %p \t (%sdebug info) \t %s",
			de.u.LoadDll.lpBaseOfDll,
			//de.u.LoadDll.lpBaseOfDll,
			de.u.LoadDll.nDebugInfoSize == 0 ? L"no " : L"",
			pszFilename);

Cleanup:
	CloseHandle(de.u.LoadDll.hFile);

	EXIT_FN
}

HRESULT DebugEngine::CreateProcessDebugEvent(const DEBUG_EVENT& de)
{
	ENTER_FN

	LPCREATE_PROCESS_DEBUG_INFO pCreateProcessDebugInfo = (LPCREATE_PROCESS_DEBUG_INFO)&de.u.CreateProcessInfo;
	HANDLE hProcess = de.u.CreateProcessInfo.hProcess;

	IMAGEHLP_MODULE64 module_info_symbols;
	module_info_symbols.SizeOfStruct = sizeof(module_info_symbols);

	IMAGEHLP_MODULE64 module_info_module;
	module_info_module.SizeOfStruct = sizeof(module_info_module);

	LPWSTR processName = new WCHAR[MAX_PATH];

	Write(WriteLevel::Debug, L"CREATE_PROCESS_DEBUG_INFO = {"
			L"hFile=0x%08LX"
			L" hProcess=0x%08LX"
			L" hThread=0x%08LX",
			pCreateProcessDebugInfo->hFile,
			pCreateProcessDebugInfo->hProcess,
			pCreateProcessDebugInfo->hThread);

	Write(WriteLevel::Debug, L"CREATE_PROCESS_DEBUG_INFO = {"
			L" lpBaseOfImage=0x%p "
			L" lpStartAddress=0x%p }",
			pCreateProcessDebugInfo->lpBaseOfImage,
			pCreateProcessDebugInfo->lpStartAddress);

	m_iSpawnedProcess++;

	m_dwProcessNameLen = GetFinalPathNameByHandleW(
						de.u.CreateProcessInfo.hFile,
						processName,
						MAX_PATH,
						0);
	if (m_dwProcessNameLen == 0)
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
		Write(WriteLevel::Debug , L"SymLoadModuleEx OK returned dwBase=0x%p", dwBase);
	}


	//
	// Retrieves the module information of the specified module.
	//
	Write(WriteLevel::Debug , L"SymGetModuleInfo64 on hProcess=0x%x, Start Address=0x%p", hProcess, dwBase);
	BOOL bSuccess = SymGetModuleInfo64(
			hProcess,
			dwBase,
			&module_info_symbols);

	if (!bSuccess)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		Write(WriteLevel::Error, L"SymGetModuleInfo64 failed with 0x%x to load symbols moudule", hr);
		goto Exit;
	}

	BREAK_IF_DEBUGGER_PRESENT();

	//
	// Retrieves the module information of the specified module.
	// bSuccess = SymGetModuleInfo64(
	//
	// It appears that CREATE_PROCESS_DEBUG_EVENT is too early to execute
	// SymLoadModule64, the modules must not have been loaded yet at that
	// point. If instead I do it 'just-in-time' when a program breakpoint
	// gets hit (ie in FindCode) it seems to work with no problems.
	//			 http://stackoverflow.com/questions/27026579/symgetlinefromaddr64-gives-errors-7e-1e7//
	//
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

	// @TODO get the size of the loaded module
#ifdef _AMD64_
	Write(WriteLevel::Info, L" %p   \t (%sdebug info) \t %s",
			de.u.CreateProcessInfo.lpBaseOfImage,
			//(DWORD64)de.u.CreateProcessInfo.lpBaseOfImage, // + (DWORD64)module_info_module.ImageSize),
			(module_info_symbols.SymType == SymPdb) ? L"" : L"no ",
			processName);
#else
	Write(WriteLevel::Info, L" %p  \t (%sdebug info) \t %s",
			de.u.CreateProcessInfo.lpBaseOfImage,
			//de.u.CreateProcessInfo.lpBaseOfImage, // + module_info_module.ImageSize),
			(module_info_symbols.SymType == SymPdb) ? L"" : L"no ",
			processName);
#endif


	//
	// Insert a break point by replacing the first instruction
	//
	

	// I'll need this to set the wow64 breakpoint
	m_dw64StartAddress = (DWORD64)de.u.CreateProcessInfo.lpStartAddress;

	// Insert breakpoint for native
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	BOOL bIsWow64 = FALSE;

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
		InsertBreakpoint(hProcess, m_dw64StartAddress);
	}

	EXIT_FN
}

HRESULT DebugEngine::StepOver()
{
	ENTER_FN

	EXIT_FN
}

HRESULT DebugEngine::AddInteractiveSession(InteractiveCommandLine * interactive)
{
	ENTER_FN

	m_InteractiveSessionObject = interactive;

	EXIT_FN
}

HRESULT DebugEngine::ExceptionBreakpoint(HANDLE hThread, HANDLE hProcess)
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
	if (m_bfirstDebugEvent)
	{
		// First chance: Display the current instruction and register values.
		Write(WriteLevel::Info, L"EXCEPTION_BREAKPOINT (first) ignoring...");
		m_bfirstDebugEvent = 0;
	}
	else
//#endif
	{
		Write(WriteLevel::Info, L"EXCEPTION_BREAKPOINT");

		GetCurrentFunctionName(hThread, hProcess, lcContext);

		if (!m_mBreakpointsOriginalInstruction.empty())
		{

#ifdef _X86_
			dw64StartAddress = lcContext.Eip - 1;
#else
			dw64StartAddress = lcContext.Rip - 1;
#endif

			auto element = m_mBreakpointsOriginalInstruction.find(dw64StartAddress);
			if (element != m_mBreakpointsOriginalInstruction.end())
			{
				Write(WriteLevel::Info, L"Found a BP that i had set!, %d", element->second);
				SIZE_T lNumberOfBytesRead;

				// Write back original instruction and remove BP from map
				WriteProcessMemory(hProcess, (LPVOID)element->first, &element->second, 1, &lNumberOfBytesRead);
				FlushInstructionCache(hProcess, (LPVOID)dw64StartAddress, 1);

				Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");
				lcContext.EFlags |= 0x100;

#ifdef _X86_
				lcContext.Eip--;
#else
				lcContext.Rip--;
#endif

				if (0 == SetThreadContext(hThread, &lcContext))
				{
					hr = HRESULT_FROM_WIN32(GetLastError());
					Write(WriteLevel::Error, L"SetThreadContext failed with 0x%x.", hr);
					goto Exit;
				}
			}

		}


//		// This does not work when you have a physical DebugBreak() in the code
//		if (m_bOriginalInstruction != 0)
//		{
//			Write(WriteLevel::Debug, L"Writing back original instruction ");
//
//			SIZE_T lNumberOfBytesRead;
//
//#ifdef _X86_
//			lcContext.Eip--;
//			DWORD dwStartAddress;
//			dwStartAddress = lcContext.Eip;
//			WriteProcessMemory(hProcess, (LPVOID)dwStartAddress, &m_bOriginalInstruction, 1, &lNumberOfBytesRead);
//			FlushInstructionCache(hProcess, (LPVOID)dwStartAddress, 1);
//#else
//			lcContext.Rip--;
//			dw64StartAddress = lcContext.Rip;
//			WriteProcessMemory(hProcess, (LPVOID)dw64StartAddress, &m_bOriginalInstruction, 1, &lNumberOfBytesRead);
//			FlushInstructionCache(hProcess, (LPVOID)dw64StartAddress, 1);
//#endif
//
//			m_bOriginalInstruction = 0;
//		}
//
//		Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");
//		lcContext.EFlags |= 0x100;
//
//		//A 64-bit application can set the context of a WOW64 thread using the Wow64SetThreadContext function.
//		if (0 == SetThreadContext(hThread, &lcContext))
//		{
//			hr = HRESULT_FROM_WIN32(GetLastError());
//			Write(WriteLevel::Error, L"SetThreadContext failed with 0x%x.", hr);
//			goto Exit;
//		}
	}

	EXIT_FN
}

HRESULT DebugEngine::GetCurrentFunctionName(HANDLE hThread, HANDLE hProcess, const CONTEXT& context)
{
	ENTER_FN

	std::string sFuntionName;
	std::wstring wsFuctionName;
	DWORD64 instructionPointer;
	BOOL bSkip = FALSE;

	hr = RetrieveCallstack(hThread, hProcess, context, 1 /* 1 frame */, &sFuntionName, &instructionPointer, &bSkip);

	if (bSkip)
	{
		hr = S_OK;
		goto Exit;
	}

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
		if (sFuntionName.compare(m_sLastFunctionName) == 0)
		{
			goto Exit;
		}
		else
		{
			m_sLastFunctionName = sFuntionName;
		}
	}

	m_lFunctionCalls++;

	wsFuctionName.assign(sFuntionName.begin(), sFuntionName.end());

	//
	// Note that this instructionPointer is not the last instruction
	//
	//
	// @TODO print memory contents at that address
	//
#ifdef _X86_
	Write(WriteLevel::Info, L"0x%p %4d %s",
				(DWORD)instructionPointer,
				m_lFunctionCalls,
				wsFuctionName.c_str());
#else
	Write(WriteLevel::Info, L"0x%p %4d thread=%x  %s", 
				instructionPointer,
				m_lFunctionCalls,
				hThread,
				wsFuctionName.c_str());
#endif

	EXIT_FN
}

HRESULT DebugEngine::GetCurrentCallstack()
{
	ENTER_FN

	STACKFRAME64 stack = {0};
	IMAGEHLP_SYMBOL64 *pSym = NULL;
	bool bModuleFound = FALSE;
	DWORD64 dwOffsetFromSmybol = 0;
	std::string sModuleName;
	std::map<std::string, IMAGEHLP_MODULE64>::iterator it;

	int nFramesToRead = 8;

	m_hCurrentContext.ContextFlags = CONTEXT_ALL;

	BOOL bResult = GetThreadContext(m_hCurrentThread, &m_hCurrentContext);
	if (!bResult)
	{
		hr =  HRESULT_FROM_WIN32(GetLastError());
		Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", hr);
		goto Exit;
	}

	DumpContext(m_hCurrentContext);

#ifdef _X86_
	stack.AddrPC.Offset = m_hCurrentContext.Eip;    // EIP - Instruction Pointer
	stack.AddrFrame.Offset = m_hCurrentContext.Ebp; // EBP
	stack.AddrStack.Offset = m_hCurrentContext.Esp; // ESP - Stack Pointer
#else
	stack.AddrPC.Offset = m_hCurrentContext.Rip;    // EIP - Instruction Pointer
	stack.AddrFrame.Offset = m_hCurrentContext.Rbp; // EBP
	stack.AddrStack.Offset = m_hCurrentContext.Rsp; // ESP - Stack Pointer
#endif

	stack.AddrPC.Mode = AddrModeFlat;
	stack.AddrFrame.Mode = AddrModeFlat;
	stack.AddrStack.Mode = AddrModeFlat;

	pSym = (IMAGEHLP_SYMBOL64*) malloc(sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
	pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
	pSym->MaxNameLength = STACKWALK_MAX_NAMELEN;

	Write(WriteLevel::Debug, L"SymInitialize on hProcess=0x%x ...", m_hCurrentProcess);

	if (FALSE == m_bSymInitialized)
	{
		m_bSymInitialized = TRUE;
		BOOL bRes = SymInitialize(m_hCurrentProcess, NULL, TRUE);
		if (FALSE == bRes)
		{
			DWORD error = GetLastError();
			if (error != ERROR_SUCCESS)
			{
				hr = HRESULT_FROM_WIN32(error);
				Write(WriteLevel::Error, L"SymInitialize failed 0x%x", error);
				goto Cleanup;
			}
		}
	}

//	// We have the IP, search in the cache first before calling API to get the mod name
//	Write(WriteLevel::Debug, L"im looking for this address, 0x%p", stack.AddrPC.Offset);
//	for (it = m_mLoadedModules.begin(); it != m_mLoadedModules.end(); ++it)
//	{
//		if ((stack.AddrPC.Offset > it->second.BaseOfImage)
//				&& (stack.AddrPC.Offset < (it->second.BaseOfImage + it->second.ImageSize)))
//		{
//			sModuleName = it->first;
//			bModuleFound = TRUE;
//		}
//	}

	if (!bModuleFound)
	{
		// if we got out, this means we havent loaded this module, do it
		IMAGEHLP_MODULE64 module_info_module;
		module_info_module.SizeOfStruct = sizeof(module_info_module);

		BOOL bSuccess = SymGetModuleInfo64(
				m_hCurrentProcess,
				stack.AddrPC.Offset,
				&module_info_module);

		if (!bSuccess)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"SymGetModuleInfo64 failed with 0x%x at addess %p",
					hr, (DWORD64)stack.AddrPC.Offset);
			goto Exit;
		}
		else
		{
			// Add this new found module to the cache
			sModuleName = module_info_module.ModuleName;
			m_mLoadedModules.insert(std::pair<std::string, IMAGEHLP_MODULE64>(sModuleName, module_info_module));
		}
	}

	for (int frameNum = 0; (nFramesToRead ==0) || (frameNum < nFramesToRead); ++frameNum)
	{
		Write(WriteLevel::Debug, L"About to walk the stack hProcess=0x%x hThread=0x%x", m_hCurrentProcess, m_hCurrentThread);

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
				m_hCurrentProcess,
				m_hCurrentThread,
				&stack,
				(PVOID)(&m_hCurrentContext), // only pass for x86
				NULL,
				SymFunctionTableAccess64,
				SymGetModuleBase64,
				NULL);

		if (FALSE == bResult)
		{
			// StackWalk64 does not set "GetLastError"...
			// this also might indicate end of stack
			hr = HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"StackWalk64 failed, the following hr must not be trusted: hr=%x", hr);
			goto Cleanup;
		}

		if (stack.AddrPC.Offset == 0)
		{
			Write(WriteLevel::Error, L"stack.AddrPC.Offset == 0");
			goto Exit;
		}

		// we seem to have a valid PC
		if (SymGetSymFromAddr64(m_hCurrentProcess,
									stack.AddrPC.Offset,
									&dwOffsetFromSmybol,
									pSym) != FALSE)
		{
			std::string sFuntionName;
			sFuntionName = sModuleName;
			sFuntionName += "!";
			sFuntionName += pSym->Name;

			std::wstring wsFuctionName;
			wsFuctionName.assign(sFuntionName.begin(), sFuntionName.end());

			Write(WriteLevel::Info, L" %d -> %s", frameNum, wsFuctionName.c_str());
		}
		else
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error,
						L"SymGetSymFromAddr64 failed 0x%x, address=0x%p",
						hr,
						stack.AddrPC.Offset);
			goto Cleanup;
		}
	} // for

Cleanup:
	if (pSym)
	{
		delete pSym;
	}

	EXIT_FN
}

HRESULT DebugEngine::RetrieveCallstack(HANDLE hThread, HANDLE hProcess, const CONTEXT& context, int nFramesToRead, std::string* sFuntionName, DWORD64* ip, BOOL* bSkip)
{
	ENTER_FN

	STACKFRAME64 stack = {0};
	IMAGEHLP_SYMBOL64 *pSym = NULL;
	DWORD64 dwOffsetFromSmybol = 0;
	std::string sModuleName;
	bool bModuleFound = FALSE;
	std::map<std::string, IMAGEHLP_MODULE64>::iterator it;

	*bSkip = FALSE;

	if (hThread == INVALID_HANDLE_VALUE
			|| hProcess == INVALID_HANDLE_VALUE)
	{
		Write(WriteLevel::Error, L"Handles are invalid");
		goto Cleanup;
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

	if (FALSE == m_bSymInitialized)
	{
		m_bSymInitialized = TRUE;
		BOOL bRes = SymInitialize(hProcess, NULL, TRUE);
		if (FALSE == bRes)
		{
			DWORD error = GetLastError();
			if (error != ERROR_SUCCESS)
			{
				hr = HRESULT_FROM_WIN32(error);
				Write(WriteLevel::Error, L"SymInitialize failed 0x%x", error);
				goto Cleanup;
			}
		}
	}

	// We have the IP, search in the cache first before calling API to get the mod name
	Write(WriteLevel::Debug, L"im looking for this address, 0x%p", stack.AddrPC.Offset);
	for (it = m_mLoadedModules.begin(); it != m_mLoadedModules.end(); ++it)
	{
		if ((stack.AddrPC.Offset > it->second.BaseOfImage)
				&& (stack.AddrPC.Offset < (it->second.BaseOfImage + it->second.ImageSize)))
		{
			sModuleName = it->first;
			bModuleFound = TRUE;
		}
	}

	if (!bModuleFound)
	{
		// if we got out, this means we havent loaded this module, do it
		IMAGEHLP_MODULE64 module_info_module;
		module_info_module.SizeOfStruct = sizeof(module_info_module);

		BOOL bSuccess = SymGetModuleInfo64(
				hProcess,
				stack.AddrPC.Offset,
				&module_info_module);

		if (!bSuccess)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"SymGetModuleInfo64 failed with 0x%x at addess %p",
					hr, (DWORD64)stack.AddrPC.Offset);
			goto Exit;
		}
		else
		{
			// Add this new found module to the cache
			sModuleName = module_info_module.ModuleName;
			m_mLoadedModules.insert(std::pair<std::string, IMAGEHLP_MODULE64>(sModuleName, module_info_module));
		}
	}

	// This needs work, maybe configurable to say what to and not to show
	if ((gAnalysisLevel == 3) &&
			(sModuleName.compare("ntdll") == 0
			|| sModuleName.compare("KERNELBASE") == 0
			|| sModuleName.compare("msvcrt") == 0
			|| sModuleName.compare("dbghelp") == 0
			|| sModuleName.compare("KERNEL32") == 0))
	{
		*bSkip = TRUE;
		//DebugBreak();
		goto Cleanup;
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
			hr = HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"StackWalk64 failed, the following hr must not be trusted: hr=%x", hr);
			goto Cleanup;
		}

#if 0
			if (FALSE == SymRefreshModuleList(hProcess))
			{
					Write(WriteLevel::Error, L"SymRefreshModuleList failed :(");
			}
#endif

		if (stack.AddrPC.Offset == 0)
		{
			goto Exit;
		}

		// we seem to have a valid PC
		if (SymGetSymFromAddr64(hProcess,
									stack.AddrPC.Offset,
									&dwOffsetFromSmybol,
									pSym) != FALSE)
		{
			// Undecorate names:
			// Check pSym->name

			// Copy into caller
			*sFuntionName = sModuleName;
			*sFuntionName += "!";
			*sFuntionName += pSym->Name;
		}
		else
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error,
						L"SymGetSymFromAddr64 failed 0x%x, address=0x%p",
						hr,
						stack.AddrPC.Offset);

			BREAK_IF_DEBUGGER_PRESENT();

			goto Cleanup;
		}

	} // for

Cleanup:
	if (pSym)
	{
		delete pSym;
	}

	EXIT_FN
}

