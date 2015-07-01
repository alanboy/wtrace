
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
#include <WinBase.h>
#include <Winternl.h>
#include <Dbghelp.h>

#include "output.h"
#include "Utils.h"
#include "Main.h"
#include "Debugger.h"

#define WIDE2(x) L##x
#define WIDE1(x) WIDE2(x)
#define ENTER_FN \
			dFunctionDepth++; \
			Write(WriteLevel::Debug, L"ENTERING FUNCTION " WIDE1(__FUNCTION__)); \
			dFunctionDepth++;

#define EXIT_FN \
			dFunctionDepth--; \
			Write(WriteLevel::Debug, L"EXITING  FUNCTION " WIDE1(__FUNCTION__)); \
			dFunctionDepth--;



int gAnalysisLevel;
BYTE m_OriginalInstruction;
DWORD processNameLen;
LPVOID g_dwStartAddress;
int nSpawnedProcess;
bool bSyminitialized;
bool firstDebugEvent = 1;
std::string lastFunctionName;
long lnFunctionCalls = 0;



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

void DumpContext(const CONTEXT& lcContext)
{
#ifdef _X86_
	Write(WriteLevel::Info, L" IP=0x%x Instruction=0x%x",
			lcContext.Eip,
			*lcContext.Eip,
		 );
#else
	Write(WriteLevel::Info,  L"RIP = %08X EAX = %08X EBX = %08X ECX = %08X "
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
}

void Run()
{
	ENTER_FN

	DEBUG_EVENT de = {0};
	int bCreateProcRes;
	HRESULT hr;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	bSyminitialized = FALSE;
	g_dwStartAddress = 0;

	// Ref count of processes created
	nSpawnedProcess = 0;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	Write(WriteLevel::Debug, L"Creating process %s", gpCommandLine);

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	DWORD StartTicks = GetTickCount();

	bCreateProcRes = CreateProcess(NULL, gpCommandLine, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi );

	if (bCreateProcRes)
	{
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
										L" dwDebugEventCode = 0x%08LX)",
										de.dwProcessId,
										de.dwThreadId,
										de.dwDebugEventCode);

			switch (de.dwDebugEventCode)
			{
				case EXCEPTION_DEBUG_EVENT:

					switch (de.u.Exception.ExceptionRecord.ExceptionCode)
					{
						case EXCEPTION_ACCESS_VIOLATION:
						// First chance: Pass this on to the system. 
						// Last chance: Display an appropriate error. 
						Write(WriteLevel::Debug, L"EXCEPTION_ACCESS_VIOLATION");
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
							ExceptionSingleStep(pi.hProcess, pi.hThread);
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
						Write(WriteLevel::Debug, L"unknown debug event \t%d ? ", de.u.Exception.ExceptionRecord.ExceptionCode);
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

			hr  = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);

			if(FAILED(hr))
			{
				Write(WriteLevel::Debug, L"Error.");
				break;
			}
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

	}
	else
	{
		Write(WriteLevel::Error, L"Unable to create process. hr=0x%x", GetLastError());
	}

	DWORD TickDiff = GetTickCount() - StartTicks;

	Write(WriteLevel::Output, L"Finished after %d seconds ", TickDiff/1000 );

	EXIT_FN
}

void DebugStringEvent(const DEBUG_EVENT& de)
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
		Write(WriteLevel::Output, L"OUTPUT_DEBUG_STRING_EVENT: %s", msg);
	}
	else
	{
		Write(WriteLevel::Output, L"OUTPUT_DEBUG_STRING_EVENT: ");
	
	}

	delete [] msg;

	EXIT_FN
}

void ExceptionSingleStep(HANDLE hProcess, HANDLE hThread)
{
	ENTER_FN

	CONTEXT lcContext = {0};

	// First chance: Update the display of the 
	// current instruction and register values. 
	if (gAnalysisLevel >= 3)
	{
		lcContext.ContextFlags = CONTEXT_ALL;

		BOOL bResult = GetThreadContext(hThread, &lcContext);
		if (!bResult)
		{
			Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", GetLastError());
			goto Exit;
		}

//		DumpContext(lcContext);

//		if (IsDebuggerPresent())
//		{
//			//DebugBreak();
//		}

		lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception

		bResult = SetThreadContext(hThread, &lcContext);
		if (!bResult)
		{
			Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", GetLastError());
			goto Exit;
		}

		GetCurrentFunctionName(
				hThread,
				hProcess);

		//gAnalysisLevel = 0;
	}

Exit:
	EXIT_FN
}

void LoadDllDebugEvent(const DEBUG_EVENT& de, HANDLE hProcess)
{
	ENTER_FN

	// Read the debugging information included in the newly loaded DLL.
	WCHAR pszFilename[MAX_PATH+1];
	GetFileNameFromHandle(de.u.LoadDll.hFile, (WCHAR *)&pszFilename);

	wchar_t *pwstrDllName;
	pwstrDllName = pszFilename;
	IMAGEHLP_MODULE64 module_info;
	BOOL bSuccess;
	DWORD64 dwBase;

	Write(WriteLevel::Debug, L"SymLoadModuleEx on hProcess 0x%x", hProcess);
	dwBase = SymLoadModuleEx(
			hProcess,//_In_  HANDLE hProcess,
			NULL,//_In_  HANDLE hFile,
			NULL,//_In_  PCTSTR ImageName,
			NULL,//_In_  PCTSTR ModuleName,
			(DWORD64)de.u.LoadDll.lpBaseOfDll,//_In_  DWORD64 BaseOfDll,
			0,//_In_  DWORD DllSize,
			NULL,//_In_  PMODLOAD_DATA Data,
			0);//_In_  DWORD Flags

	if (0 == dwBase)
	{
		Write(WriteLevel::Error, L"SymLoadModuleEx failed with 0x%x", GetLastError());
		goto Exit;
	}

	module_info.SizeOfStruct = sizeof(module_info);
	bSuccess = SymGetModuleInfo64(
			hProcess,
			dwBase,
			&module_info);

	if (!bSuccess)
	{
		Write(WriteLevel::Error, L"SymGetModuleInfo64 failed with %x", GetLastError());
		goto Exit;
	}

	Write(WriteLevel::Info, L"Loaded %s at %x, symbols %s loaded",
			pwstrDllName,
			de.u.LoadDll.lpBaseOfDll,
			(bSuccess && module_info.SymType == SymPdb) ? L"" : L" NOT ");

Exit:
	EXIT_FN
}

void CreateProcessDebugEvent(const DEBUG_EVENT& de)
{
	ENTER_FN

	LPCREATE_PROCESS_DEBUG_INFO pCreateProcessDebugInfo = (LPCREATE_PROCESS_DEBUG_INFO)&de.u.CreateProcessInfo;

	BYTE cInstruction;
	DWORD64 dw64StartAddress = 0;
	HANDLE hProcess = de.u.CreateProcessInfo.hProcess;
	IMAGEHLP_MODULE64 module_info;
	SIZE_T lpNumberOfBytesRead;
	LPWSTR processName = new WCHAR[MAX_PATH];

	Write(WriteLevel::Debug, L"LPCREATE_PROCESS_DEBUG_INFO = {"
			L"hFile = 0x%08LX"
			L" hProcess = 0x%08LX"
			L" hThread = 0x%08LX"
			L" lpBaseOfImage = 0x%08LX }",
			pCreateProcessDebugInfo->hFile,
			pCreateProcessDebugInfo->hProcess,
			pCreateProcessDebugInfo->hThread,
			pCreateProcessDebugInfo->lpBaseOfImage);

	g_dwStartAddress = (LPVOID)de.u.CreateProcessInfo.lpStartAddress;
	dw64StartAddress = (DWORD64)de.u.CreateProcessInfo.lpStartAddress;

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
	Write(WriteLevel::Info , L"SymLoadModuleEx on hProcess=0x%x", hProcess);
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
		Write(WriteLevel::Info , L"SymLoadModuleEx OK returned dwBase=0x%x", dwBase);
        dw64StartAddress = dwBase;
	}

	module_info.SizeOfStruct = sizeof(module_info);

	//
	// Retrieves the module information of the specified module.
	//
	Write(WriteLevel::Debug , L"SymGetModuleInfo64 on hProcess=0x%x, dwStartAddress=0x%x", hProcess, dw64StartAddress);
	BOOL bSuccess = SymGetModuleInfo64(
			hProcess,
			dw64StartAddress,
			&module_info);

	if (!bSuccess)
	{
		Write(WriteLevel::Error, L"SymGetModuleInfo64 failed with 0x%x", GetLastError());
		goto Exit;
	}

	Write(WriteLevel::Debug, L"Crated process %s, symbols %sloaded ",
			processName,
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
						(void*)g_dwStartAddress,
						&cInstruction,
						1,
						&lpNumberOfBytesRead);

		if (result == 0)
		{
			Write(WriteLevel::Debug, L"ReadProcessMemory failed %x", GetLastError());
			goto Exit;
		}

		if (cInstruction != 0xCC)
		{
			Write(WriteLevel::Debug, L"Replacing first instruction '%x' with 0xCC", cInstruction);
			m_OriginalInstruction = cInstruction;

			// Replace it with Breakpoint
			cInstruction = 0xCC;
			WriteProcessMemory(hProcess, (void*)g_dwStartAddress,&cInstruction, 1, &lpNumberOfBytesRead);
			FlushInstructionCache(hProcess, (void*)g_dwStartAddress, 1);
		}
	}

Exit:
	EXIT_FN
}


void ExceptionBreakpoint(HANDLE hThread, HANDLE hProcess)
{
	ENTER_FN

	CONTEXT lcContext;

	if (firstDebugEvent)
	{
		// First chance: Display the current instruction and register values.
		Write(WriteLevel::Info, L"EXCEPTION_BREAKPOINT (first) ignoring...");
		firstDebugEvent = 0;
	}
	else
	{
		Write(WriteLevel::Info, L"EXCEPTION_BREAKPOINT");
		Write(WriteLevel::Debug, L"Start address=%x", g_dwStartAddress);

		lcContext.ContextFlags = CONTEXT_ALL;
		BOOL bResult = GetThreadContext(hThread, &lcContext);
		if (!bResult)
		{
			Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", GetLastError());
			goto Exit;
		}

		DumpContext(lcContext);

		GetCurrentFunctionName(hThread, hProcess);

		// This does not work when you have a physical DebugBreak() in the code
		Write(WriteLevel::Debug, L"Instruction pointer minus 1");
#ifdef _X86_
		lcContext.Eip--;
#else
		lcContext.Rip--;
#endif

		Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");
		lcContext.EFlags |= 0x100;
		SetThreadContext(hThread, &lcContext);

		if (m_OriginalInstruction != 0)
		{
			Write(WriteLevel::Debug, L"Writing back original instruction ");
			SIZE_T lNumberOfBytesRead ;
			WriteProcessMemory(hProcess, g_dwStartAddress, &m_OriginalInstruction, 1, &lNumberOfBytesRead);
			FlushInstructionCache(hProcess, g_dwStartAddress, 1);
			m_OriginalInstruction = 0;
		}
	}

Exit:
	EXIT_FN
}

void GetCurrentFunctionName(HANDLE hThread, HANDLE hProcess)
{

	ENTER_FN

	std::string sFuntionName;
	DWORD64 instructionPointer;

	RetrieveCallstack(hThread, hProcess, 1, &sFuntionName, &instructionPointer); //1 means one frame

	if (sFuntionName.compare(lastFunctionName) == 0)
	{
		goto Exit;
	}
	else
	{
		lnFunctionCalls++;

		printf("0x%x %d : %s\n", instructionPointer, lnFunctionCalls, sFuntionName.c_str());

		lastFunctionName = sFuntionName;
	}

Exit:
	EXIT_FN
}

void RetrieveCallstack(HANDLE hThread, HANDLE hProcess, int nFramesToRead, std::string* sFuntionName, DWORD64 * ip)
{
	ENTER_FN

	CONTEXT context = {0};
	STACKFRAME64 stack = {0};
	IMAGEHLP_SYMBOL64 *pSym = NULL;
	CallstackEntry csEntry;

	if (hThread == INVALID_HANDLE_VALUE
			|| hProcess == INVALID_HANDLE_VALUE)
	{
		Write(WriteLevel::Error, L"Handles are invalid");
		goto Exit;
	}

	//Get the context
	context.ContextFlags = CONTEXT_FULL; //USED_CONTEXT_FLAGS ?

	if (GetThreadContext(hThread, &context) == FALSE)
	{
		Write(WriteLevel::Error, L"GetThreadContext failed 0x%x", GetLastError());
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

		BOOL bResult = StackWalk64(
				IMAGE_FILE_MACHINE_AMD64, // IMAGE_FILE_MACHINE_I386,
				hProcess,
				hThread,
				&stack,
				&context,
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
			// show procedure info (SymGetSymFromAddr64())
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
			}
			else
			{
				Write(WriteLevel::Error,
							L"SymGetSymFromAddr64 failed 0x%x, s.AddrPC.Offset=0x%x",
							GetLastError(),
							stack.AddrPC.Offset);
			}
		}
	}

Exit:
	delete pSym;

	EXIT_FN
}

