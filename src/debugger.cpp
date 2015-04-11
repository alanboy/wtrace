
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

int gAnalysisLevel;
BYTE m_OriginalInstruction;
DWORD processNameLen;
LPVOID dwStartAddress;
LPWSTR processName;
PROCESS_INFORMATION pi;
int nSpawnedProcess;

void GetProcessInfo(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pinfo;
	ULONG resLen;

	LONG status = NtQueryInformationProcess(
			hProcess,
			PROCESSINFOCLASS::ProcessBasicInformation,
			(PVOID)&pinfo,
			sizeof(PVOID)*6,
			&resLen);

	PPEB ppeb = (PPEB)((PVOID*)&pinfo)[1];
	PPEB ppebCopy = (PPEB)malloc(sizeof(PEB));

	BOOL result = ReadProcessMemory(hProcess,
			ppeb,
			ppebCopy,
			sizeof(PEB),
			NULL);

	PRTL_USER_PROCESS_PARAMETERS pRtlProcParam = ppebCopy->ProcessParameters;
	PRTL_USER_PROCESS_PARAMETERS pRtlProcParamCopy = (PRTL_USER_PROCESS_PARAMETERS)malloc(sizeof(RTL_USER_PROCESS_PARAMETERS));

	result = ReadProcessMemory(hProcess,
			pRtlProcParam,
			pRtlProcParamCopy,
			sizeof(RTL_USER_PROCESS_PARAMETERS),
			NULL);

	PWSTR wBuffer = pRtlProcParamCopy->CommandLine.Buffer;
	USHORT len =  pRtlProcParamCopy->CommandLine.Length;
	PWSTR wBufferCopy = (PWSTR)malloc(len);
	result = ReadProcessMemory(hProcess,
			wBuffer,
			wBufferCopy, // command line goes here
			len,
			NULL);

	if (gFp)
		fwprintf( gFp, L" %s\n", wBufferCopy );

}


void Run()
{
	BYTE cInstruction;
	CONTEXT lcContext;
	DEBUG_EVENT de = {0};
	DWORD dwReadBytes ;
	SIZE_T dwWriteSize ;
	HRESULT hr;
	STARTUPINFOW si;
	bool firstDebugEvent = 1;

	dwStartAddress = 0;
	processName = new WCHAR[MAX_PATH];

	// Ref count of processes created
	nSpawnedProcess = 0;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	Write(WriteLevel::Debug, L"Creating process %s", gpCommandLine);

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	DWORD StartTicks = GetTickCount();

	bool bCreateProcRes;
	bCreateProcRes = CreateProcess(NULL, gpCommandLine, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi );

	if (bCreateProcRes)
	{
		nSpawnedProcess++;

		int bContinue = TRUE;
		while (bContinue)
		{
			WaitForDebugEvent(&de, INFINITE);

			//Write(WriteLevel::Debug, "dwProcessId = %d", de.dwProcessId);
			//Write(WriteLevel::Debug, "dwThreadId = %d", de.dwThreadId);
			//Write(WriteLevel::Debug, "dwDebugEventCode = %d", de.dwDebugEventCode);

			switch (de.dwDebugEventCode)
			{
				case EXCEPTION_DEBUG_EVENT: 

					Write(WriteLevel::Debug, L"EXCEPTION_DEBUG_EVENT");
					switch (de.u.Exception.ExceptionRecord.ExceptionCode)
					{
						case EXCEPTION_ACCESS_VIOLATION: 
						// First chance: Pass this on to the system. 
						// Last chance: Display an appropriate error. 
						Write(WriteLevel::Debug, L"	EXCEPTION_ACCESS_VIOLATION");
						break;

						case EXCEPTION_BREAKPOINT: 
						// First chance: Display the current 
						// instruction and register values.

						if (firstDebugEvent)
						{
							Write(WriteLevel::Debug, L"First EXCEPTION_BREAKPOINT ignoring...");
							firstDebugEvent = 0;
						}
						else
						{
							Write(WriteLevel::Debug, L"EXCEPTION_BREAKPOINT");
							Write(WriteLevel::Debug, L"Start address=%x", dwStartAddress);

							lcContext.ContextFlags = CONTEXT_ALL;
							GetThreadContext(pi.hThread, &lcContext);
#ifdef _X86_
							lcContext.Eip--;
#else
							lcContext.Rip--;
#endif

							lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
							SetThreadContext(pi.hThread,&lcContext); 

							if (m_OriginalInstruction != 0)
							{
								WriteProcessMemory(pi.hProcess, dwStartAddress, &m_OriginalInstruction, 1,&dwWriteSize);
								FlushInstructionCache(pi.hProcess, dwStartAddress, 1);
								m_OriginalInstruction = 0;
							}


//							// I have restored the original instruction
//							RetrieveCallstack(
//								de.u.CreateProcessInfo.hThread,
//								de.u.CreateProcessInfo.hProcess);
						}

						break;

						case EXCEPTION_DATATYPE_MISALIGNMENT: 
						// First chance: Pass this on to the system. 
						// Last chance: Display an appropriate error. 
						Write(WriteLevel::Debug, L"	EXCEPTION_DATATYPE_MISALIGNMENT");

							
						break;

						case EXCEPTION_SINGLE_STEP: 
						// First chance: Update the display of the 
						// current instruction and register values. 
							Write(WriteLevel::Debug, L"	EXCEPTION_SINGLE_STEP");

							lcContext.ContextFlags = CONTEXT_ALL;
							GetThreadContext(pi.hThread, &lcContext);
//#if X86
//							lcContext.Eip--;
//#else
//							lcContext.Rip--;
							Write(WriteLevel::Debug, L"	rip=0x%x", lcContext.Rip);
//#endif

							lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
							SetThreadContext(pi.hThread,&lcContext); 

							//RetrieveCallstack(
							//	de.u.CreateProcessInfo.hThread,
							//	de.u.CreateProcessInfo.hProcess);

						break;
 
						case DBG_CONTROL_C:
						// First chance: Pass this on to the system. 
						// Last chance: Display an appropriate error. 
						Write(WriteLevel::Debug, L"	DBG_CONTROL_C");
						break;

						case 0xc000001d:
						Write(WriteLevel::Debug, L"Illegal Instruction  An attempt was made to execute an illegal instruction.");
						break;

						default:
						// Handle other exceptions. 
						Write(WriteLevel::Debug, L"    %d ? ", de.u.Exception.ExceptionRecord.ExceptionCode);
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
					LoadDllDebugEvent(de);
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

			if(!SUCCESS(hr))
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
		Write(WriteLevel::Output, L"Unable to create process.");
		DWORD creatProcessErr = GetLastError();
		printf("%x\n", creatProcessErr );
	}

	DWORD TickDiff = GetTickCount() - StartTicks;


	Write(WriteLevel::Output, L"Finished after %d milliseconds ", TickDiff );
}

void DebugStringEvent(const DEBUG_EVENT& de)
{
	Write(WriteLevel::Debug, L"");
	OUTPUT_DEBUG_STRING_INFO DebugString = de.u.DebugString;

	WCHAR *msg = new WCHAR[DebugString.nDebugStringLength];
	//// Don't care if string is ANSI, and we allocate double...

	ReadProcessMemory(
			pi.hProcess,					// HANDLE to Debuggee
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
		Write(WriteLevel::Output, L"OUTPUT_DEBUG_STRING_EVENT: %s", gpCommandLine);
	
	}

	delete []msg;
}

void LoadDllDebugEvent(const DEBUG_EVENT& de)
{
	// Read the debugging information included in the newly loaded DLL.
	WCHAR pszFilename[MAX_PATH+1];
	GetFileNameFromHandle(de.u.LoadDll.hFile, (WCHAR *)&pszFilename);

	wchar_t *pwstrDllName;
    pwstrDllName = pszFilename;
	//pwstrDllName = charToWChar(pszFilename);
    //
	Write(WriteLevel::Info, L"LOAD_DLL_DEBUG_EVENT: Loaded %s at %x",
			pwstrDllName,
			de.u.LoadDll.lpBaseOfDll);

	DWORD64 dwBase = SymLoadModuleEx(
			pi.hProcess,//_In_  HANDLE hProcess,
			NULL,//_In_  HANDLE hFile,
			NULL,//_In_  PCTSTR ImageName,
			NULL,//_In_  PCTSTR ModuleName,
			(DWORD64)de.u.LoadDll.lpBaseOfDll,//_In_  DWORD64 BaseOfDll,
			0,//_In_  DWORD DllSize,
			NULL,//_In_  PMODLOAD_DATA Data,
			0);//_In_  DWORD Flags

	IMAGEHLP_MODULE64 module_info;
	module_info.SizeOfStruct = sizeof(module_info);
	BOOL bSuccess = SymGetModuleInfo64(
			pi.hProcess,
			dwBase,
			&module_info);

	//// Check and notify
	if (bSuccess && module_info.SymType == SymPdb)
	{
		Write(WriteLevel::Info, L"Symbols loaded.");
	}
	else
	{
		Write(WriteLevel::Info, L"No symbols.");
	}
}

void CreateProcessDebugEvent(const DEBUG_EVENT& de)
{
	// As needed, examine or change the registers of the
	// process's initial thread with the GetThreadContext and
	// SetThreadContext functions; read from and write to the
	// process's virtual memory with the ReadProcessMemory and
	// WriteProcessMemory functions; and suspend and resume
	// thread execution with the SuspendThread and ResumeThread
	// functions. Be sure to close the handle to the process image
	// file with CloseHandle.
	Write(WriteLevel::Debug, L"CREATE_PROCESS_DEBUG_EVENT");
	dwStartAddress = (LPVOID)de.u.CreateProcessInfo.lpStartAddress;
	Write(WriteLevel::Debug, L"\tStart address=0x%x", dwStartAddress);

	nSpawnedProcess++;

	processNameLen = GetFinalPathNameByHandleW(
			de.u.CreateProcessInfo.hFile,//_In_   HANDLE hFile,
			processName,//_Out_  LPWTSTR lpszFilePath,
			MAX_PATH,//_In_   DWORD cchFilePath,
			0//_In_   DWORD dwFlags
			);

	if (processNameLen == 0)
	{
		Write(WriteLevel::Debug, L"GetFinalPathNameByHandle failed");
	}

	Write(WriteLevel::Output, L"New process name = %s", processName);

	//
	// Initializes the symbol handler for a process.
	//
	//		The current working directory of the application
	//		The _NT_SYMBOL_PATH environment variable
	//		The _NT_ALTERNATE_SYMBOL_PATH environment variable
	//
	BOOL bRes = SymInitialize(de.u.CreateProcessInfo.hProcess, NULL, false);
	if (FALSE == bRes)
	{
		DWORD error = GetLastError();
		if (error != ERROR_SUCCESS)
		{
			printf("SymInitialize returned %x\n", error);
		}
	}


	GetProcessInfo(de.u.CreateProcessInfo.hProcess);

	//
	// Loads the symbol table for the specified module.
	//
	DWORD64 dwBase = SymLoadModuleEx(
						de.u.CreateProcessInfo.hProcess,//_In_  HANDLE hProcess,
						de.u.CreateProcessInfo.hFile,//_In_  HANDLE hFile,
						"main.exe",//_In_  PCTSTR ImageName,
						NULL,//_In_  PCTSTR ModuleName,
						NULL,//_In_  DWORD64 BaseOfDll,
						0,//_In_  DWORD DllSize,
						NULL,//_In_  PMODLOAD_DATA Data,
						0);//_In_  DWORD Flags

	if (dwBase == 0)
	{
		DWORD error = GetLastError();
		if (error != ERROR_SUCCESS)
		{
			printf("SymLoadModuleEx returned %x\n", error);
		}
	}

	IMAGEHLP_MODULE64 module_info;
	module_info.SizeOfStruct = sizeof(module_info);

	//
	// Retrieves the module information of the specified module.
	//
	BOOL bSuccess = SymGetModuleInfo64(
			de.u.CreateProcessInfo.hProcess,
			dwBase,
			&module_info);

	if (bSuccess && module_info.SymType == SymPdb)
	{
		Write(WriteLevel::Info, L"Symbols loaded.");
		//also know if source code, check the module_info 
	}
	else
	{
		Write(WriteLevel::Info, L"No symbols.");
	}

	BYTE cInstruction;
	SIZE_T dwReadBytes;

	// Read the first instruction
	ReadProcessMemory(
			pi.hProcess,
			(void*)dwStartAddress,
			&cInstruction,
			1,
			&dwReadBytes);

	Write(WriteLevel::Debug, L"	replacing %x with BP", cInstruction);

	if (cInstruction != 0xCC) {
		m_OriginalInstruction = cInstruction;
		// Replace it with Breakpoint
		cInstruction = 0xCC;
		WriteProcessMemory(pi.hProcess, (void*)dwStartAddress,&cInstruction, 1, &dwReadBytes);
		FlushInstructionCache(pi.hProcess,(void*)dwStartAddress,1);
	}
}

void RetrieveCallstack(HANDLE hThread, HANDLE hProcess)
{
	// Initialize 'stack' with some required stuff.
	STACKFRAME64 stack={0};

	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;


#ifdef _X86_
	stack.AddrPC.Offset = context.Eip; // EIP - Instruction Pointer
	stack.AddrFrame.Offset = context.Ebp; // EBP
	stack.AddrStack.Offset = context.Esp; // ESP - Stack Pointer
#else
	stack.AddrPC.Offset = context.Rip; // EIP - Instruction Pointer
	stack.AddrFrame.Offset = context.Rbp; // EBP
	stack.AddrStack.Offset = context.Rsp; // ESP - Stack Pointer
#endif

	// Must be like this
	stack.AddrPC.Mode = AddrModeFlat;
	stack.AddrFrame.Mode = AddrModeFlat;
	stack.AddrStack.Mode = AddrModeFlat;

	GetThreadContext(hThread, &context);

	BOOL res = StackWalk64(
//			IMAGE_FILE_MACHINE_I386,
			IMAGE_FILE_MACHINE_AMD64,
			hProcess,
			hThread,
			&stack,
			&context,
			NULL,//		_ProcessMemoryReader,
			SymFunctionTableAccess64,
			SymGetModuleBase64,
			0);

	if (!res)
	{
		Write(WriteLevel::Info, L"StackWalk64 failed");
	}
	IMAGEHLP_MODULE64 module={0};
	module.SizeOfStruct = sizeof(module);

	BOOL bSuccess = SymGetModuleInfo64(
			hProcess,
			(DWORD64)stack.AddrPC.Offset,
			&module);

	if (bSuccess && module.SymType == SymPdb)
	{
		Write(WriteLevel::Info, L"Symbols loaded.");
		//also know if source code, check the module_info 
	}
	else
	{
		Write(WriteLevel::Info, L"No symbols.");
	}

	Write(WriteLevel::Debug, L"linenumbers=%x", module.LineNumbers);


//	DWORD add = GetStartAddress(hProcess, hThread, "mainCRTStartup");
//	printf("maincrtstartup = 0x%x \n", add);
//
//	add = GetStartAddress(hProcess, hThread, "LauraFun");
//	printf("maincrtstartup = 0x%x \n", add);
}


//
// Get the address of a given function name
//
//
DWORD GetStartAddress(HANDLE hProcess, HANDLE hThread, CHAR * funName)
{
   SYMBOL_INFO *pSymbol;
   pSymbol = (SYMBOL_INFO *)new BYTE[sizeof(SYMBOL_INFO )+MAX_SYM_NAME];
   pSymbol->SizeOfStruct= sizeof(SYMBOL_INFO );
   pSymbol->MaxNameLen = MAX_SYM_NAME;
   SymFromName(hProcess, funName, pSymbol);

   // Store address, before deleting pointer
   DWORD dwAddress = pSymbol->Address;

   delete [](BYTE*)pSymbol; // Valid syntax!

   return dwAddress;
}
