
/* ********************************************************** 
 *
 * wtrace
 * 2014 - Alan Gonzalez
 *
 * ********************************************************** */
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
	STARTUPINFOA si;
	bool firstDebugEvent = 1;

	dwStartAddress = 0;
	processName = new WCHAR[MAX_PATH];

	// Ref count of processes created
	nSpawnedProcess = 0;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	// gpCommandLine is char*, Write() needs wchar_t*
	wchar_t *pwstrCommandLine;
	pwstrCommandLine = charToWChar(gpCommandLine);
	Write(WriteLevel::Debug, L"Creating process %s", pwstrCommandLine);

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

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
#if 0
							//x86
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

	Write(WriteLevel::Debug, L"Finished.");
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

	if ( DebugString.fUnicode )
	{
		Write(WriteLevel::Output, L"OUTPUT_DEBUG_STRING_EVENT: %s", msg);
	}
	else
	{
		wchar_t *pwstrDebugMessage;
		pwstrDebugMessage = charToWChar(gpCommandLine);
		Write(WriteLevel::Output, L"OUTPUT_DEBUG_STRING_EVENT: %s", pwstrDebugMessage);
	
	}

	delete []msg;
}

void LoadDllDebugEvent(const DEBUG_EVENT& de)
{
	// Read the debugging information included in the newly loaded DLL.
	TCHAR pszFilename[MAX_PATH+1];
	GetFileNameFromHandle(de.u.LoadDll.hFile, (TCHAR *)&pszFilename);

	wchar_t *pwstrDllName;
	pwstrDllName = charToWChar(pszFilename);
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
		printf("symbols loaded...\n");
	}
	else
	{
		printf("no symbols ...\n");
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
		RetrieveCallstack(de.u.CreateProcessInfo.hThread);
	}
	else
	{
		printf("No symbols ...\n");
	}

	BYTE cInstruction;
	SIZE_T dwReadBytes;

	// Read the first instruction
	ReadProcessMemory(pi.hProcess, (void*)dwStartAddress, &cInstruction, 1, &dwReadBytes);


	Write(WriteLevel::Debug, L"	replacing %x with BP", cInstruction);
	// Save it!

	if (cInstruction != 0xCC) {
		m_OriginalInstruction = cInstruction;
		// Replace it with Breakpoint
		cInstruction = 0xCC;
		WriteProcessMemory(pi.hProcess, (void*)dwStartAddress,&cInstruction, 1, &dwReadBytes);
		FlushInstructionCache(pi.hProcess,(void*)dwStartAddress,1);
	}
}

void RetrieveCallstack(HANDLE hThread)
{
	// Initialize 'stack' with some required stuff.
	STACKFRAME64 stack={0};

	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;

	GetThreadContext(hThread, &context);

#if X86
	stack.AddrPC.Offset = context.Eip; // EIP - Instruction Pointer
	stack.AddrFrame.Offset = context.Ebp; // EBP
	stack.AddrStack.Offset = context.Esp; // ESP - Stack Pointer
#else
	stack.AddrPC.Offset = context.Rip; // EIP - Instruction Pointer
#endif

	// Must be like this
	stack.AddrPC.Mode = AddrModeFlat;
	stack.AddrFrame.Mode = AddrModeFlat;
	stack.AddrStack.Mode = AddrModeFlat;

//	StackWalk64(
//			IMAGE_FILE_MACHINE_I386,
//			pi.hProcess,
//			hThread,
//			&stack,
//			&context,
//			_ProcessMemoryReader,
//			SymFunctionTableAccess64,
//			SymGetModuleBase64,
//			0);
}
