
#include <windows.h>
#include <stdio.h>
#include <string>
#include <WinBase.h>
#include <Winternl.h>

#define SUCCESS(x) (x=!0)


enum class WriteLevel
{
	Debug = 0,
	Info,
	Output
};

char * gSzOutputFileName;
wchar_t *gOutputFile;
WriteLevel gWriteLevelThreshold = WriteLevel::Output;
FILE * gFileHandle;
FILE * fp;

void Write(WriteLevel level, const WCHAR * lineFormat, ...)
{
	va_list lineArgs;
	va_start (lineArgs, lineFormat);

	if (level >= gWriteLevelThreshold)
	{
		if (fp == NULL)
		{
			vwprintf(lineFormat, lineArgs);
			printf("\n");
		}
		else
		{
		
			fwprintf(fp, lineFormat, lineArgs );
		}
	}

	va_end (lineArgs);
}

void Usage(void)
{
	printf("trace [options] cmd\n");
	printf("\t-?           show help");
	printf("\t-o <file>    output all debugging information to <file>\n");
	printf("\t-v <string>  set logging verbosity, can be: debug, info, output\n");
}

void Logo(void)
{
	printf("trace 0.1\n(c) 2014 Alan Gonzalez\n\n");
}


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

	fwprintf( fp, L" %s\n", wBufferCopy );

}

void ParseCommandLine(int argc, char ** argv)
{
	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-?") == 0)
		{
			Usage();
		}
		else if (strcmp(argv[i], "-o") == 0)
		{
			i++;

			gOutputFile = (WCHAR*)malloc(sizeof(WCHAR)*strlen(argv[i]));
			mbstowcs(gOutputFile, argv[i], strlen(argv[i]));

			Write(WriteLevel::Debug, L"Set output file to %s.", gOutputFile);

			fp = fopen(argv[i], "w");

			if (!fp)
			{
				Write(WriteLevel::Output, L"Unable to open %s for writing.", gOutputFile);
			}
		}
		else if (strcmp(argv[i], "-v") == 0)
		{
			i++;
			if (strcmp(argv[i], "info"))
			{
				gWriteLevelThreshold = WriteLevel::Info;
			}
			else if (strcmp(argv[i], "debug"))
			{
				gWriteLevelThreshold = WriteLevel::Debug;
			}
		}
	}
}

int main(int argc, char ** argv)
{
	BYTE cInstruction;
	BYTE m_OriginalInstruction;
	CONTEXT lcContext;
	DEBUG_EVENT de = {0};
	DWORD dwReadBytes ;
	DWORD dwWriteSize ;
	HRESULT hr;
	LPVOID dwStartAddress = 0;
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;

	Logo();

	ParseCommandLine(argc, argv);

//	LPTSTR processName = new TCHAR[MAX_PATH];
//	DWORD processNameLen;
//
//	// Ref count of processes created
//	int nSpawnedProcess = 0;
//
//	memset(&si, 0, sizeof(si));
//	memset(&pi, 0, sizeof(pi));
//
//	bool bCreateProcRes;
//	bCreateProcRes = CreateProcess(NULL, argv[2], NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi );
//
//	if (bCreateProcRes)
//	{
//		nSpawnedProcess++;
//
//		int bContinue = TRUE;
//		while (bContinue)
//		{
//			WaitForDebugEvent(&de, INFINITE);
//
//			//Write(WriteLevel::Debug, "dwProcessId = %d", de.dwProcessId);
//			//Write(WriteLevel::Debug, "dwThreadId = %d", de.dwThreadId);
//			//Write(WriteLevel::Debug, "dwDebugEventCode = %d", de.dwDebugEventCode);
//
//			switch (de.dwDebugEventCode)
//			{
//
//				case EXCEPTION_DEBUG_EVENT: 
//
//					Write(WriteLevel::Debug, "EXCEPTION_DEBUG_EVENT");
//					switch (de.u.Exception.ExceptionRecord.ExceptionCode)
//					{ 
//						case EXCEPTION_ACCESS_VIOLATION: 
//						// First chance: Pass this on to the system. 
//						// Last chance: Display an appropriate error. 
//						Write(WriteLevel::Debug, "	EXCEPTION_ACCESS_VIOLATION");
//						break;
//
//						case EXCEPTION_BREAKPOINT: 
//						// First chance: Display the current 
//						// instruction and register values.
//
//						Write(WriteLevel::Debug, "	EXCEPTION_BREAKPOINT");
//
//						dwStartAddress = (LPVOID)de.u.CreateProcessInfo.lpStartAddress;
//						Write(WriteLevel::Debug, "	Start address=%x", dwStartAddress);
//
//						//lcContext.ContextFlags = CONTEXT_ALL;
//						//GetThreadContext(pi.hThread, &lcContext);
//						//lcContext.Eip--;
//						//lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
//						//SetThreadContext(pi.hThread,&lcContext); 
//
//						//WriteProcessMemory(pi.hProcess, StartAddress, &m_OriginalInstruction, 1,&dwWriteSize);
//						//FlushInstructionCache(pi.hProcess, StartAddress, 1);
//
//						//WriteProcessMemory(pi.hProcess, (void*)dwStartAddress, &m_OriginalInstruction, 1, &dwWriteSize);
//						//FlushInstructionCache(pi.hProcess,(void*)dwStartAddress,1);
//
//						break;
//
//						case EXCEPTION_DATATYPE_MISALIGNMENT: 
//						// First chance: Pass this on to the system. 
//						// Last chance: Display an appropriate error. 
//						Write(WriteLevel::Debug, "	EXCEPTION_DATATYPE_MISALIGNMENT");
//						break;
//
//						case EXCEPTION_SINGLE_STEP: 
//						// First chance: Update the display of the 
//						// current instruction and register values. 
//						Write(WriteLevel::Debug, "	EXCEPTION_SINGLE_STEP");
//						break;
// 
//						case DBG_CONTROL_C: 
//						// First chance: Pass this on to the system. 
//						// Last chance: Display an appropriate error. 
//						Write(WriteLevel::Debug, "	DBG_CONTROL_C");
//						break;
//
//						case 0xc000001d:
//						Write(WriteLevel::Debug, "Illegal Instruction  An attempt was made to execute an illegal instruction.");
//						break;
//
//						default:
//						// Handle other exceptions. 
//						Write(WriteLevel::Debug, "    %d ? ", de.u.Exception.ExceptionRecord.ExceptionCode);
//						break;
//					} 
//
//					break;
//
//				default:
//					// Handle other exceptions. 
//					Write(WriteLevel::Debug, "    nothing to do ? ");
//					break;
//
//				 case CREATE_THREAD_DEBUG_EVENT: 
//					// As needed, examine or change the thread's registers 
//					// with the GetThreadContext and SetThreadContext functions; 
//					// and suspend and resume thread execution with the 
//					// SuspendThread and ResumeThread functions. 
//					Write(WriteLevel::Debug, "CREATE_THREAD_DEBUG_EVENT");
//					break;
//
//				 case CREATE_PROCESS_DEBUG_EVENT: 
//					// As needed, examine or change the registers of the
//					// process's initial thread with the GetThreadContext and
//					// SetThreadContext functions; read from and write to the
//					// process's virtual memory with the ReadProcessMemory and
//					// WriteProcessMemory functions; and suspend and resume
//					// thread execution with the SuspendThread and ResumeThread
//					// functions. Be sure to close the handle to the process image
//					// file with CloseHandle.
//					Write(WriteLevel::Debug, "CREATE_PROCESS_DEBUG_EVENT");
//					dwStartAddress = (LPVOID)de.u.CreateProcessInfo.lpStartAddress;
//					Write(WriteLevel::Debug, "\tStart address=0x%x", dwStartAddress);
//
//					nSpawnedProcess++;
//
//					processNameLen = GetFinalPathNameByHandle(
//								de.u.CreateProcessInfo.hFile,//_In_   HANDLE hFile,
//								processName,//_Out_  LPTSTR lpszFilePath,
//								MAX_PATH,//_In_   DWORD cchFilePath,
//								0//_In_   DWORD dwFlags
//								);
//
//					if (processNameLen == 0)
//					{
//						Write(WriteLevel::Debug, "GetFinalPathNameByHandle failed");
//						break;
//					}
//					
//					Write(WriteLevel::Output, "New process name = %s", processName);
//
//
//					GetProcessInfo(de.u.CreateProcessInfo.hProcess);
//#if 0
//					BYTE cInstruction;
//					DWORD dwReadBytes;
//
//					// Read the first instruction    
//					ReadProcessMemory(pi.hProcess, (void*)dwStartAddress, &cInstruction, 1, &dwReadBytes);
//
//					// Save it!
//
//					if (cInstruction != 0xCC) {
//						Write(WriteLevel::Debug, "	replacing with BP");
//						m_OriginalInstruction = cInstruction;
//						// Replace it with Breakpoint
//						cInstruction = 0xCC;
//						//WriteProcessMemory(pi.hProcess, (void*)dwStartAddress,&cInstruction, 1, &dwReadBytes);
//						//FlushInstructionCache(pi.hProcess,(void*)dwStartAddress,1);
//					}
//#endif
//
//					break;
//		 
//				 case EXIT_THREAD_DEBUG_EVENT: 
//				 // Display the thread's exit code. 
//					Write(WriteLevel::Debug, "EXIT_THREAD_DEBUG_EVENT");
//					break;
//		 
//				 case EXIT_PROCESS_DEBUG_EVENT: 
//				 // Display the process's exit code. 
//					nSpawnedProcess--;
//
//					if (nSpawnedProcess == 1)  bContinue = false;
//
//					Write(WriteLevel::Debug, "EXIT_PROCESS_DEBUG_EVENT");
//					break;
//		 
//				 case LOAD_DLL_DEBUG_EVENT: 
//				 // Read the debugging information included in the newly 
//				 // loaded DLL. Be sure to close the handle to the loaded DLL 
//				 // with CloseHandle.
//					Write(WriteLevel::Debug, "LOAD_DLL_DEBUG_EVENT");
//
//					/*CStringA sDLLName;
//				    sDLLName = GetFileNameFromHandle(de.u.LoadDll.hFile);
//
//				    DWORD64 dwBase = SymLoadModule64 (m_cProcessInfo.hProcess, NULL, sDLLName, 0, (DWORD64)de.u.LoadDll.lpBaseOfDll, 0);
//
//				    Write(WriteLevel::Debug, "Loaded DLL '%s' at add	ess %x.", sDLLName, de.u.LoadDll.lpBaseOfDll);  
//					*/
//
//					break;
//		 
//				 case UNLOAD_DLL_DEBUG_EVENT: 
//				 // Display a message that the DLL has been unloaded. 
//					Write(WriteLevel::Debug, "UNLOAD_DLL_DEBUG_EVENT");
//					break;
//		 
//				 case OUTPUT_DEBUG_STRING_EVENT: 
//				 // Display the output debugging string. 
//					Write(WriteLevel::Debug, "OUTPUT_DEBUG_STRING_EVENT");
//					break;
//
//				 case RIP_EVENT:
//					Write(WriteLevel::Debug, "RIP_EVENT");
//					break;
//
//					
//			}
//
//			hr  = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
//
//			if(!SUCCESS(hr))
//			{
//				Write(WriteLevel::Debug, "Error.");
//				break;
//			}
//		}
//
//		CloseHandle(pi.hProcess);
//		CloseHandle(pi.hThread);	
//
//	}
//	else
//	{
//		Write(WriteLevel::Debug, "Unable to create process.");
//	}
//
//	Write(WriteLevel::Debug, "Finished.");
//
//	fclose(fp);

	return 0;
}

