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

#define STACKWALK_MAX_NAMELEN 1024

extern bool bSyminitialized;

HRESULT DumpWowContext(const WOW64_CONTEXT& lcContext)
{
	ENTER_FN

	Write(WriteLevel::Debug,  L"eax=%08X ebx=%08X ecx=%08X edx=%08X esi=%08X edi=%08X",
			lcContext.Eax, lcContext.Ebx, lcContext.Ecx,
			lcContext.Edx, lcContext.Esi, lcContext.Edi);

	Write(WriteLevel::Debug,  L"eip=%08X esp=%08X ebp=%08X",
			lcContext.Eip, lcContext.Esp, lcContext.Ebp);

	Write(WriteLevel::Debug, L"eflags = %08X",
			lcContext.EFlags);

	EXIT_FN
}

HRESULT RetrieveWoWCallstack(HANDLE hThread, HANDLE hProcess, const WOW64_CONTEXT& context, int nFramesToRead, std::string* sFuntionName, DWORD * ip)
{
	ENTER_FN

	STACKFRAME64 stack = {0};
	IMAGEHLP_SYMBOL64 *pSym = NULL;
	//CallstackEntry csEntry;

	if (hThread == INVALID_HANDLE_VALUE
			|| hProcess == INVALID_HANDLE_VALUE)
	{
		Write(WriteLevel::Error, L"Handles are invalid");
		goto Exit;
	}

	// We can assume X86 registers
	stack.AddrPC.Offset = context.Eip;    // EIP - Instruction Pointer
	stack.AddrFrame.Offset = context.Ebp; // EBP
	stack.AddrStack.Offset = context.Esp; // ESP - Stack Pointer

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

	for (int frameNum = 0; (nFramesToRead==0) || (frameNum < nFramesToRead); ++frameNum)
	{
		Write(WriteLevel::Debug, L"About to walk the stack hProcess=0x%x hThread=0x%x", hProcess, hThread);

		//
		// StackWalk64 only needs context when image is not IMAGE_FILE_MACHINE_I386, the 
		// context might be modified.
		//
		BOOL bResult = StackWalk64(
				IMAGE_FILE_MACHINE_I386,
				hProcess,
				hThread,
				&stack,
				NULL,// (PVOID)(&context), // Only needed when MachineType  != IMAGE_FILE_MACHINE_I386
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

		DWORD64 offsetFromSmybol;
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
										&offsetFromSmybol,
										pSym) != FALSE)
			{
				// Undecorate names:
				// UnDecorateSymbolName(pSym->Name, csEntry.undName, STACKWALK_MAX_NAMELEN, UNDNAME_NAME_ONLY );
				// UnDecorateSymbolName(pSym->Name, csEntry.undFullName, STACKWALK_MAX_NAMELEN, UNDNAME_COMPLETE );
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

HRESULT Wow64SingleStep(HANDLE hProcess, HANDLE hThread)
{
	ENTER_FN

	Write(WriteLevel::Debug, L"Wow64SingleStep");

	WOW64_CONTEXT lcWowContext = {0};
	BOOL bResult = FALSE;

	if (gAnalysisLevel >= 3)
	{
		lcWowContext.ContextFlags = WOW64_CONTEXT_CONTROL;

		bResult = Wow64GetThreadContext(hThread, &lcWowContext);
		if (!bResult)
		{
			hr =  HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"Wow64GetThreadContext failed 0x%x", hr);
			goto Exit;
		}

		hr = DumpWowContext(lcWowContext);

		Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");
		lcWowContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception

		if (0 == Wow64SetThreadContext(hThread, &lcWowContext))
		{
			hr =  HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"Wow64SetThreadContext failed with 0x%x.", hr);
			goto Exit;
		}

		std::string sFuntionName;
		std::wstring wsFuctionName;
		DWORD instructionPointer;
		hr = RetrieveWoWCallstack(hThread, hProcess, lcWowContext, 1 /* 1 frame */, &sFuntionName, &instructionPointer);

		//Write(WriteLevel::Debug, L"GetCurrentFunctionName result 0x%x", hr);
		//if (FAILED(hr))
		//{
		//	Write(WriteLevel::Error, L"GetCurrentFunctionName failed 0x%x", hr);
		//	goto Exit;
		//}

		//wsFuctionName.assign(sFuntionName.begin(), sFuntionName.end());
		//Write(WriteLevel::Info, L"0x%08x %s", (DWORD)instructionPointer, wsFuctionName.c_str());

	}

	EXIT_FN
}

HRESULT Wow64Breakpoint(HANDLE hProcess, HANDLE hThread)
{
	ENTER_FN

	Write(WriteLevel::Info, L"WOW64 breakpoint");

	WOW64_CONTEXT lcWowContext = {0};
	BOOL bResult = FALSE;

	if (gAnalysisLevel >= 3)
	{
		lcWowContext.ContextFlags = WOW64_CONTEXT_CONTROL;

		bResult = Wow64GetThreadContext(hThread, &lcWowContext);
		if (!bResult)
		{
			hr =  HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"Wow64GetThreadContext failed 0x%x", hr);
			goto Exit;
		}

		hr = DumpWowContext(lcWowContext);

		Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");
		lcWowContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception

		if (0 == Wow64SetThreadContext(hThread, &lcWowContext))
		{
			hr =  HRESULT_FROM_WIN32(GetLastError());
			Write(WriteLevel::Error, L"Wow64SetThreadContext failed with 0x%x.", hr);
			goto Exit;
		}
//
//
//		std::string sFuntionName;
//		std::wstring wsFuctionName;
//		DWORD64 instructionPointer;
//		hr = RetrieveWoWCallstack(hThread, hProcess, lcWowContext, 2 /* 1 frame */, &sFuntionName, &instructionPointer);
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

	EXIT_FN
}

