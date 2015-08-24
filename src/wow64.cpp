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
#include <list>

#include "output.h"
#include "Utils.h"
#include "Main.h"

// Debugging engines
#include "DebugEngine.h"
#include "NativeDebugEngine.h"
#include "wow64.h"

#define STACKWALK_MAX_NAMELEN 1024

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



HRESULT WowDebugEngine::Wow64Breakpoint(HANDLE hProcess, HANDLE hThread)
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

		if (gbFirst)
		{
			gbFirst = FALSE;
			/////////////////////////////////////////////////////////////////
			// If this is our first time hitting WoW64 BreakPoint, set a BP
			// at the start address 
			//
			// Read the first instruction and save it
			BYTE cInstruction;
			SIZE_T lpNumberOfBytesRead;
			int result = ReadProcessMemory(
					hProcess,
					(void*)m_dw64StartAddress,
					&cInstruction,
					1,
					&lpNumberOfBytesRead);

			if (result == 0)
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
				Write(WriteLevel::Error, L"ReadProcessMemory failed to read 0x%p hr=0x%x", m_dw64StartAddress, hr);
				goto Exit;
			}
			if (cInstruction != 0xCC)
			{
				Write(WriteLevel::Debug, L"Replacing first instruction '%x' at 0x%08x with 0xCC", cInstruction, m_dw64StartAddress);

				m_OriginalInstruction = cInstruction;

				// Replace it with Breakpoint
				cInstruction = 0xCC;

				WriteProcessMemory(hProcess, (void*)m_dw64StartAddress, &cInstruction, 1, &lpNumberOfBytesRead);

				FlushInstructionCache(hProcess, (void*)m_dw64StartAddress, 1);
			}
		}
		else
		{
			/////////////////////////////////////////////////////////////////
			// IF we are hitting a BP i set, restore the instruction
			//
			if (m_OriginalInstruction != 0)
			{
				Write(WriteLevel::Debug, L"Writing back original instruction ");

				SIZE_T lNumberOfBytesRead;

				lcWowContext.Eip--;
				DWORD dwStartAddress;
				dwStartAddress = lcWowContext.Eip;
				WriteProcessMemory(hProcess, (LPVOID)dwStartAddress, &m_OriginalInstruction, 1, &lNumberOfBytesRead);
				FlushInstructionCache(hProcess, (LPVOID)dwStartAddress, 1);

				m_OriginalInstruction = 0;

				Write(WriteLevel::Debug, L"Set trap flag, which raises single-step exception");
				lcWowContext.EFlags |= 0x100;

				if (0 == Wow64SetThreadContext(hThread, &lcWowContext))
				{
					hr =  HRESULT_FROM_WIN32(GetLastError());
					Write(WriteLevel::Error, L"Wow64SetThreadContext failed with 0x%x.", hr);
					goto Exit;
				}
			}
		}

	}

	EXIT_FN
}

HRESULT WowDebugEngine::Wow64SingleStep(HANDLE hProcess, HANDLE hThread)
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

		if (FAILED(hr))
		{
			Write(WriteLevel::Error, L"GetCurrentFunctionName failed 0x%x", hr);
			goto Exit;
		}

		wsFuctionName.assign(sFuntionName.begin(), sFuntionName.end());

		Write(WriteLevel::Info, L"0x%08x thread=%x  %s", 
				instructionPointer,
				hThread,
				wsFuctionName.c_str());

	}

	EXIT_FN
}

HRESULT WowDebugEngine::RetrieveWoWCallstack(HANDLE hThread, HANDLE hProcess, const WOW64_CONTEXT& context, int nFramesToRead, std::string* sFuntionName, DWORD * ip)
{
	ENTER_FN

	STACKFRAME64 stack = {0};
	IMAGEHLP_SYMBOL64 *pSym = NULL;
	std::string sModuleName;
	bool bModuleFound = FALSE;
	std::map<std::string, IMAGEHLP_MODULE64>::iterator it;


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

	// C4244: Possible loss of precision
	*ip = (DWORD)stack.AddrPC.Offset;

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

			Write(WriteLevel::Debug, L"SymGetModuleInfo64 ok ataddress %p",
					(DWORD64)stack.AddrPC.Offset);
		}
	}

	for (int frameNum = 0; (nFramesToRead ==0) || (frameNum < nFramesToRead); ++frameNum)
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
				NULL,// (PVOID)(&context), 
				// Only needed when MachineType  != IMAGE_FILE_MACHINE_I386
				NULL,
				SymFunctionTableAccess64,
				SymGetModuleBase64,
				NULL);

		if (FALSE == bResult)
		{
			// StackWalk64 does not set "GetLastError"...
			//hr = HRESULT_FROM_WIN32(GetLastError());
			//Write(WriteLevel::Error, L"StackWalk64 failed, the following hr must not be trusted: hr=%x", hr);
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
					*sFuntionName = sModuleName;
					*sFuntionName += "!";
					*sFuntionName += pSym->Name;
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

Cleanup:
	if (pSym)
	{
		delete pSym;
	}

	EXIT_FN
}
