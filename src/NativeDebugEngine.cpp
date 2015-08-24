/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

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

#include "DebugEventCallback.h"
#include "interactive.h"


HRESULT NativeDebugEngine::DumpContext(const CONTEXT& lcContext)
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


