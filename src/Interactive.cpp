/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

#include <iostream>
#include <string>
#include <windows.h>

#include "DebugEventCallback.h"
#include "interactive.h"
#include "output.h"
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

InteractiveCommandLine::InteractiveCommandLine(DebugEngine * engine)
{
	m_DebugEngine = engine;
}

HRESULT InteractiveCommandLine::DebugEvent(const DEBUG_EVENT& event)
{
	ENTER_FN

	bool bLetGo = false;
	do {

		std::map<std::string, DWORD64> mapRegisters;
		m_DebugEngine->GetRegisters(&mapRegisters);

#ifdef _X86_
		std::cout << "eip=0x" << std::hex << mapRegisters.at("eip") << std::endl;
#else
		std::cout << "rip=0x" << std::hex << mapRegisters.at("rip") << std::endl;
#endif

		std::cout << "input>";

		std::cin >> m_sCurrentCmd;
		Dispatch(&bLetGo);

	} while(!bLetGo);

	EXIT_FN
}

HRESULT InteractiveCommandLine::Dispatch(bool* bLetGo)
{
	ENTER_FN

	if (m_sCurrentCmd.empty())
	{
		goto Exit;
	}

	if (m_sCurrentCmd.compare("q") == 0)
	{
		*bLetGo = false;
		goto Exit;
	}
	else if (m_sCurrentCmd.compare("kn") == 0)
	{
		hr = m_DebugEngine->GetCurrentCallstack();
		*bLetGo = false;
		goto Exit;
	}
	else if (m_sCurrentCmd.compare("p") == 0)
	{
		//hr = m_DebugEngine->StepOver();
		*bLetGo = true;
		goto Exit;
	}
	else if (m_sCurrentCmd.compare("t") == 0)
	{
		hr = m_DebugEngine->SetSingleStepFlag();
		*bLetGo = true;
		goto Exit;
	}
	else if (m_sCurrentCmd.compare("g") == 0)
	{
		*bLetGo = true;
		goto Exit;
	}
	else
	{
		std::cout << "Unknown command." << std::endl;;
		*bLetGo = false;
		goto Exit;
	}

	EXIT_FN
}

