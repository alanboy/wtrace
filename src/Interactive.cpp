/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

#include <iostream>
#include <string>
#include <windows.h>

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

HRESULT InteractiveCommandLine::DebugEvent()
{
	ENTER_FN

	std::cout << "input>";
	std::cin >> m_sCurrentCmd;

	Dispatch();

	EXIT_FN
}

HRESULT InteractiveCommandLine::Dispatch()
{
	ENTER_FN

	if (m_sCurrentCmd.empty())
	{
		goto Exit;
	}

	if (m_sCurrentCmd.compare("q") == 0)
	{
		goto Exit;
	}
	else if (m_sCurrentCmd.compare("kn") == 0)
	{
		hr = m_DebugEngine->GetCurrentCallstack();
		goto Exit;
	}

	EXIT_FN
}

