/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

#include <iostream>
#include <string>
#include <list>
#include <map>

#include <windows.h>

#include "DebugEventCallback.h"
#include "interactive.h"
#include "output.h"
#include "Utils.h"
#include "DebugEngine.h"
#include "wow64.h"

InteractiveCommandLine::InteractiveCommandLine(DebugEngine * engine)
{
	m_DebugEngine = engine;
}

void InteractiveCommandLine::SetCommandToExecute(const std::wstring& wsCommand)
{
	m_wsCommandToExecute = wsCommand;
}

HRESULT InteractiveCommandLine::DebugEvent(const DEBUG_EVENT& event)
{
	ENTER_FN

	bool bLetGo = false;
	std::map<std::string, DWORD64> mapRegisters;
	WCHAR pszFilename[MAX_PATH+1];
	BOOL bSuccess = FALSE;

	switch (event.dwDebugEventCode)
	{
		case EXCEPTION_DEBUG_EVENT:
			switch (event.u.Exception.ExceptionRecord.ExceptionCode)
			{
				//////////////////////////////////////////////
				//			NATIVE EXCEPTIONS
				//////////////////////////////////////////////
				case EXCEPTION_ACCESS_VIOLATION:
				break;

				case EXCEPTION_BREAKPOINT:
					Write(WriteLevel::Info, L"EXCEPTION_BREAKPOINT");
				break;

				case EXCEPTION_DATATYPE_MISALIGNMENT: 
				break;

				case EXCEPTION_SINGLE_STEP:
				break;

				case DBG_CONTROL_C:
				break;

				case 0xc000001d:
				break;

				//////////////////////////////////////////////
				//				WOW Exceptions
				//////////////////////////////////////////////
				case STATUS_WX86_BREAKPOINT:
				break;

				case STATUS_WX86_SINGLE_STEP:
				break;

				case STATUS_WX86_UNSIMULATE:
				break;

				case STATUS_WX86_CONTINUE:
				break;

				case STATUS_WX86_EXCEPTION_CONTINUE:
				break;

				case STATUS_WX86_EXCEPTION_LASTCHANCE:
				break;

				case STATUS_WX86_EXCEPTION_CHAIN:
				break;

				default:
				break;
			}

			break;

		default:
			break;

		 case CREATE_THREAD_DEBUG_EVENT: 
				Write(WriteLevel::Info, L"CREATE_THREAD_DEBUG_EVENT");
				bLetGo = true;
			break;

		 case CREATE_PROCESS_DEBUG_EVENT: 
				Write(WriteLevel::Info, L"CREATE_PROCESS_DEBUG_EVENT");
				bLetGo = true;
			break;

		 case EXIT_THREAD_DEBUG_EVENT: 
			break;

		 case EXIT_PROCESS_DEBUG_EVENT: 
			break;

		 case LOAD_DLL_DEBUG_EVENT:

				bSuccess = GetFileNameFromHandle(event.u.LoadDll.hFile, (WCHAR *)&pszFilename);
				if (!bSuccess)
				{
					Write(WriteLevel::Error, L"GetFileNameFromHandle failed ");
					goto Exit;
				}

				Write(WriteLevel::Info, L" %p \t (%sdebug info) \t %s",
						event.u.LoadDll.lpBaseOfDll,
						event.u.LoadDll.nDebugInfoSize == 0 ? L"no " : L"",
						pszFilename);

				bLetGo = true;
			break;

		 case UNLOAD_DLL_DEBUG_EVENT: 
			break;

		 case OUTPUT_DEBUG_STRING_EVENT: 
			break;

		 case RIP_EVENT:
			break;
	}

	if (bLetGo)
	{
		goto Exit;
	}

	do {
		m_DebugEngine->GetRegisters(&mapRegisters);

#ifdef _X86_
		std::cout << "eip=0x" << std::hex << mapRegisters.at("eip") << std::endl;
#else
		std::cout << "rip=0x" << std::hex << mapRegisters.at("rip") << std::endl;
#endif


		if (m_wsCommandToExecute.empty())
		{
			std::cout << "input>";
			std::cin >> m_sCurrentCmd;
		}
		else
		{
			std::cout << "auto>";

			std::string str(m_wsCommandToExecute.begin(), m_wsCommandToExecute.end() );

			// @TODO if ";" exists, then put the first part into currentCmd
			// and leave the rest in the buffer.
			std::size_t found = str.find(";");
			if (found != std::string::npos)
			{
				m_sCurrentCmd = str.substr(0, found);
				m_wsCommandToExecute = m_wsCommandToExecute.substr(found+1);
			}
			else
			{
				m_sCurrentCmd = str;
				m_wsCommandToExecute.clear();
			}

			std::cout << m_sCurrentCmd << std::endl;
		}

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
		std::list<std::string> stack;
		hr = m_DebugEngine->GetCurrentCallstack(&stack);

		int n = 0;
		for (auto it = stack.begin(); it != stack.end(); it++)
		{
			std::cout << n++ << " " << *it << std::endl;
		}

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

