/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

#include <iostream>
#include <string>
#include <list>
#include <windows.h>

#include "DebugEventCallback.h"
#include "Tracer.h"
#include "output.h"

#include "ArchitectureSpecificInterface.h"
#include "DebugEngine.h"
#include "wow64.h"

TracerPlugin::TracerPlugin(DebugEngine * engine)
{
	m_DebugEngine = engine;
}

HRESULT TracerPlugin::DebugEvent(const DEBUG_EVENT& event)
{
	ENTER_FN;

	std::map<std::string, DWORD64> mapRegisters;

	switch (event.dwDebugEventCode)
	{
		case EXCEPTION_DEBUG_EVENT:
			switch (event.u.Exception.ExceptionRecord.ExceptionCode)
			{
				//////////////////////////////////////////////
				//			NATIVE EXCEPTIONS
				//////////////////////////////////////////////
				case EXCEPTION_ACCESS_VIOLATION:
					std::cout << "EXCEPTION_ACCESS_VIOLATION" << std::endl;
				break;

				case EXCEPTION_BREAKPOINT:
					std::cout << "EXCEPTION_BREAKPOINT" << std::endl;
					hr = m_DebugEngine->SetSingleStepFlag();
				break;

				case EXCEPTION_DATATYPE_MISALIGNMENT: 
					std::cout << "EXCEPTION_DATATYPE_MISALIGNMENT" << std::endl;
				break;

				case EXCEPTION_SINGLE_STEP:
					//std::cout << "EXCEPTION_SINGLE_STEP" << std::endl;
					hr = m_DebugEngine->SetSingleStepFlag();

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
					std::cout << "CREATE_THREAD_DEBUG_EVENT" << std::endl;
			break;

		 case CREATE_PROCESS_DEBUG_EVENT: 
					std::cout << "CREATE_PROCESS_DEBUG_EVENT" << std::endl;
			break;

		 case EXIT_THREAD_DEBUG_EVENT: 
					std::cout << "EXIT_THREAD_DEBUG_EVENT" << std::endl;
			break;

		 case EXIT_PROCESS_DEBUG_EVENT: 
					std::cout << "EXIT_PROCESS_DEBUG_EVENT" << std::endl;
			break;

		 case LOAD_DLL_DEBUG_EVENT: 
					std::cout << "LOAD_DLL_DEBUG_EVENT" << std::endl;
			break;

		 case UNLOAD_DLL_DEBUG_EVENT: 
					std::cout << "UNLOAD_DLL_DEBUG_EVENT" << std::endl;
			break;

		 case OUTPUT_DEBUG_STRING_EVENT: 
					std::cout << "OUTPUT_DEBUG_STRING_EVENT" << std::endl;
			break;

		 case RIP_EVENT:
			break;
	}

	if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
			&& event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		m_DebugEngine->GetRegisters(&mapRegisters);

		std::list<std::string> mapStack;
		hr = m_DebugEngine->GetCurrentCallstack(&mapStack);

		auto it = mapStack.front();

		if (it.compare(strLastFunction) != 0)
		{
			strLastFunction = it;

#ifdef _X86_
			std::cout << "eip=0x" << std::hex << mapRegisters.at("eip") << " ";
			std::cout << "esp=0x" << std::hex << mapRegisters.at("esp") << " ";
#else
			std::cout << "rip=0x" << std::hex << mapRegisters.at("rip") << " ";
			std::cout << "rsp=0x" << std::hex << mapRegisters.at("rsp") << " ";
#endif

			std::cout << "tid=0x" << std::hex << event.dwThreadId << " ";


			for (auto it = mapStack.begin(); it != mapStack.end(); it++)
			{
				std::cout << "  ";
			}

			std::cout << mapStack.back() << "()";
			std::cout  << std::endl;

			//		hr = m_DebugEngine->SetSingleStepFlag();
		}

	}

	EXIT_FN;
}

