/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */
#include <string>
#include <iostream>
#include <fstream> //for html
#include <map>
#include <list>

#include <windows.h>
#include <Dbghelp.h>

#include "output.h"

#include "DebugEngine.h"
#include "DebugEventCallback.h"

#include "html.h"

HtmlOutput::~HtmlOutput()
{
	ENTER_FN;

	EndOutput();
	myfile.close();

	EXIT_FN_NO_RET;
}

HtmlOutput::HtmlOutput(DebugEngine * engine, std::wstring sOutputFilename)
{
	ENTER_FN;

	m_DebugEngine = engine;
	m_bStarted = false;
	myfile.open("out.html", std::ofstream::trunc);

	StartOutput();

	EXIT_FN_NO_RET;
}

HRESULT HtmlOutput::StartOutput()
{
	ENTER_FN;

	myfile << "<html><body><table border=1>" << std::endl;
	m_bStarted = true;

	EXIT_FN;
}

HRESULT HtmlOutput::EndOutput()
{
	ENTER_FN;

	myfile << "</table></body></html>" << std::endl;

	EXIT_FN;
}

HRESULT HtmlOutput::DebugEvent(const DEBUG_EVENT& event)
{
	ENTER_FN;

	std::map<std::string, DWORD64> mapRegisters;

	m_DebugEngine->GetRegisters(&mapRegisters);
	std::list<std::string> mapStack;

	myfile << "<tr>"  << std::endl;

	switch (event.dwDebugEventCode)
	{
			case EXCEPTION_DEBUG_EVENT:

				switch (event.u.Exception.ExceptionRecord.ExceptionCode)
				{
					//////////////////////////////////////////////
					//			NATIVE EXCEPTIONS
					//////////////////////////////////////////////
					case EXCEPTION_ACCESS_VIOLATION:
						myfile << "<td>EXCEPTION_ACCESS_VIOLATION</td>" << std::endl;
					break;

					case EXCEPTION_BREAKPOINT:
						myfile << "<td>EXCEPTION_ACCESS_VIOLATION</td>" << std::endl;
						hr = m_DebugEngine->SetSingleStepFlag();
					break;

					case EXCEPTION_DATATYPE_MISALIGNMENT: 
						myfile << "<td>EXCEPTION_DATATYPE_MISALIGNMENT</td>" << std::endl;
					break;

					case EXCEPTION_SINGLE_STEP:
						myfile << "<td>EXCEPTION_SINGLE_STEP</td>" << std::endl;
						hr = m_DebugEngine->SetSingleStepFlag();

					break;

					case DBG_CONTROL_C:
					break;

					case 0xc000001d:
					break;

/*					//////////////////////////////////////////////
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

					*/
					default:
					break;

				}

				break;

			default:
				break;

			 case CREATE_THREAD_DEBUG_EVENT: 
						myfile << "<td>CREATE_THREAD_DEBUG_EVENT</td>" << std::endl;
				break;

			 case CREATE_PROCESS_DEBUG_EVENT: 
						myfile << "<td>CREATE_PROCESS_DEBUG_EVENT</td>" << std::endl;
				break;

			 case EXIT_THREAD_DEBUG_EVENT: 
						myfile << "<td>EXIT_THREAD_DEBUG_EVENT</td>" << std::endl;
				break;

			 case EXIT_PROCESS_DEBUG_EVENT: 
						myfile << "<td>EXIT_PROCESS_DEBUG_EVENT</td>" << std::endl;
				break;

			 case LOAD_DLL_DEBUG_EVENT: 
						myfile << "<td>LOAD_DLL_DEBUG_EVENT</td>" << std::endl;
				break;

			 case UNLOAD_DLL_DEBUG_EVENT: 
						myfile << "<td>UNLOAD_DLL_DEBUG_EVENT</td>" << std::endl;
				break;

			 case OUTPUT_DEBUG_STRING_EVENT: 
						myfile << "<td>OUTPUT_DEBUG_STRING_EVENT</td>" << std::endl;
				break;

			 case RIP_EVENT:
				break;
	}


#ifdef _X86_
	myfile << "<td>eip=0x" << std::hex << mapRegisters.at("eip") << "</td>" << std::endl;
#else
	myfile << "<td>rip=0x" << std::hex << mapRegisters.at("rip") << "</td>" << std::endl;
#endif

	myfile << "<td>" << std::endl;
	if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
			&& event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		hr = m_DebugEngine->GetCurrentCallstack(&mapStack, 256);

		if (!FAILED(hr) && !mapStack.empty())
		{
			auto it = mapStack.front();
			myfile << it << std::endl;
	//		hr = m_DebugEngine->SetSingleStepFlag();
		}
	}

	myfile << "</td>" << std::endl;
	myfile << "</tr>" ;


	EXIT_FN;
}

