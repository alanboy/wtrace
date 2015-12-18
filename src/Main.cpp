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
#include <Strsafe.h>
#include <fstream> //for html

#include "output.h"
#include "Utils.h"
#include "Main.h"

#include "DebugEngine.h"
#include "DebugEventCallback.h"

#include "plugins\html.h"
#include "plugins\interactive.h"
#include "plugins\Tracer.h"

BOOL OptionInteractive = FALSE;
BOOL OptionHtml = FALSE;
BOOL OptionFunctionLevel = FALSE;
wchar_t *gpCommandToInteractive;

void ParseCommandLine(int argc, wchar_t ** argv, bool* pfExitProgram)
{
	ENTER_FN;

	*pfExitProgram = FALSE;

	int i = 0;

	if (argc <= 1)
	{
		*pfExitProgram = TRUE;
		goto Exit;
	}

	for (i = 1; i < argc; i++)
	{
		if (CMPSTR(argv[i], L"-?") || CMPSTR(argv[i], L"/?"))
		{
			WtraceUsage();
			*pfExitProgram = TRUE;
		}
		else if (CMPSTR(argv[i], L"-o"))
		{
			i++;

			gOutputFile = (WCHAR*)malloc(sizeof(WCHAR)*wcslen(argv[i]));
			StringCchCopy(gOutputFile, sizeof(WCHAR)*wcslen(argv[i]), argv[i]);

			Write(WriteLevel::Debug, L"Set output file to %s.", gOutputFile);

			_wfopen_s(&gFp, argv[i], L"w");

			if (!gFp)
			{
				Write(WriteLevel::Output, L"Unable to open %s for writing.", gOutputFile);
			}
		}
		else if (CMPSTR(argv[i], L"-v"))
		{
			i++;
			if (CMPSTR(argv[i], L"info"))
			{
				gWriteLevelThreshold = WriteLevel::Info;
			}
			else if (CMPSTR(argv[i], L"debug"))
			{
				gWriteLevelThreshold = WriteLevel::Debug;
			}
		}
		else if (CMPSTR(argv[i], L"-i"))
		{
			OptionInteractive = TRUE;
		}
		else if (CMPSTR(argv[i], L"-c"))
		{
			// -c option, must be used with -i
			OptionInteractive = TRUE;

			i++;
			gpCommandToInteractive = (WCHAR*)malloc(sizeof(WCHAR)*wcslen(argv[i]));
			StringCchCopy(gpCommandToInteractive, sizeof(WCHAR)*wcslen(argv[i]), argv[i]);
		}
		else if (CMPSTR(argv[i], L"-html"))
		{
			OptionHtml = TRUE;
		}
		else if (CMPSTR(argv[i], L"-a"))
		{
			i++;
			gAnalysisLevel = _wtoi(argv[i]);
		}
		else if (CMPSTR(argv[i], L"-f"))
		{
			OptionFunctionLevel = TRUE;
		}
		else if (CMPSTR(argv[i], L"-debugbreak"))
		{
			*pfExitProgram = true;
			Write(WriteLevel::Output, L"About to call DebugBreak");
			DebugBreak();
		}
		else if (CMPSTR(argv[i], L"-createprocess"))
		{
			// Launch another process
			*pfExitProgram = true;
		}
		else if (CMPSTR(argv[i], L"-debugoutput"))
		{
			Write(WriteLevel::Output, L"About to send text to debugger using OutputDebugString");
			OutputDebugString(L"Some Text Sent Via OutputDebugString() \r\n");
			*pfExitProgram = true;
		}
	}

	// The last argument is the command line to trace
	gpCommandLine = (argv[argc-1]);

	EXIT_FN_NO_RET;
}

void WtraceUsage(void)
{
	printf("wtrace [options] <cmd>\n");
	printf("\t-?           show help\n");
	printf("\t-o <file>    output all debugging information to <file>\n");
	printf("\t-v <string>  set logging verbosity: debug, info or output\n");
	printf("\t-a <int>     Analysis depth, can be: 1 for processes, 2 for io calls, 3 for function level (if symbols are available)\n");

	printf("\n\n Plugins:\n");
	printf("\t-f  Function level tracing.\n");
	printf("\t-html  Html output.\n");
	printf("\t-i  Interactive. You can pass commands to interactive mode using \"-c\" .\n");
	printf("\t\t\tIn interative mode you can use the following commands:\n");
	printf("\t\t\t\tg\n");
	printf("\t\t\t\tkn\n");
	printf("\t\t\t\tq\n");
	
	printf("\n\n Debugging:\n");
	printf("\t-debugbreak\n");
	printf("\t-createprocess  \n");
	printf("\t-debugoutput \n");
	
}

void Logo(void)
{
	// @TODO put date here
	//http://stackoverflow.com/questions/997946/how-to-get-current-time-and-date-in-c
	printf("trace 0.0.0.2\n(c) 2013-2015 Alan Gonzalez\n\n");
}

int wmain(int argc, wchar_t ** argv)
{
	ENTER_FN;

	Logo();
	
	gAnalysisLevel = 0;
	bool fExitProgram = FALSE;

	DebugEngine engine;
	InteractiveCommandLine interactive(&engine);
	HtmlOutput* htmlOutput = NULL;
	TracerPlugin* tracerPlugin = NULL;

	// Alters state by modifying global variables
	ParseCommandLine(argc, argv, &fExitProgram);

	if (fExitProgram)
		goto Cleanup;

	// Add callbacks, this will cause to call the DebugEvent method
	// on the passed object on each debug event.
	if (OptionInteractive)
	{
		if (gpCommandToInteractive)
		{
			std::wstring foo(gpCommandToInteractive);
			interactive.SetCommandToExecute(foo);
		}

		engine.AddCallback(&interactive);
	}
	else if (OptionHtml)
	{
		htmlOutput = new HtmlOutput(&engine, L"out.html");
		engine.AddCallback(htmlOutput);
	}
	else if (OptionFunctionLevel)
	{
		tracerPlugin = new TracerPlugin(&engine);
		engine.AddCallback(tracerPlugin);
	}

	engine.SetCommandLine(gpCommandLine);

	hr = engine.Run();

	printf("Finished. Overall result=0x%08x", hr);

Cleanup:
	if (gFp)
		fclose(gFp);

	if (htmlOutput)
		delete htmlOutput;

	EXIT_FN_NO_RET;

	return hr;
}

