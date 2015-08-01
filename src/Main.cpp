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

#include "output.h"
#include "Utils.h"
#include "Debugger.h"
#include "Main.h"
#include "interactive.h"

#define CMPSTR(X,Y) CompareStringOrdinal(##X##, -1, ##Y##, -1, TRUE) == CSTR_EQUAL

BOOL OptionInteractive = FALSE;

void ParseCommandLine(int argc, wchar_t ** argv, bool* pfExitProgram)
{
	*pfExitProgram = FALSE;

	int i = 0;

	if (argc <= 1)
	{
		*pfExitProgram = TRUE;
		goto Exit;
	}

	for (i = 1; i < argc; i++)
	{
		if (CMPSTR(argv[i], L"-?"))
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
		else if (CMPSTR(argv[i], L"-a"))
		{
			i++;
			gAnalysisLevel = _wtoi(argv[i]);
		}
		else if (CMPSTR(argv[i], L"-debugbreak"))
		{
			*pfExitProgram = true;
			Write(WriteLevel::Output, L"About to call DebugBreak");
			DebugBreak();

		}
	}

	// The last argument is the command line to trace
	gpCommandLine = (argv[argc-1]);

Exit:
	return;
}

void WtraceUsage(void)
{
	printf("wtrace [options] cmd\n");
	printf("\t-?           show help\n");
	printf("\t-o <file>    output all debugging information to <file>\n");
	printf("\t-v <string>  set logging verbosity, can be: debug, info, output\n");
	printf("\t-a <int>     Analysis depth, can be: 1 for processes, 2 for io calls, 3 for function level (if symbols are available)\n");
}

void Logo(void)
{
	// @TODO put date here
	//http://stackoverflow.com/questions/997946/how-to-get-current-time-and-date-in-c
	printf("trace 0.1\n(c) 2015 Alan Gonzalez\n\n");
}

// type is void (__cdecl *)(void)
void foobar()
{
	
}

int wmain(int argc, wchar_t ** argv)
{
	Logo();

	gAnalysisLevel = 0;
	bool fExitProgram = FALSE;
	DebugEngine engine;
	InteractiveCommandLine interactive;

	// Alters state by modifying global variables
	ParseCommandLine(argc, argv, &fExitProgram);

	if (fExitProgram)
	{
		goto Exit;
	}

	if (OptionInteractive)
	{
		// This will cause the engine to call on this
		// function everytime something happens
		engine.AddInteractiveSession(&interactive);
	}

	HRESULT hr = engine.Run();

	printf("Finished. Overall result=0x%08x", hr);

Exit:
	if (gFp)
		fclose(gFp);

	return 0;
}

