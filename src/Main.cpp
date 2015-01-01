
/* ********************************************************** 
 *
 * wtrace
 * 2014 - Alan Gonzalez
 *
 * ********************************************************** */
#include <windows.h>
#include <stdio.h>
#include <string>
#include <WinBase.h>
#include <Winternl.h>

#include "output.h"
#include "Utils.h"
#include "Debugger.h"
#include "Main.h"

void ParseCommandLine(int argc, char ** argv)
{
	int i = 0;
	for (i = 0; i < (argc-1); i++)
	{
		if (strcmp(argv[i], "-?") == 0)
		{
			Usage();
		}
		else if (strcmp(argv[i], "-o") == 0)
		{
			i++;

			gOutputFile = (WCHAR*)malloc(sizeof(WCHAR)*strlen(argv[i]));
			mbstowcs(gOutputFile, argv[i], strlen(argv[i]));

			Write(WriteLevel::Debug, L"Set output file to %s.", gOutputFile);

			gFp = fopen(argv[i], "w");

			if (!gFp)
			{
				Write(WriteLevel::Output, L"Unable to open %s for writing.", gOutputFile);
			}
		}
		else if (strcmp(argv[i], "-v") == 0)
		{
			i++;
			if (strcmp(argv[i], "info") == 0)
			{
				gWriteLevelThreshold = WriteLevel::Info;
			}
			else if (strcmp(argv[i], "debug") == 0)
			{
				gWriteLevelThreshold = WriteLevel::Debug;
			}
		}
		else if (strcmp(argv[i], "-a") == 0)
		{
			i++;
			gAnalysisLevel = atoi(argv[i]);
		}
	}

	// The last argument is the command line to trace
	gpCommandLine = (argv[i]);
	
}

void Usage(void)
{
	printf("trace [options] cmd\n");
	printf("\t-?           show help\n");
	printf("\t-o <file>    output all debugging information to <file>\n");
	printf("\t-v <string>  set logging verbosity, can be: debug, info, output\n");
	printf("\t-a <int>     Analysis depth, can be: 1 for processes, 2 for io calls, 3 for function level (if symbols are available)\n");
}

void Logo(void)
{
	printf("trace 0.1\n(c) 2014 Alan Gonzalez\n\n");
}

int main(int argc, char ** argv)
{

	Logo();

	gAnalysisLevel = 0;

	// Alters state by modifying global variables
	ParseCommandLine(argc, argv);

	Run();

	if (gFp)
		fclose(gFp);

	return 0;
}

