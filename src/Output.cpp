
/* ********************************************************** 
 *
 * wtrace
 * 2014 - Alan Gonzalez
 *
 * ********************************************************** */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <string>
#include <WinBase.h>
#include <Winternl.h>

#include "Main.h"
#include "output.h"

#include <iostream>
#include <windows.h>

WriteLevel gWriteLevelThreshold = WriteLevel::Output;
FILE * gFp;
int dFunctionDepth = 0;



void Write(WriteLevel level, const WCHAR * lineFormat, ...)
{
	const WORD colors[] =
	{
		0x0C/* red on black */, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F,
		0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6
	};

	HANDLE hstdin  = GetStdHandle( STD_INPUT_HANDLE  );
	HANDLE hstdout = GetStdHandle( STD_OUTPUT_HANDLE );

	va_list lineArgs;
	va_start (lineArgs, lineFormat);

	if (level >= gWriteLevelThreshold)
	{
		if (gFp == NULL)
		{

			CONSOLE_SCREEN_BUFFER_INFO csbi;
			GetConsoleScreenBufferInfo( hstdout, &csbi );

			if (level == WriteLevel::Error)
			{
				SetConsoleTextAttribute( hstdout, colors[ 0 ] );
				printf(" + ");
			}
			else
			{
				printf(">> ");
			}

			int i = dFunctionDepth-1;
			while ((gWriteLevelThreshold == WriteLevel::Debug) && (i-->0))
			{
				printf("\t");
			}

			if (level == WriteLevel::Error)
			{
				printf("[Error] ");
			}

			vwprintf(lineFormat, lineArgs);
			printf("\n");

			FlushConsoleInputBuffer( hstdin );

			SetConsoleTextAttribute( hstdout, csbi.wAttributes );
		}
		else
		{
			fwprintf(gFp, lineFormat, lineArgs );
		}
	}

	va_end (lineArgs);
}
