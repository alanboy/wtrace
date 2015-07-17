
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

void Interactive()
{
	std::cout << "input>";
	std::string cmd;
	std::cin >> cmd;
}

void Write(WriteLevel level, const WCHAR * lineFormat, ...)
{
	const WORD colors[] =
	{
		//
		//   0 = Black       8 = Gray
		//   1 = Blue        9 = Light Blue
		//   2 = Green       A = Light Green
		//   3 = Aqua        B = Light Aqua
		//   4 = Red         C = Light Red
		//   5 = Purple      D = Light Purple
		//   6 = Yellow      E = Light Yellow
		//   7 = White       F = Bright White
		//
		0x0C /* red on black */,
		0x2B /* green on blue? */, 
		0x0D /* Ligth purple on black - info messages */,
		0x4D, 0x5E, 0x6F,
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
				SetConsoleTextAttribute(hstdout, colors[0]);
				printf(" + ");
			}
			else if ((level == WriteLevel::Info) && (gWriteLevelThreshold == WriteLevel::Debug))
			{
				// color info messages when debug is turned on
				SetConsoleTextAttribute(hstdout, colors[1]);
				printf(">> ");
			}
			else if ((level == WriteLevel::Info) && (gWriteLevelThreshold == WriteLevel::Info))
			{
				// color all messages to distinguish from programs output
				SetConsoleTextAttribute(hstdout, colors[2]);
				printf(">> ");
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

			vwprintf(lineFormat, lineArgs);
			printf("\n");

			FlushConsoleInputBuffer( hstdin );

			SetConsoleTextAttribute( hstdout, csbi.wAttributes );


			if (level == WriteLevel::Error)
			{
				//Interactive();
			}
		}
		else
		{
			fwprintf(gFp, lineFormat, lineArgs );
		}
	}

	va_end (lineArgs);
}

