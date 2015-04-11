
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

WriteLevel gWriteLevelThreshold = WriteLevel::Output;
FILE * gFp;

void Write(WriteLevel level, const WCHAR * lineFormat, ...)
{
	va_list lineArgs;
	va_start (lineArgs, lineFormat);

	if (level >= gWriteLevelThreshold)
	{
		if (gFp == NULL)
		{
			vwprintf(lineFormat, lineArgs);
			printf("\n");
		}
		else
		{
			fwprintf(gFp, lineFormat, lineArgs );
		}
	}

	va_end (lineArgs);
}
