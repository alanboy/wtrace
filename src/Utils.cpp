
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
#include <tchar.h>
#include <string.h>
#include <psapi.h>
#include <strsafe.h>

#include "Main.h"
#include "output.h"

wchar_t *gOutputFile;
wchar_t *gpCommandLine;
FILE * gFileHandle;

//void GetProcessInfo(HANDLE hProcess)
//{
//	ENTER_FN
//
//	PROCESS_BASIC_INFORMATION pinfo;
//	ULONG resLen;
//	BOOL result;
//
//	NTSTATUS status = NtQueryInformationProcess(
//			hProcess,
//			PROCESSINFOCLASS::ProcessBasicInformation,
//			(PVOID)&pinfo,
//			sizeof(PVOID)*6,
//			&resLen);
//
//	if (status != 0)
//	{
//		Write(WriteLevel::Error, L"NtQueryInformationProcess failed 0x%x", status);
//		goto Exit;
//	}
//
//	PPEB ppeb = (PPEB)((PVOID*)&pinfo)[1];
//	PPEB ppebCopy = (PPEB)malloc(sizeof(PEB));
//
//	result = ReadProcessMemory(hProcess,
//			ppeb,
//			ppebCopy,
//			sizeof(PEB),
//			NULL);
//	if (result == 0)
//	{
//		Write(WriteLevel::Debug, L"ReadProcessMemory failed %x", GetLastError());
//		goto Exit;
//	}
//
//	PRTL_USER_PROCESS_PARAMETERS pRtlProcParam = ppebCopy->ProcessParameters;
//	PRTL_USER_PROCESS_PARAMETERS pRtlProcParamCopy = (PRTL_USER_PROCESS_PARAMETERS)malloc(sizeof(RTL_USER_PROCESS_PARAMETERS));
//
//	result = ReadProcessMemory(hProcess,
//								pRtlProcParam,
//								pRtlProcParamCopy,
//								sizeof(RTL_USER_PROCESS_PARAMETERS),
//								NULL);
//	if (result == 0)
//	{
//		Write(WriteLevel::Debug, L"ReadProcessMemory failed %x", GetLastError());
//		goto Exit;
//	}
//
//	PWSTR wBuffer = pRtlProcParamCopy->CommandLine.Buffer;
//	USHORT len =  pRtlProcParamCopy->CommandLine.Length;
//	PWSTR wBufferCopy = (PWSTR)malloc(len);
//
//	result = ReadProcessMemory(hProcess,
//								wBuffer,
//								wBufferCopy, // command line goes here
//								len,
//								NULL);
//	if (result == 0)
//	{
//		Write(WriteLevel::Debug, L"ReadProcessMemory failed %x", GetLastError());
//		goto Exit;
//	}
//
//	//if (gFp)
//	//	fwprintf( gFp, L" %s\n", wBufferCopy );
//
//Exit:
//	EXIT_FN
//
//	return;
//}
//
// This was taken from 
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa366789(v=vs.85).aspx
//
BOOL GetFileNameFromHandle(HANDLE hFile, TCHAR *pszFilename)
{
  BOOL bSuccess = FALSE;
  HANDLE hFileMap;

  // Get the file size.
  DWORD dwFileSizeHi = 0;
  DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi); 

  if( dwFileSizeLo == 0 && dwFileSizeHi == 0 )
  {
     _tprintf(TEXT("Cannot map a file with a length of zero.\n"));
     return FALSE;
  }

  // Create a file mapping object.
  hFileMap = CreateFileMapping(hFile, 
                    NULL, 
                    PAGE_READONLY,
                    0, 
                    1,
                    NULL);

  if (hFileMap) 
  {
    // Create a file mapping to get the file name.
    void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

    if (pMem) 
    {
      if (GetMappedFileName (GetCurrentProcess(), 
                             pMem, 
                             pszFilename,
                             MAX_PATH)) 
      {

        // Translate path with device name to drive letters.
        TCHAR szTemp[BUFSIZE];
        szTemp[0] = '\0';

        if (GetLogicalDriveStrings(BUFSIZE-1, szTemp)) 
        {
          TCHAR szName[MAX_PATH];
          TCHAR szDrive[3] = TEXT(" :");
          BOOL bFound = FALSE;
          TCHAR* p = szTemp;

          do 
          {
            // Copy the drive letter to the template string
            *szDrive = *p;

            // Look up each device name
            if (QueryDosDevice(szDrive, szName, MAX_PATH))
            {
              size_t uNameLen = _tcslen(szName);

              if (uNameLen < MAX_PATH) 
              {
                bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
                         && *(pszFilename + uNameLen) == _T('\\');

                if (bFound) 
                {
                  // Reconstruct pszFilename using szTempFile
                  // Replace device path with DOS path
                  TCHAR szTempFile[MAX_PATH];
                  StringCchPrintf(szTempFile,
                            MAX_PATH,
                            TEXT("%s%s"),
                            szDrive,
                            pszFilename+uNameLen);
                  StringCchCopyN(pszFilename, MAX_PATH+1, szTempFile, _tcslen(szTempFile));
                }
              }
            }

            // Go to the next NULL character.
            while (*p++);
          } while (!bFound && *p); // end of string
        }
      }
      bSuccess = TRUE;
      UnmapViewOfFile(pMem);
    } 

    CloseHandle(hFileMap);
  }
  return(bSuccess);
}
