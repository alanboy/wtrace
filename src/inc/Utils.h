
BOOL GetFileNameFromHandle(HANDLE hFile, TCHAR *pszFilename);


#define CMPSTR(X,Y) CompareStringOrdinal(##X##, -1, ##Y##, -1, TRUE) == CSTR_EQUAL

#define BREAK_IF_DEBUGGER_PRESENT() if (IsDebuggerPresent()) DebugBreak();



