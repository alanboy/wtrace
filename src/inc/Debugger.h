
ULONG64 GetStartAddress(HANDLE hProcess, CHAR * funName);
HRESULT DebugStringEvent(const DEBUG_EVENT& de);
HRESULT LoadDllDebugEvent(const DEBUG_EVENT& de, HANDLE hProcess);
HRESULT CreateProcessDebugEvent(const DEBUG_EVENT& de);
HRESULT GetProcessInfo(HANDLE hProcess);
HRESULT RetrieveCallstack(HANDLE hThread, HANDLE hProcess, const CONTEXT& context, int nFramesToRead, std::string* sFuntionName, DWORD64 * ip, BOOL * bSkip);
HRESULT Run();
HRESULT GetCurrentFunctionName(HANDLE hThread, HANDLE hProcess, const CONTEXT& context);
HRESULT ExceptionBreakpoint(HANDLE hThread, HANDLE hProcess);
HRESULT ExceptionSingleStep(HANDLE hProcess, HANDLE hThread);
HRESULT ExceptionAccessViolation(HANDLE hProcess, HANDLE hThread,const EXCEPTION_RECORD& exception );

