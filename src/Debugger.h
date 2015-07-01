
void DebugStringEvent(const DEBUG_EVENT& de);
void LoadDllDebugEvent(const DEBUG_EVENT& de, HANDLE hProcess);
void CreateProcessDebugEvent(const DEBUG_EVENT& de);
void GetProcessInfo(HANDLE hProcess);
void RetrieveCallstack(HANDLE hThread, HANDLE hProcess, const CONTEXT& context, int nFramesToRead, std::string* sFuntionName, DWORD64 * ip);
void Run();
ULONG64 GetStartAddress(HANDLE hProcess, CHAR * funName);

void GetCurrentFunctionName(HANDLE hThread, HANDLE hProcess, const CONTEXT& context);
void ExceptionBreakpoint(HANDLE hThread, HANDLE hProcess);
void ExceptionSingleStep(HANDLE hProcess, HANDLE hThread);


