
void DebugStringEvent(const DEBUG_EVENT& de);
void LoadDllDebugEvent(const DEBUG_EVENT& de);
void CreateProcessDebugEvent(const DEBUG_EVENT& de);
void GetProcessInfo(HANDLE hProcess);
void RetrieveCallstack(HANDLE hThread, HANDLE hProcess);
void Run();
DWORD GetStartAddress(HANDLE hProcess, CHAR * funName);

