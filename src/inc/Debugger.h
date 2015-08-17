
#include <iostream>
#include <map>
#include <Dbghelp.h>

class InteractiveCommandLine;
class DebugEventCallback;


class DebugEngine
{
private:
	BYTE m_bOriginalInstruction;
	DWORD m_dwProcessNameLen;
	DWORD64 m_dw64StartAddress = 0;
	bool m_bSymInitialized;
	bool m_bfirstDebugEvent = 1;
	int m_iAnalysisLevel;
	int m_iSpawnedProcess;
	long m_lFunctionCalls = 0;
	std::map<std::string, IMAGEHLP_MODULE64> m_mLoadedModules;
	std::map<DWORD64, BYTE> m_mBreakpointsOriginalInstruction;

	// Current context & info
	HANDLE m_hCurrentThread;
	HANDLE m_hCurrentProcess;
	CONTEXT m_hCurrentContext;

	// Interactive session
	DebugEventCallback * m_pCallback = nullptr;

	HRESULT CreateProcessDebugEvent(const DEBUG_EVENT& de);
	HRESULT DebugStringEvent(const DEBUG_EVENT& de);
	HRESULT LoadDllDebugEvent(const DEBUG_EVENT& de, HANDLE hProcess);
	HRESULT ExceptionAccessViolation(HANDLE hProcess, HANDLE hThread,const EXCEPTION_RECORD& exception );
	HRESULT ExceptionBreakpoint(HANDLE hThread, HANDLE hProcess);
	HRESULT ExceptionSingleStep(HANDLE hProcess, HANDLE hThread);

public:
	// OTher stuff
	//HRESULT AddInteractiveSession(InteractiveCommandLine * interactive);
	HRESULT AddCallback(DebugEventCallback *callback);

	//Debugging the targe
	HRESULT GetCurrentFunctionName(HANDLE hThread, HANDLE hProcess, const CONTEXT& context);
	HRESULT GetProcessInfo(HANDLE hProcess);
	HRESULT GetCurrentCallstack(std::map<std::string, STACKFRAME64> *mapStack);
	HRESULT GetRegisters(std::map<std::string, DWORD64> *mapRegisters);
	HRESULT InsertBreakpoint(HANDLE hProcess, DWORD64 dw64Address);
	HRESULT SetSingleStepFlag();
	HRESULT Run();
};


