/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

#include <iostream>
#include <map>
#include <list>
#include <Dbghelp.h>

class DebugEventCallback;
class WowDebugEngine;

//
// Public interface for debugging engine
//
class DebugEngine
{
private:
	BYTE m_bOriginalInstruction;
	DWORD m_dwProcessNameLen;
	DWORD64 m_dw64StartAddress = 0;
	bool m_bfirstDebugEvent = true;
	bool m_bIsWowProcess = false;
	int m_iAnalysisLevel;
	int m_iSpawnedProcess;
	long m_lFunctionCalls = 0;
	wchar_t * m_StrCmd;
	std::map<std::string, IMAGEHLP_MODULE64> m_mLoadedModules;
	std::map<DWORD64, BYTE> m_mBreakpointsOriginalInstruction;

protected:
	bool m_bSymInitialized;
	bool m_bInUserCode = false; // true when running user-written code (not loader)
	HANDLE m_hCurrentThread;
	HANDLE m_hCurrentProcess;
	CONTEXT m_hCurrentContext;
	WOW64_CONTEXT m_hCurrentWoWContext; // get rid of this, and move it to wowdebugengine

private:
	WowDebugEngine * m_pWow64engine;
	DebugEventCallback * m_pCallback = nullptr;

	HRESULT CreateProcessDebugEvent(const DEBUG_EVENT& de);
	HRESULT DebugStringEvent(const DEBUG_EVENT& de);
	HRESULT LoadDllDebugEvent(const DEBUG_EVENT& de, HANDLE hProcess);
	HRESULT ExceptionAccessViolation(HANDLE hProcess, HANDLE hThread,const EXCEPTION_RECORD& exception );
	HRESULT ExceptionBreakpoint(HANDLE hThread, HANDLE hProcess);
	HRESULT ExceptionSingleStep();
	HRESULT GetModuleName(DWORD64 add,std::string *sModuleName);

public:
	// OTher stuff
	HRESULT AddCallback(DebugEventCallback *callback);

	//Debugging the target
	HRESULT GetCurrentFunctionName(const CONTEXT& context);
	HRESULT GetProcessInfo(HANDLE hProcess);
	HRESULT GetCurrentCallstack(std::list<std::string> *mapStack, int nFrames);
	HRESULT GetRegisters(std::map<std::string, DWORD64> *mapRegisters);
	HRESULT InsertBreakpoint(HANDLE hProcess, DWORD64 dw64Address);
	HRESULT SetSingleStepFlag();
	HRESULT SetCommandLine(wchar_t *strCmd);
	HRESULT Run();
	HRESULT IsWowProcess(bool *bIsWow);

	HRESULT IsPastFirstBreakPoint(bool *bIsPastFirstBp);
};


