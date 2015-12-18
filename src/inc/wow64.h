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

//
// WoWDebugEngine for handling Windows on Windows processes.
// * x86 on amd64
//
// Implements ArchictectureSpecificInterface and Extends DebugEngine
class WowDebugEngine : public DebugEngine
{
private:
	bool 			m_bSymInitialized;
	DWORD64 		m_dw64StartAddress;
	BYTE			m_OriginalInstruction;
	BOOL			gbFirst = TRUE;
	std::map<std::string, IMAGEHLP_MODULE64>	m_mLoadedModules;

	WOW64_CONTEXT m_hCurrentContext;

public:
	HRESULT Wow64SingleStep(HANDLE hProcess, HANDLE hThread);
	HRESULT Wow64Breakpoint(HANDLE hProcess, HANDLE hThread);
	HRESULT GetCurrentCallstack(std::list<std::string> *mapStack);
	HRESULT WowDebugEngine::SetStartAddress(DWORD64 startAddress);
};


//
// From ntstatus.h for now put it here until u figure out how to call it from the 
// proper header file.
//
#define STATUS_WX86_UNSIMULATE           ((NTSTATUS)0x4000001CL)
#define STATUS_WX86_CONTINUE             ((NTSTATUS)0x4000001DL)
#define STATUS_WX86_SINGLE_STEP          ((NTSTATUS)0x4000001EL)
#define STATUS_WX86_BREAKPOINT           ((NTSTATUS)0x4000001FL)
#define STATUS_WX86_EXCEPTION_CONTINUE   ((NTSTATUS)0x40000020L)
#define STATUS_WX86_EXCEPTION_LASTCHANCE ((NTSTATUS)0x40000021L)
#define STATUS_WX86_EXCEPTION_CHAIN      ((NTSTATUS)0x40000022L)
#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE ((NTSTATUS)0x40000023L)
#define STATUS_NO_YIELD_PERFORMED        ((NTSTATUS)0x40000024L)
#define STATUS_TIMER_RESUME_IGNORED      ((NTSTATUS)0x40000025L)
#define STATUS_ARBITRATION_UNHANDLED     ((NTSTATUS)0x40000026L)
#define STATUS_CARDBUS_NOT_SUPPORTED     ((NTSTATUS)0x40000027L)
#define STATUS_WX86_CREATEWX86TIB        ((NTSTATUS)0x40000028L)
#define STATUS_WX86_INTERNAL_ERROR       ((NTSTATUS)0xC000026FL)
#define STATUS_WX86_FLOAT_STACK_CHECK    ((NTSTATUS)0xC0000270L)

