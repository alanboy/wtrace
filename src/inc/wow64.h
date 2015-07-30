
class WowDebugEngine
{
private:
	bool 			m_bSymInitialized;
	DWORD64 		m_dw64StartAddress;
	BYTE			m_OriginalInstruction;
	BOOL			gbFirst = TRUE;
	std::map<std::string, IMAGEHLP_MODULE64>	m_mLoadedModules;

public:
	HRESULT DumpWowContext(const WOW64_CONTEXT& lcContext);
	HRESULT Wow64SingleStep(HANDLE hProcess, HANDLE hThread);
	HRESULT Wow64Breakpoint(HANDLE hProcess, HANDLE hThread);
	HRESULT RetrieveWoWCallstack(HANDLE hThread, HANDLE hProcess, const WOW64_CONTEXT& context, int nFramesToRead, std::string* sFuntionName, DWORD * ip);

	void SetStartAddress(DWORD64 dw64StartAdd)
	{
		m_dw64StartAddress = dw64StartAdd;
	}
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

