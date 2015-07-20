
HRESULT DumpWowContext(const WOW64_CONTEXT& lcContext);
HRESULT Wow64SingleStep(HANDLE hProcess, HANDLE hThread);
HRESULT Wow64Breakpoint(HANDLE hProcess, HANDLE hThread);
HRESULT RetrieveWoWCallstack(HANDLE hThread, HANDLE hProcess, const WOW64_CONTEXT& context, int nFramesToRead, std::string* sFuntionName, DWORD64 * ip);


// From ntstatus.h for now put it here until u figure out how to call it from the 
// proper header file.

//
// MessageId: STATUS_WX86_UNSIMULATE
//
// MessageText:
//
// Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_UNSIMULATE           ((NTSTATUS)0x4000001CL)

//
// MessageId: STATUS_WX86_CONTINUE
//
// MessageText:
//
// Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_CONTINUE             ((NTSTATUS)0x4000001DL)

//
// MessageId: STATUS_WX86_SINGLE_STEP
//
// MessageText:
//
// Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_SINGLE_STEP          ((NTSTATUS)0x4000001EL)

//
// MessageId: STATUS_WX86_BREAKPOINT
//
// MessageText:
//
// Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_BREAKPOINT           ((NTSTATUS)0x4000001FL)

//
// MessageId: STATUS_WX86_EXCEPTION_CONTINUE
//
// MessageText:
//
// Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_EXCEPTION_CONTINUE   ((NTSTATUS)0x40000020L)

//
// MessageId: STATUS_WX86_EXCEPTION_LASTCHANCE
//
// MessageText:
//
// Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_EXCEPTION_LASTCHANCE ((NTSTATUS)0x40000021L)

//
// MessageId: STATUS_WX86_EXCEPTION_CHAIN
//
// MessageText:
//
// Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_EXCEPTION_CHAIN      ((NTSTATUS)0x40000022L)

//
// MessageId: STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE
//
// MessageText:
//
// {Machine Type Mismatch}
// The image file %hs is valid, but is for a machine type other than the current machine.
//
#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE ((NTSTATUS)0x40000023L)

//
// MessageId: STATUS_NO_YIELD_PERFORMED
//
// MessageText:
//
// A yield execution was performed and no thread was available to run.
//
#define STATUS_NO_YIELD_PERFORMED        ((NTSTATUS)0x40000024L)

//
// MessageId: STATUS_TIMER_RESUME_IGNORED
//
// MessageText:
//
// The resumable flag to a timer API was ignored.
//
#define STATUS_TIMER_RESUME_IGNORED      ((NTSTATUS)0x40000025L)

//
// MessageId: STATUS_ARBITRATION_UNHANDLED
//
// MessageText:
//
// The arbiter has deferred arbitration of these resources to its parent
//
#define STATUS_ARBITRATION_UNHANDLED     ((NTSTATUS)0x40000026L)

//
// MessageId: STATUS_CARDBUS_NOT_SUPPORTED
//
// MessageText:
//
// The device "%hs" has detected a CardBus card in its slot, but the firmware on this system is not configured to allow the CardBus controller to be run in CardBus mode.
// The operating system will currently accept only 16-bit (R2) pc-cards on this controller.
//
#define STATUS_CARDBUS_NOT_SUPPORTED     ((NTSTATUS)0x40000027L)

//
// MessageId: STATUS_WX86_CREATEWX86TIB
//
// MessageText:
//
// Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_CREATEWX86TIB        ((NTSTATUS)0x40000028L)

//
// MessageId: STATUS_WX86_INTERNAL_ERROR
//
// MessageText:
//
// An internal error occurred in the Win32 x86 emulation subsystem.
//
#define STATUS_WX86_INTERNAL_ERROR       ((NTSTATUS)0xC000026FL)

//
// MessageId: STATUS_WX86_FLOAT_STACK_CHECK
//
// MessageText:
//
// Win32 x86 emulation subsystem Floating-point stack check.
//
#define STATUS_WX86_FLOAT_STACK_CHECK    ((NTSTATUS)0xC0000270L)
