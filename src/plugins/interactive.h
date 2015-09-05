
class DebugEngine;

class InteractiveCommandLine : public DebugEventCallback
{
private:
	std::string m_sCurrentCmd; // Store the cmd provided by the user
	std::wstring m_wsCommandToExecute; // The cmd provided by the -c argument
	DebugEngine * m_DebugEngine;

	HRESULT Dispatch(bool* bContinueExecution);

public:
	InteractiveCommandLine(DebugEngine * engine);
	void SetCommandToExecute(const std::wstring& sCommand);
	HRESULT DebugEvent(const DEBUG_EVENT& event);
};

