
class DebugEngine;

class InteractiveCommandLine : public DebugEventCallback
{
private:
	std::string m_sCurrentCmd;
	DebugEngine * m_DebugEngine;

	HRESULT Dispatch(bool* bContinueExecution);

public:
	InteractiveCommandLine(DebugEngine * engine);

	HRESULT DebugEvent(const DEBUG_EVENT& event);
};

