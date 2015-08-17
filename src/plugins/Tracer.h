
class DebugEngine;

class TracerPlugin : public DebugEventCallback
{
private:
	DebugEngine * m_DebugEngine;
	size_t nLastCallSize;
	std::string strLastFunction;

public:
	TracerPlugin(DebugEngine * engine);

	HRESULT DebugEvent(const DEBUG_EVENT& event);
};

