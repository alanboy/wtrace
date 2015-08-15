
class DebugEngine;

class TracerPlugin : public DebugEventCallback
{
private:
	DebugEngine * m_DebugEngine;

public:
	TracerPlugin(DebugEngine * engine);

	HRESULT DebugEvent(const DEBUG_EVENT& event);
};

