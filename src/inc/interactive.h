
#pragma once

class DebugEngine;

class InteractiveCommandLine
{
private:
	std::string m_sCurrentCmd;
	DebugEngine * m_DebugEngine;

	HRESULT Dispatch();

public:
	InteractiveCommandLine(DebugEngine * engine);

	HRESULT DebugEvent();
};

