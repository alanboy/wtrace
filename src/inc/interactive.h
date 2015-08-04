
#pragma once

class DebugEngine;

class InteractiveCommandLine
{
private:
	std::string m_sCurrentCmd;
	DebugEngine * m_DebugEngine;

	HRESULT Dispatch(bool* bContinueExecution);

public:
	InteractiveCommandLine(DebugEngine * engine);

	HRESULT DebugEvent();
};

