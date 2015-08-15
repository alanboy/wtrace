
class DebugEngine;


class HtmlOutput : public DebugEventCallback
{

private:
	DebugEngine * m_DebugEngine;
	bool m_bStarted;

	HRESULT Dispatch(bool* bLetGo);
	HRESULT StartOutput();
	HRESULT EndOutput();
	HtmlOutput();

	std::ofstream myfile;

public:
	HtmlOutput(DebugEngine * engine, std::wstring sOutputFilename);

	HRESULT DebugEvent(const DEBUG_EVENT& event);

	~HtmlOutput();

};

