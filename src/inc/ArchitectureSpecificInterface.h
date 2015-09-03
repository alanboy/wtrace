/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */


class ArchictectureSpecificInterface
{
public:
	virtual HRESULT DumpContext() =0;
	virtual HRESULT GetCurrentCallstack(std::list<std::string> *mapStack) =0;
};
