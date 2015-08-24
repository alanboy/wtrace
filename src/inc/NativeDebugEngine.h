/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

#include <iostream>
#include <map>
#include <list>
#include <Dbghelp.h>

//
// WoWDebugEngine for handling native debugging.
// * x86 on x86
// * amd64 on amd64
//
class NativeDebugEngine : public DebugEngine
{
private:

public:
	HRESULT DumpContext(const CONTEXT& lcContext);
};


