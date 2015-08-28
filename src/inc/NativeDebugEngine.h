/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

//
// WoWDebugEngine for handling native debugging.
// * x86 on x86
// * amd64 on amd64
//
// Implements ArchictectureSpecificInterface and Extends DebugEngine
class NativeDebugEngine : public ArchictectureSpecificInterface
{
public:
	HRESULT DumpContext();
};


