
enum class WriteLevel
{
	Debug = 0,
	Info,
	Output,
	Error
};

extern WriteLevel gWriteLevelThreshold;
extern FILE * gFp;
extern int dFunctionDepth;

void Write(WriteLevel level, const WCHAR * lineFormat, ...);
