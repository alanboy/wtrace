
enum class WriteLevel
{
	Debug = 0,
	Info,
	Output
};

extern WriteLevel gWriteLevelThreshold;
extern FILE * gFp;

void Write(WriteLevel level, const WCHAR * lineFormat, ...);
