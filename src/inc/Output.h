
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


void Interactive();
void Write(WriteLevel level, const WCHAR * lineFormat, ...);

#define WIDE2(x) L##x
#define WIDE1(x) WIDE2(x)
#define ENTER_FN \
			dFunctionDepth++; \
			Write(WriteLevel::Debug, L"ENTERING FUNCTION " WIDE1(__FUNCTION__)); \
			dFunctionDepth++; \
			HRESULT hr; \
			hr = S_OK;


#define EXIT_FN \
			if (0,0) goto Exit; \
			Exit: \
			dFunctionDepth--; \
			Write(WriteLevel::Debug, L"EXITING  FUNCTION " WIDE1(__FUNCTION__));\
			dFunctionDepth--; \
			return hr;

#define EXIT_FN_NO_RET \
			if (0,0) goto Exit; \
			Exit: \
			dFunctionDepth--; \
			Write(WriteLevel::Debug, L"EXITING  FUNCTION " WIDE1(__FUNCTION__));\
			dFunctionDepth--; \

#define FATAL_ERROR(X) \
			Write(WriteLevel::Error, L"Fatal Error 0x%x at " WIDE1(__FILE__) L" : " WIDE1(__FUNCTION__), X);\
			hr = X;

