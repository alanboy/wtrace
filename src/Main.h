
#define SUCCESS(x) (x=!0)
#define _UNICODE
#define UNICODE 

#define BUFSIZE 512

extern wchar_t *gOutputFile;
extern char *gpCommandLine;
extern FILE * gFileHandle;
extern int gAnalysisLevel;

void ParseCommandLine(int argc, char ** argv);
void Usage(void);
void Logo(void);
int  main(int argc, char ** argv);

