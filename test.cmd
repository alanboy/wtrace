@echo off

rem 
rem TODO:
rem
rem Replace this with something like Google Test Framework
rem Test using white/black box technique.
rem The test should make perf measurements, and
rem check in the results, so that no regressions are
rem introduced.
rem

echo ==== Test help menu
bin\x86\wtrace.exe -? > NUL
if NOT ERRORLEVEL 0 goto failed

echo ==== Test amd64 on amd64 process leve tracing
bin\x64\wtrace.exe -v info -a 3 "bin\x64\wtrace.exe -?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo ==== Test x86 on x86 
bin\x86\wtrace.exe -v info -a 3 "bin\x86\wtrace.exe -?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo ==== Test inbox binary (native)
 bin\x64\wtrace.exe "%windir%\system32\xcopy.exe /?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo ==== Test inbox binary (wow)
 bin\x64\wtrace.exe -v info "%windir%\syswow64\xcopy.exe /?" > NUL
if NOT ERRORLEVEL 0 goto failed

rem echo ==== Test 2 levels deep (process that launches a process)
rem bin\x64\wtrace.exe -v info "%windir%\syswow64\xcopy.exe /?" > NUL
rem if NOT ERRORLEVEL 0 goto failed

rem echo ==== Test tracing with debugging information
rem bin\x64\wtrace.exe -v debug -a 3 "bin\x86\wtrace.exe -?"
rem if NOT ERRORLEVEL 0 goto failed
rem 
rem echo ==== Test function level tracing
rem bin\x64\wtrace.exe -f -v info "bin\x64\wtrace.exe -?"
rem if NOT ERRORLEVEL 0 goto failed
rem 
rem echo ==== Test html mode
rem bin\x64\wtrace.exe -html -a 3 "bin\x86\wtrace.exe -?"
rem if NOT ERRORLEVEL 0 goto failed

echo ==== Test interactive mode (simple)
echo g |  bin\x64\wtrace.exe -i "bin\x64\wtrace.exe -?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo ==== Test interactive mode (command line)
bin\x64\wtrace.exe -i -c "kn;g;g;g;g;g;g" "bin\x64\wtrace.exe -?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo All test passed.
goto end

:failed
echo !!! TEST FAILED !!!!
echo %ERRORLEVEL%

:end

