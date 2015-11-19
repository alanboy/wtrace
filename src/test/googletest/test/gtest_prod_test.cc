// Copyright 2006, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Author: wan@google.com (Zhanyong Wan)
//
// Unit test for include/gtest/gtest_prod.h.
#define UNICODE
#define _UNICODE

#include "gtest/gtest.h"
#include "test/production.h"

#include <windows.h>
#include "DebugEngine.h"
#include "Output.h"

/** Implement the following test cases */
/*

echo == == Test help menu
bin\x86\wtrace.exe - ? > NUL
if NOT ERRORLEVEL 0 goto failed

echo == == Test amd64 on amd64 process leve tracing
bin\x64\wtrace.exe - v info - a 3 "bin\x64\wtrace.exe -?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo == == Test x86 on x86
bin\x86\wtrace.exe - v info - a 3 "bin\x86\wtrace.exe -?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo == == Test inbox binary(native)
bin\x64\wtrace.exe "%windir%\system32\xcopy.exe /?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo == == Test inbox binary(wow)
bin\x64\wtrace.exe - v info "%windir%\syswow64\xcopy.exe /?" > NUL
if NOT ERRORLEVEL 0 goto failed

rem echo == == Test 2 levels deep(process that launches a process)
rem bin\x64\wtrace.exe - v info "%windir%\syswow64\xcopy.exe /?" > NUL
rem if NOT ERRORLEVEL 0 goto failed

rem echo == == Test tracing with debugging information
rem bin\x64\wtrace.exe - v debug - a 3 "bin\x86\wtrace.exe -?"
rem if NOT ERRORLEVEL 0 goto failed
rem
rem echo == == Test function level tracing
rem bin\x64\wtrace.exe - f - v info "bin\x64\wtrace.exe -?"
rem if NOT ERRORLEVEL 0 goto failed
rem
rem echo == == Test html mode
rem bin\x64\wtrace.exe - html - a 3 "bin\x86\wtrace.exe -?"
rem if NOT ERRORLEVEL 0 goto failed

echo == == Test interactive mode(simple)
echo g | bin\x64\wtrace.exe - i "bin\x64\wtrace.exe -?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo == == Test interactive mode(command line)
bin\x64\wtrace.exe - i - c "kn;g;g;g;g;g;g" "bin\x64\wtrace.exe -?" > NUL
if NOT ERRORLEVEL 0 goto failed

echo All test passed.
goto end

*/
TEST(WtraceHelpTest, CanAccessPrivateMembers) {
	DebugEngine engine;
	gWriteLevelThreshold = WriteLevel::Debug;

	std::wstring foo( L"C:\\Users\\alanb\\Code\\wtrace2\\wtrace\\bin.x86\\wtrace.exe");
	wchar_t * pm = L"C:\\Users\\alanb\\Code\\wtrace2\\wtrace\\bin.x86\\wtrace.exe\0\0";

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	//CreateProcess(NULL, pm, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);
	
	engine.SetCommandLine(pm);
	engine.Run();
}

