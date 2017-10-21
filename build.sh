#!/bin/bash
set -ev
mono nuget.exe restore $SLN

ls 
ls WebToken

msbuild /p:Configuration=$VERSION $SLN

mono ./testrunner/NUnit.ConsoleRunner.3.5.0/tools/nunit3-console.exe ./WebTokenTest/bin/$VERSION/WebTokenTest.dll
