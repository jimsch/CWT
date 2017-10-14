#!/bin/bash
set -ev
mono nuget.exe restore $SLN

ls packages
ls packages/Portable.BouncyCastle.1.8.1.3
ls packages/Portable.BouncyCastle.1.8.1.3/lib


msbuild /p:Configuration=$VERSION $SLN

mono ./testrunner/NUnit.ConsoleRunner.3.5.0/tools/nunit3-console.exe ./WebTokenTest/bin/$VERSION/WebTokenTest.dll
