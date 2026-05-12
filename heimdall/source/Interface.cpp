/* Copyright (c) 2010-2017 Benjamin Dobell, Glass Echidna

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.*/

// C/C++ Standard Library
#include <cstdarg>
#include <cstdlib>
#include <stdio.h>

// Heimdall
#include "Heimdall.h"
#include "Interface.h"

using namespace std;
using namespace libpit;
using namespace Heimdall;

bool stdoutErrors = false;

const char *version = "v2.2.2";
const char *actionUsage = "Usage: heimdall <action> <action arguments>\n";

const char *releaseInfo = "Heimdall %s\n\n\
Copyright (c) 2010-2017 Benjamin Dobell, Glass Echidna https://glassechidna.com.au\n\
Copyright (c) 2021-2024 Henrik Grimler\n\
This software is provided free of charge. Copying and redistribution is encouraged.\n\n";

static const char *extraInfo = "Heimdall utilises libusb for all USB communication:\n\
    https://www.libusb.info/\n\
\n\
libusb is licensed under the LGPL-2.1:\n\
    https://www.gnu.org/licenses/licenses.html#LGPL\n\n";

void Interface::Print(const char *format, ...)
{
        va_list args;
        va_start(args, format);

        vfprintf(stdout, format, args);
        fflush(stdout);

        va_end(args);

}

void Interface::Print(rust::Str message)
{
        fprintf(stdout, "%.*s", (int)message.length(), message.data());
        fflush(stdout);
}

void Interface::PrintWarning(const char *format, ...)
{
        va_list stderrArgs;
        va_start(stderrArgs, format);

        if (stdoutErrors)
        {
                va_list stdoutArgs;
                va_copy(stdoutArgs, stderrArgs);
                fprintf(stdout, "WARNING: ");
                vfprintf(stdout, format, stdoutArgs);
                fflush(stdout);
                va_end(stdoutArgs);
        }

        fprintf(stderr, "WARNING: ");
        vfprintf(stderr, format, stderrArgs);
        fflush(stderr);

        va_end(stderrArgs);
}

void Interface::PrintWarning(rust::Str message)
{
        if (stdoutErrors)
        {
                fprintf(stdout, "WARNING: %.*s", (int)message.length(), message.data());
                fflush(stdout);
        }

        fprintf(stderr, "WARNING: %.*s", (int)message.length(), message.data());
        fflush(stderr);
}

void Interface::PrintWarningSameLine(const char *format, ...)
{
        va_list stderrArgs;
        va_start(stderrArgs, format);

        if (stdoutErrors)
        {
                va_list stdoutArgs;
                va_copy(stdoutArgs, stderrArgs);
                vfprintf(stdout, format, stdoutArgs);
                fflush(stdout);
                va_end(stdoutArgs);
        }

        vfprintf(stderr, format, stderrArgs);
        fflush(stderr);

        va_end(stderrArgs);
}

void Interface::PrintError(const char *format, ...)
{
        va_list stderrArgs;
        va_start(stderrArgs, format);

        if (stdoutErrors)
        {
                va_list stdoutArgs;
                va_copy(stdoutArgs, stderrArgs);
                fprintf(stdout, "ERROR: ");
                vfprintf(stdout, format, stdoutArgs);
                fflush(stdout);
                va_end(stdoutArgs);
        }

        fprintf(stderr, "ERROR: ");
        vfprintf(stderr, format, stderrArgs);
        fflush(stderr);

        va_end(stderrArgs);
}

void Interface::PrintError(rust::Str message)
{
        if (stdoutErrors)
        {
                fprintf(stdout, "ERROR: %.*s", (int)message.length(), message.data());
                fflush(stdout);
        }

        fprintf(stderr, "ERROR: %.*s", (int)message.length(), message.data());
        fflush(stderr);
}

void Interface::PrintErrorSameLine(const char *format, ...)
{
        va_list stderrArgs;
        va_start(stderrArgs, format);

        if (stdoutErrors)
        {
                va_list stdoutArgs;
                va_copy(stdoutArgs, stderrArgs);
                vfprintf(stdout, format, stdoutArgs);
                fflush(stdout);
                va_end(stdoutArgs);
        }

        vfprintf(stderr, format, stderrArgs);
        fflush(stderr);

        va_end(stderrArgs);
}

void Interface::PrintVersion(void)
{
        Interface::Print("%s\n", version);
}

void Interface::PrintReleaseInfo(void)
{
        Interface::Print(releaseInfo, version);
}

void Interface::PrintFullInfo(void)
{
        Interface::Print(releaseInfo, version);
        Interface::Print(extraInfo);
}

void Interface::PrintDeviceDetectionFailed(void)
{
        Interface::PrintError("Failed to detect compatible download-mode device.\n");
}


void Interface::SetStdoutErrors(bool enabled)
{
        stdoutErrors = enabled;
}
