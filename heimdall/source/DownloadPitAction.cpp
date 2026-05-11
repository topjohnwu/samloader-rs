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

// C Standard Library
#include <stdio.h>

// Heimdall
#include "ActionInterfaces.h"
#include "BridgeManager.h"
#include "Heimdall.h"
#include "Interface.h"

using namespace std;
using namespace Heimdall;


int Heimdall::action_download_pit(rust::Str output, bool verbose, bool wait, bool stdout_errors, rust::Str usb_log_level)
{
        string outputFilename(output.data(), output.length());

        if (outputFilename.empty())
        {
                Interface::Print("Output file was not specified.\n\n");
                return (0);
        }

        bool waitForDevice = wait;

        if (stdout_errors)
                Interface::SetStdoutErrors(true);

        // Info
        Interface::PrintReleaseInfo();
        Sleep(1000);

        // Open output file
        FILE *outputPitFile = FileOpen(outputFilename.c_str(), "wb");

        if (!outputPitFile)
        {
                Interface::PrintError("Failed to open output file \"%s\"\n", outputFilename.c_str());
                return (1);
        }

        // Download PIT file from device.
        BridgeManager *bridgeManager = new BridgeManager(verbose, waitForDevice);
        bridgeManager->SetUsbLogLevel(usb_log_level);

        if (bridgeManager->Initialise() != BridgeManager::kInitialiseSucceeded || !bridgeManager->BeginSession())
        {
                FileClose(outputPitFile);
                delete bridgeManager;

                return (1);
        }

        unsigned char *pitBuffer = nullptr;
        int fileSize = bridgeManager->DownloadPitFile(&pitBuffer);

        bool success = true;

        if (fileSize > 0)
        {
                if (fwrite(pitBuffer, 1, fileSize, outputPitFile) != static_cast<size_t>(fileSize))
                {
                        Interface::PrintError("Failed to write PIT data to output file.\n");
                        success = false;
                }
        }
        else
        {
                success = false;
        }

        if (!bridgeManager->EndSession())
                success = false;

        delete bridgeManager;

        FileClose(outputPitFile);
        delete [] pitBuffer;

        return (success ? 0 : 1);
}
