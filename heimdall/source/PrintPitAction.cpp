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
#include "Heimdall.h"
#include "Interface.h"
#include "heimdall/src/main.rs.h"

using namespace std;
using namespace libpit;
using namespace Heimdall;


int Heimdall::action_print_pit(rust::Str file, bool verbose, bool wait, bool stdout_errors, rust::Str usb_log_level)
{
        string filename(file.data(), file.length());

        bool waitForDevice = wait;

        if (stdout_errors)
                Interface::SetStdoutErrors(true);

        // Open file (if specified).

        FILE *localPitFile = nullptr;

        if (!filename.empty())
        {
                localPitFile = FileOpen(filename.c_str(), "rb");

                if (!localPitFile)
                {
                        Interface::PrintError("Failed to open file \"%s\"\n", filename.c_str());
                        return (1);
                }
        }

        // Info

        Interface::PrintReleaseInfo();
        Sleep(1000);

        if (localPitFile)
        {
                // Print PIT from file; there's no need for a BridgeManager.

                FileSeek(localPitFile, 0, SEEK_END);
                unsigned int localPitFileSize = (unsigned int)FileTell(localPitFile);
                FileRewind(localPitFile);

                // Load the local pit file into memory.
                unsigned char *pitFileBuffer = new unsigned char[localPitFileSize];
                fread(pitFileBuffer, 1, localPitFileSize, localPitFile);
                FileClose(localPitFile);

                auto pitData = PitData::make();
                pitData->Unpack({pitFileBuffer, (size_t)localPitFileSize});

                delete [] pitFileBuffer;

                pitData->Print();

                return (0);
        }
        else
        {
                // Print PIT from a device.

                rust::Box<BridgeManager> bridgeManager = BridgeManager::create(verbose, waitForDevice);
                bridgeManager->SetUsbLogLevel(usb_log_level);

                if (bridgeManager->Initialise() != InitialiseResult::Succeeded || !bridgeManager->BeginSession())
                {
                        return (1);
                }

                rust::Vec<unsigned char> devicePit = bridgeManager->DownloadPitFile();
                bool success = !devicePit.empty();

                if (success)
                {
                        auto pitData = PitData::make();

                        if (pitData->Unpack({devicePit.data(), devicePit.size()}))
                        {
                                pitData->Print();
                        }
                        else
                        {
                                Interface::PrintError("Failed to unpack device's PIT file!\n");
                                success = false;
                        }
                }

                if (!bridgeManager->EndSession())
                        success = false;

                return (success ? 0 : 1);
        }
}
