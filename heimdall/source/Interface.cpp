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
#include "ClosePcScreenAction.h"
#include "DetectAction.h"
#include "DownloadPitAction.h"
#include "FlashAction.h"
#include "HelpAction.h"
#include "InfoAction.h"
#include "Heimdall.h"
#include "Interface.h"
#include "PrintPitAction.h"
#include "VersionAction.h"

using namespace std;
using namespace libpit;
using namespace Heimdall;

map<string, Interface::ActionInfo> actionMap;
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

void populateActionMap(void)
{
	actionMap["close-pc-screen"] = Interface::ActionInfo(&ClosePcScreenAction::Execute, ClosePcScreenAction::usage);
	actionMap["detect"] = Interface::ActionInfo(&DetectAction::Execute, DetectAction::usage);
	actionMap["download-pit"] = Interface::ActionInfo(&DownloadPitAction::Execute, DownloadPitAction::usage);
	actionMap["flash"] = Interface::ActionInfo(&FlashAction::Execute, FlashAction::usage);
	actionMap["help"] = Interface::ActionInfo(&HelpAction::Execute, HelpAction::usage);
	actionMap["info"] = Interface::ActionInfo(&InfoAction::Execute, InfoAction::usage);
	actionMap["print-pit"] = Interface::ActionInfo(&PrintPitAction::Execute, PrintPitAction::usage);
	actionMap["version"] = Interface::ActionInfo(&VersionAction::Execute, VersionAction::usage);
}

const map<string, Interface::ActionInfo>& Interface::GetActionMap(void)
{
	if (actionMap.size() == 0)
		populateActionMap();

	return actionMap;
}

void Interface::Print(const char *format, ...)
{
	va_list args;
	va_start(args, format);

	vfprintf(stdout, format, args);
	fflush(stdout);

	va_end(args);

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

void Interface::PrintUsage(void)
{
	const map<string, ActionInfo>& actionMap = Interface::GetActionMap();

	Interface::Print(actionUsage);

	for (map<string, ActionInfo>::const_iterator it = actionMap.begin(); it != actionMap.end(); it++)
		Interface::Print("\n%s", it->second.usage);
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

void Interface::PrintPit(const PitData& pitData)
{
	Interface::Print("--- PIT Header ---\n");
	Interface::Print("Entry Count: %d\n", pitData.GetEntryCount());
	Interface::Print("Unknown string: %s\n", pitData.GetComTar2().c_str());
	Interface::Print("CPU/bootloader tag: %s\n", pitData.GetCpuBlId().c_str());
	Interface::Print("Logic unit count: %d\n", pitData.GetLUCount());

	for (unsigned int i = 0; i < pitData.GetEntryCount(); i++)
	{
		const PitEntry *entry = pitData.GetEntry(i);

		Interface::Print("\n\n--- Entry #%d ---\n", i);
		Interface::Print("Binary Type: %d (", entry->GetBinaryType());

		switch (static_cast<BinaryType>(entry->GetBinaryType()))
		{
			case BinaryType::ApplicationProcessor:
				Interface::Print("AP");
				break;

			case BinaryType::CommunicationProcessor:
				Interface::Print("CP");
				break;

			default:
				Interface::Print("Unknown");
				break;
		}

		Interface::Print(")\n");

		Interface::Print("Device Type: %d (", entry->GetDeviceType());

		switch (static_cast<DeviceType>(entry->GetDeviceType()))
		{
			case DeviceType::OneNand:
				Interface::Print("OneNAND");
				break;

			case DeviceType::File:
				Interface::Print("File/FAT");
				break;

			case DeviceType::MMC:
				Interface::Print("MMC");
				break;

			case DeviceType::All:
				Interface::Print("All (?)");
				break;

			case DeviceType::UFS:
				Interface::Print("UFS");
				break;

			default:
				Interface::Print("Unknown");
				break;
		}

		Interface::Print(")\n");

		Interface::Print("Identifier: %d\n", entry->GetIdentifier());

		Interface::Print("Attributes: %d (", entry->GetAttributes());

		if (entry->GetAttributes() & static_cast<uint32_t>(Attribute::STL))
			Interface::Print("STL ");

		/*if (entry->GetAttributes() & static_cast<uint32_t>(Attribute::BML))
			Interface::Print("BML ");*/

		if (entry->GetAttributes() & static_cast<uint32_t>(Attribute::Write))
			Interface::Print("Read/Write");
		else
			Interface::Print("Read-Only");

		Interface::Print(")\n");

		Interface::Print("Update Attributes: %d", entry->GetUpdateAttributes());

		if (entry->GetUpdateAttributes())
		{
			Interface::Print(" (");

			if (entry->GetUpdateAttributes() & static_cast<uint32_t>(UpdateAttribute::Fota))
			{
				if (entry->GetUpdateAttributes() & static_cast<uint32_t>(UpdateAttribute::Secure))
					Interface::Print("FOTA, Secure");
				else
					Interface::Print("FOTA");
			}
			else
			{
				if (entry->GetUpdateAttributes() & static_cast<uint32_t>(UpdateAttribute::Secure))
					Interface::Print("Secure");
			}

			Interface::Print(")\n");
		}
		else
		{
			Interface::Print("\n");
		}

		Interface::Print("Partition Block Size/Offset: %d\n", entry->GetBlockSizeOrOffset());
		Interface::Print("Partition Block Count: %d\n", entry->GetBlockCount());

		Interface::Print("File Offset (Obsolete): %d\n", entry->GetFileOffset());
		Interface::Print("File Size (Obsolete): %d\n", entry->GetFileSize());

		Interface::Print("Partition Name: %s\n", entry->GetPartitionName().c_str());
		Interface::Print("Flash Filename: %s\n", entry->GetFlashFilename().c_str());
		Interface::Print("FOTA Filename: %s\n", entry->GetFotaFilename().c_str());
	}

	Interface::Print("\n");
}

void Interface::SetStdoutErrors(bool enabled)
{
	stdoutErrors = enabled;
}
