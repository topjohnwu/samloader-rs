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
#include "Arguments.h"
#include "BridgeManager.h"
#include "EnableTFlashPacket.h"
#include "EndModemFileTransferPacket.h"
#include "EndPhoneFileTransferPacket.h"
#include "FlashAction.h"
#include "Heimdall.h"
#include "Interface.h"
#include "SessionSetupResponse.h"
#include "TotalBytesPacket.h"
#include "Utility.h"

using namespace std;
using namespace libpit;
using namespace Heimdall;

const char *FlashAction::usage = "Action: flash\n\
Arguments:\n\
    [--<partition name> <filename> ...]\n\
    [--<partition identifier> <filename> ...]\n\
    [--pit <filename>] [--verbose] [--no-reboot] [--resume] [--stdout-errors]\n\
    [--usb-log-level <none/error/warning/debug>] [--skip-size-check] [--wait]\n\
  or:\n\
    --repartition --pit <filename> [--<partition name> <filename> ...]\n\
    [--<partition identifier> <filename> ...] [--verbose] [--no-reboot]\n\
    [--resume] [--stdout-errors] [--usb-log-level <none/error/warning/debug>]\n\
    [--tflash] [--skip-size-check] [--wait]\n\
Description: Flashes one or more firmware files to your phone. Partition names\n\
    (or identifiers) can be obtained by executing the print-pit action.\n\
    With --wait Heimdall waits until a compatible device is connected.\n\
    T-Flash mode allows to flash the inserted SD-card instead of the internal MMC.\n\
    Use --skip-size-check to not verify that files fit in the specified partition.\n\
Note: --no-reboot causes the device to remain in download mode after the action\n\
      is completed. If you wish to perform another action whilst remaining in\n\
      download mode, then the following action must specify the --resume flag.\n\
WARNING: If you're repartitioning it's strongly recommended you specify\n\
        all files at your disposal.\n";

struct PartitionFile
{
	const char *argumentName;
	FILE *file;
	unsigned long fileSize;

	PartitionFile(const char *argumentName, FILE *file, unsigned long fileSize)
	{
		this->argumentName = argumentName;
		this->file = file;
		this->fileSize = fileSize;
	}
};

struct PartitionFlashInfo
{
	const PitEntry *pitEntry;
	FILE *file;

	PartitionFlashInfo(const PitEntry *pitEntry, FILE *file)
	{
		this->pitEntry = pitEntry;
		this->file = file;
	}
};

static bool openFiles(Arguments& arguments, vector<PartitionFile>& partitionFiles, FILE *& pitFile)
{
	// Open PIT file

	const StringArgument *pitArgument = static_cast<const StringArgument *>(arguments.GetArgument("pit"));

	if (pitArgument)
	{
		pitFile = FileOpen(pitArgument->GetValue().c_str(), "rb");

		if (!pitFile)
		{
			Interface::PrintError("Failed to open file \"%s\"\n", pitArgument->GetValue().c_str());
			return (false);
		}
	}

	// Open partition files

	for (vector<const Argument *>::const_iterator it = arguments.GetArguments().begin(); it != arguments.GetArguments().end(); it++)
	{
		const string& argumentName = (*it)->GetName();

		// The only way an argument could exist without being in the argument types map is if it's a wild-card.
		// The "%d" wild-card refers to a partition by identifier, where as the "%s" wild-card refers to a
		// partition by name.

		if (arguments.GetArgumentTypes().find(argumentName) == arguments.GetArgumentTypes().end())
		{
			const StringArgument *stringArgument = static_cast<const StringArgument *>(*it);
			FILE *file = FileOpen(stringArgument->GetValue().c_str(), "rb");
			if (!file)
			{
				Interface::PrintError("Failed to open file \"%s\"\n", stringArgument->GetValue().c_str());
				return (false);
			}

			FileSeek(file, 0, SEEK_END);
			unsigned long fileSize = (unsigned long)FileTell(file);
			FileRewind(file);

			partitionFiles.push_back(PartitionFile(argumentName.c_str(), file, fileSize));
		}
	}

	return (true);
}

static void closeFiles(vector<PartitionFile>& partitionFiles, FILE *& pitFile)
{
	// Close PIT file

	if (pitFile)
	{
		FileClose(pitFile);
		pitFile = nullptr;
	}

	// Close partition files

	for (vector<PartitionFile>::const_iterator it = partitionFiles.begin(); it != partitionFiles.end(); it++)
		FileClose(it->file);

	partitionFiles.clear();
}

static bool sendTotalTransferSize(BridgeManager *bridgeManager, const vector<PartitionFile>& partitionFiles, FILE *pitFile, bool repartition)
{
	unsigned long totalBytes = 0;

	for (vector<PartitionFile>::const_iterator it = partitionFiles.begin(); it != partitionFiles.end(); it++)
	{
		totalBytes += it->fileSize;
	}

	if (repartition)
	{
		FileSeek(pitFile, 0, SEEK_END);
		totalBytes += (unsigned long)FileTell(pitFile);
		FileRewind(pitFile);
	}

	bool success;

	TotalBytesPacket *totalBytesPacket = new TotalBytesPacket(totalBytes);
	success = bridgeManager->SendPacket(totalBytesPacket);
	delete totalBytesPacket;

	if (!success)
	{
		Interface::PrintError("Failed to send total bytes packet!\n");
		return (false);
	}

	SessionSetupResponse *totalBytesResponse = new SessionSetupResponse();
	success = bridgeManager->ReceivePacket(totalBytesResponse);
	int totalBytesResult = totalBytesResponse->GetResult();
	delete totalBytesResponse;

	if (!success)
	{
		Interface::PrintError("Failed to receive session total bytes response!\n");
		return (false);
	}

	if (totalBytesResult != 0)
	{
		Interface::PrintError("Unexpected session total bytes response!\nExpected: 0\nReceived:%d\n", totalBytesResult);
		return (false);
	}

	return (true);
}

static bool setupPartitionFlashInfo(const vector<PartitionFile>& partitionFiles, const PitData *pitData, vector<PartitionFlashInfo>& partitionFlashInfos)
{
	for (vector<PartitionFile>::const_iterator it = partitionFiles.begin(); it != partitionFiles.end(); it++)
	{
		const PitEntry *pitEntry = nullptr;

		// Was the argument a partition identifier?
		unsigned int partitionIdentifier;

		if (Utility::ParseUnsignedInt(partitionIdentifier, it->argumentName) == kNumberParsingStatusSuccess)
		{
			pitEntry = pitData->FindEntry(partitionIdentifier);

			if (!pitEntry)
			{
				Interface::PrintError("No partition with identifier \"%s\" exists in the specified PIT.\n", it->argumentName);
				return (false);
			}
		}
		else
		{
			// The argument must be an partition name e.g. "ZIMAGE"
			pitEntry = pitData->FindEntry(it->argumentName);

			if (!pitEntry)
			{
				Interface::PrintError("Partition \"%s\" does not exist in the specified PIT.\n", it->argumentName);
				return (false);
			}
		}

		partitionFlashInfos.push_back(PartitionFlashInfo(pitEntry, it->file));
	}

	return (true);
}

static bool flashPitData(BridgeManager *bridgeManager, const PitData *pitData)
{
	Interface::Print("Uploading PIT\n");

	if (bridgeManager->SendPitData(pitData))
	{
		Interface::Print("PIT upload successful\n\n");
		return (true);
	}
	else
	{
		Interface::PrintError("PIT upload failed!\n\n");
		return (false);
	}
}

static bool flashFile(BridgeManager *bridgeManager, const PartitionFlashInfo& partitionFlashInfo)
{
	if (static_cast<BinaryType>(partitionFlashInfo.pitEntry->GetBinaryType()) == BinaryType::CommunicationProcessor) // Modem
	{
		Interface::Print("Uploading %s\n", partitionFlashInfo.pitEntry->GetPartitionName().c_str());

		if (bridgeManager->SendFile(partitionFlashInfo.file, EndModemFileTransferPacket::kDestinationModem,
			partitionFlashInfo.pitEntry->GetDeviceType()))
		{
			Interface::Print("%s upload successful\n\n", partitionFlashInfo.pitEntry->GetPartitionName().c_str());
			return (true);
		}
		else
		{
			Interface::PrintError("%s upload failed!\n\n", partitionFlashInfo.pitEntry->GetPartitionName().c_str());
			return (false);
		}
	}
	else // static_cast<BinaryType>(partitionFlashInfo.pitEntry->GetBinaryType()) == BinaryType::ApplicationProcessor
	{
		Interface::Print("Uploading %s\n", partitionFlashInfo.pitEntry->GetPartitionName().c_str());

		if (bridgeManager->SendFile(partitionFlashInfo.file, EndPhoneFileTransferPacket::kDestinationPhone,
			partitionFlashInfo.pitEntry->GetDeviceType(), partitionFlashInfo.pitEntry->GetIdentifier()))
		{
			Interface::Print("%s upload successful\n\n", partitionFlashInfo.pitEntry->GetPartitionName().c_str());
			return (true);
		}
		else
		{
			Interface::PrintError("%s upload failed!\n\n", partitionFlashInfo.pitEntry->GetPartitionName().c_str());
			return (false);
		}
	}
}

static bool flashPartitions(BridgeManager *bridgeManager, const vector<PartitionFile>& partitionFiles, const PitData *pitData, bool repartition, bool skipSizeCheck)
{
	vector<PartitionFlashInfo> partitionFlashInfos;

	// Map the files being flashed to partitions stored in the PIT file.
	if (!setupPartitionFlashInfo(partitionFiles, pitData, partitionFlashInfos))
		return (false);

	/* Verify that the files we want to flash fit in partitions */
	if (!skipSizeCheck)
	{
		for (vector<PartitionFile>::const_iterator it = partitionFiles.begin(); it != partitionFiles.end(); it++)
		{
			unsigned int partitionIdentifier;
			const PitEntry *part;
			if (Utility::ParseUnsignedInt(partitionIdentifier, it->argumentName) == kNumberParsingStatusSuccess)
			{
				part = pitData->FindEntry(partitionIdentifier);

				if (!part)
				{
					Interface::PrintError("No partition with identifier \"%s\" exists in the specified PIT.\n", it->argumentName);
					return (false);

				}
			} else {
				part = pitData->FindEntry(it->argumentName);

				if (!part)
				{
					Interface::PrintError("Partition \"%s\" does not exist in the specified PIT.\n", it->argumentName);
					return (false);

				}
			}

			DeviceType deviceType = static_cast<DeviceType>(part->GetDeviceType());

			if (deviceType != DeviceType::MMC &&
			    deviceType != DeviceType::UFS)
				continue;
			unsigned long partitionSize = part->GetBlockCount();
			unsigned int blockSize = 512;
			if (deviceType == DeviceType::UFS)
				blockSize = 4096;
			if (partitionSize > 0 && it->fileSize > partitionSize*blockSize)
			{
				Interface::PrintError("%s partition is too small for given file. Use --skip-size-check to flash anyways.\n",
						      it->argumentName);
				return (false);
			}
		}
	}

	// If we're repartitioning then we need to flash the PIT file first (if it is listed in the PIT file).
	if (repartition)
	{
		if (!flashPitData(bridgeManager, pitData))
			return (false);
	}

	// Flash partitions in the same order that arguments were specified in.
	for (vector<PartitionFlashInfo>::const_iterator it = partitionFlashInfos.begin(); it != partitionFlashInfos.end(); it++)
	{
		if (!flashFile(bridgeManager, *it))
			return (false);
	}
	return (true);
}

static PitData *getPitData(BridgeManager *bridgeManager, FILE *pitFile, bool repartition)
{
	PitData *pitData;
	PitData *localPitData = nullptr;

	// If a PIT file was passed as an argument then we must unpack it.

	if (pitFile)
	{
		// Load the local pit file into memory.

		FileSeek(pitFile, 0, SEEK_END);
		unsigned long localPitFileSize = (unsigned long)FileTell(pitFile);
		FileRewind(pitFile);

		unsigned char *pitFileBuffer = new unsigned char[localPitFileSize];
		memset(pitFileBuffer, 0, localPitFileSize);

		int dataRead = fread(pitFileBuffer, 1, localPitFileSize, pitFile);

		if (dataRead > 0)
		{
			FileRewind(pitFile);

			localPitData = new_pit_data().into_raw();
			localPitData->Unpack({pitFileBuffer, (size_t)localPitFileSize});

			delete [] pitFileBuffer;
		}
		else
		{
			Interface::PrintError("Failed to read PIT file.\n");

			delete [] pitFileBuffer;
			return (nullptr);
		}
	}

	if (repartition)
	{
		// Use the local PIT file data.
		pitData = localPitData;
	}
	else
	{
		// If we're not repartitioning then we need to retrieve the device's PIT file and unpack it.
		unsigned char *pitFileBuffer;
		int devicePitFileSize = bridgeManager->DownloadPitFile(&pitFileBuffer);
		if (devicePitFileSize == 0)
			return (nullptr);

		pitData = new_pit_data().into_raw();
		pitData->Unpack({pitFileBuffer, (size_t)devicePitFileSize});

		delete [] pitFileBuffer;

		if (localPitData != nullptr)
		{
			// The user has specified a PIT without repartitioning, we should verify the local and device PIT data match!
			bool pitsMatch = pitData->Matches(*localPitData);
			rust::Box<PitData>::from_raw(const_cast<PitData *>(localPitData));

			if (!pitsMatch)
			{
				Interface::Print("Local and device PIT files don't match and repartition wasn't specified!\n");
				Interface::PrintError("Flash aborted!\n");
				return (nullptr);
			}
		}
	}

	return (pitData);
}

static bool enableTFlash(BridgeManager *bridgeManager)
{
	bool success;

	EnableTFlashPacket *enableTFlashPacket = new EnableTFlashPacket();
	success = bridgeManager->SendPacket(enableTFlashPacket);
	delete enableTFlashPacket;

	if (!success)
	{
		Interface::PrintError("Failed to send T-Flash packet!\n");
		return false;
	}

	SessionSetupResponse *enableTFlashResponse = new SessionSetupResponse();
	success = bridgeManager->ReceivePacket(enableTFlashResponse, 5000);
	unsigned int result = enableTFlashResponse->GetResult();
	delete enableTFlashResponse;

	if (!success)
	{
		Interface::PrintError("Failed to receive T-Flash response!\n");
		return false;
	}

	if (result)
	{
		Interface::PrintError("Unexpected T-Flash response!\nExpected: 0\nReceived: %d\n", result);
		return false;
	}

	return true;
}

int FlashAction::Execute(int argc, char **argv)
{
	// Setup argument types

	map<string, ArgumentType> argumentTypes;
	map<string, string> shortArgumentAliases;

	argumentTypes["repartition"] = kArgumentTypeFlag;

	argumentTypes["no-reboot"] = kArgumentTypeFlag;
	argumentTypes["resume"] = kArgumentTypeFlag;
	argumentTypes["verbose"] = kArgumentTypeFlag;
	argumentTypes["stdout-errors"] = kArgumentTypeFlag;
	argumentTypes["usb-log-level"] = kArgumentTypeString;
	argumentTypes["wait"] = kArgumentTypeFlag;
	argumentTypes["tflash"] = kArgumentTypeFlag;
	argumentTypes["skip-size-check"] = kArgumentTypeFlag;

	argumentTypes["pit"] = kArgumentTypeString;
	shortArgumentAliases["pit"] = "pit";

	// Add wild-cards "%d" and "%s", for partition identifiers and partition names respectively.
	argumentTypes["%d"] = kArgumentTypeString;
	shortArgumentAliases["%d"] = "%d";

	argumentTypes["%s"] = kArgumentTypeString;
	shortArgumentAliases["%s"] = "%s";

	map<string, string> argumentAliases;
	argumentAliases["PIT"] = "pit"; // Map upper-case PIT argument (i.e. partition name) to known lower-case pit argument.

	// Handle arguments

	Arguments arguments(argumentTypes, shortArgumentAliases, argumentAliases);

	if (!arguments.ParseArguments(argc, argv, 2))
	{
		Interface::Print(FlashAction::usage);
		return (0);
	}

	bool reboot = arguments.GetArgument("no-reboot") == nullptr;
	bool resume = arguments.GetArgument("resume") != nullptr;
	bool verbose = arguments.GetArgument("verbose") != nullptr;
	bool tflash = arguments.GetArgument("tflash") != nullptr;
	bool waitForDevice = arguments.GetArgument("wait") != nullptr;
	// If we are flashing to sdcard we can ignore size of partition in PIT
	bool skipSizeCheck = (arguments.GetArgument("skip-size-check") != nullptr) || tflash;

	if (arguments.GetArgument("stdout-errors") != nullptr)
		Interface::SetStdoutErrors(true);

	const StringArgument *usbLogLevelArgument = static_cast<const StringArgument *>(arguments.GetArgument("usb-log-level"));

	BridgeManager::UsbLogLevel usbLogLevel = BridgeManager::UsbLogLevel::Default;

	if (usbLogLevelArgument)
	{
		const string& usbLogLevelString = usbLogLevelArgument->GetValue();

		if (usbLogLevelString.compare("none") == 0 || usbLogLevelString.compare("NONE") == 0)
		{
			usbLogLevel = BridgeManager::UsbLogLevel::None;
		}
		else if (usbLogLevelString.compare("error") == 0 || usbLogLevelString.compare("ERROR") == 0)
		{
			usbLogLevel = BridgeManager::UsbLogLevel::Error;
		}
		else if (usbLogLevelString.compare("warning") == 0 || usbLogLevelString.compare("WARNING") == 0)
		{
			usbLogLevel = BridgeManager::UsbLogLevel::Warning;
		}
		else if (usbLogLevelString.compare("info") == 0 || usbLogLevelString.compare("INFO") == 0)
		{
			usbLogLevel = BridgeManager::UsbLogLevel::Info;
		}
		else if (usbLogLevelString.compare("debug") == 0 || usbLogLevelString.compare("DEBUG") == 0)
		{
			usbLogLevel = BridgeManager::UsbLogLevel::Debug;
		}
		else
		{
			Interface::Print("Unknown USB log level: %s\n\n", usbLogLevelString.c_str());
			Interface::Print(FlashAction::usage);
			return (0);
		}
	}

	const StringArgument *pitArgument = static_cast<const StringArgument *>(arguments.GetArgument("pit"));

	bool repartition = arguments.GetArgument("repartition") != nullptr;

	if (repartition && !pitArgument)
	{
		Interface::Print("If you wish to repartition then a PIT file must be specified.\n\n");
		Interface::Print(FlashAction::usage);
		return (0);
	}

	// Open files

	FILE *pitFile = nullptr;
	vector<PartitionFile> partitionFiles;

	if (!openFiles(arguments, partitionFiles, pitFile))
	{
		closeFiles(partitionFiles, pitFile);
		return (1);
	}

	if (partitionFiles.size() == 0)
	{
		Interface::Print(FlashAction::usage);
		return (0);
	}

	// Info

	Interface::PrintReleaseInfo();
	Sleep(1000);

	// Perform flash

	BridgeManager *bridgeManager = new BridgeManager(verbose, waitForDevice);
	bridgeManager->SetUsbLogLevel(usbLogLevel);

	if (bridgeManager->Initialise(resume) != BridgeManager::kInitialiseSucceeded || !bridgeManager->BeginSession())
	{
		closeFiles(partitionFiles, pitFile);
		delete bridgeManager;

		return (1);
	}

	if (tflash && !enableTFlash(bridgeManager))
	{
		closeFiles(partitionFiles, pitFile);
		delete bridgeManager;

		return (1);
	}

	bool success = sendTotalTransferSize(bridgeManager, partitionFiles, pitFile, repartition);

	if (success)
	{
		PitData *pitData = getPitData(bridgeManager, pitFile, repartition);

		if (pitData)
			success = flashPartitions(bridgeManager, partitionFiles,
						  pitData, repartition,
						  skipSizeCheck);
		else
			success = false;

		rust::Box<PitData>::from_raw(const_cast<PitData *>(pitData));
	}

	if (!bridgeManager->EndSession(reboot))
		success = false;

	delete bridgeManager;

	closeFiles(partitionFiles, pitFile);

	return (success ? 0 : 1);
}
