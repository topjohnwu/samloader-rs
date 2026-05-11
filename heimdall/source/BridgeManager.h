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

#ifndef BRIDGEMANAGER_H
#define BRIDGEMANAGER_H

// C Standard Library
#include <cstdio>
#include <vector>

// libpit
#include "heimdall/libpit/src/lib.rs.h"

// Heimdall
#include "Heimdall.h"

struct libusb_context;
struct libusb_device;
struct libusb_device_handle;

namespace Heimdall
{
	class InboundPacket;
	class OutboundPacket;

	enum class InitialiseResult
	{
		Succeeded = 0,
		Failed,
		DeviceNotDetected
	};

	enum class EmptyTransferMode
	{
		None = 0,
		Before = 1,
		After = 1 << 1,
		BeforeAndAfter = Before | After
	};

	class BridgeManager
	{
		private:

			bool verbose;
			bool waitForDevice;

			libusb_context *libusbContext;
			libusb_device_handle *deviceHandle;
			libusb_device *heimdallDevice;

			int interfaceIndex;
			int altSettingIndex;
			int inEndpoint;
			int outEndpoint;

			bool interfaceClaimed;

#ifdef OS_LINUX

			bool detachedDriver;

#endif

			unsigned int fileTransferSequenceMaxLength;
			unsigned int fileTransferPacketSize;
			unsigned int fileTransferSequenceTimeout;

			int usbLogLevel;

			InitialiseResult FindDeviceInterface(void);
			bool ClaimDeviceInterface(void);
			bool SetupDeviceInterface(void);
			void ReleaseDeviceInterface(void);

			bool InitialiseProtocol(void);

			bool SendBulkTransfer(unsigned char *data, int length, int timeout, bool retry = true) const;
			int ReceiveBulkTransfer(unsigned char *data, int length, int timeout, bool retry = true) const;

		public:

			BridgeManager(bool verbose, bool waitForDevice);
			~BridgeManager();

			bool DetectDevice(void);
			InitialiseResult Initialise(void);

			bool BeginSession(void);
			bool EndSession(void) const;

			bool SendPacket(OutboundPacket *packet, int timeout = DEFAULT_TIMEOUT_SEND, EmptyTransferMode emptyTransferMode = EmptyTransferMode::After) const;
			bool ReceivePacket(InboundPacket *packet, int timeout = DEFAULT_TIMEOUT_RECEIVE, EmptyTransferMode emptyTransferMode = EmptyTransferMode::None) const;

			bool RequestDeviceType(unsigned int request, int *result) const;

			bool SendPitData(const libpit::PitData& pitData) const;
			std::vector<unsigned char> ReceivePitFile(void) const;
			std::vector<unsigned char> DownloadPitFile(void) const; // Thin wrapper around ReceivePitFile() with additional logging.

			bool SendFile(FILE *file, unsigned int destination, unsigned int deviceType, unsigned int fileIdentifier = 0xFFFFFFFF) const;

			void SetUsbLogLevel(rust::Str usb_log_level);

			bool IsVerbose(void) const
			{
				return (verbose);
			}
	};
}

#endif
