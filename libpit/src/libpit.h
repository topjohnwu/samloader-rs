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

#ifndef LIBPIT_H
#define LIBPIT_H

#include "rust/cxx.h"
#include "libpit/src/lib.rs.h"

namespace libpit
{
	namespace PitConst
	{
		enum
		{
			kDataSize = 132,
			kPartitionNameMaxLength = 32,
			kFlashFilenameMaxLength = 32,
			kFotaFilenameMaxLength = 32
		};

		enum
		{
			kBinaryTypeApplicationProcessor = 0,
			kBinaryTypeCommunicationProcessor = 1
		};

		enum
		{
			kDeviceTypeOneNand = 0,
			kDeviceTypeFile, // FAT
			kDeviceTypeMMC,
			kDeviceTypeAll, // ?
			kDeviceTypeUFS = 8
		};

		enum
		{
			kAttributeWrite = 1,
			kAttributeSTL = 1 << 1
			/* kAttributeBML = 1 << 2 */ // ???
		};

		enum
		{
			kUpdateAttributeFota = 1,
			kUpdateAttributeSecure = 1 << 1
		};
	}
}

#endif
