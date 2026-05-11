/* Copyright 2026 Google LLC
 Copyright (c) 2010-2017 Benjamin Dobell, Glass Echidna
 Copyright (c) 2021-2024 Henrik Grimler

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

#ifndef ACTIONINTERFACES_H
#define ACTIONINTERFACES_H

#include <string>
#include <vector>
#include "heimdall/src/main.rs.h"
#include "BridgeManager.h"

namespace Heimdall
{
	int action_close_pc_screen(bool verbose, bool stdout_errors, rust::Str usb_log_level);
	int action_detect(bool verbose, bool wait, bool stdout_errors, rust::Str usb_log_level);
	int action_download_pit(rust::Str output, bool verbose, bool wait, bool stdout_errors, rust::Str usb_log_level);
	int action_print_pit(rust::Str file, bool verbose, bool wait, bool stdout_errors, rust::Str usb_log_level);
	int action_flash(bool repartition, bool verbose, bool wait, bool stdout_errors, rust::Str usb_log_level, bool skip_size_check, rust::Str pit, const rust::Vec<PartitionArg>& partitions);
	int action_info();
	int action_version();
}

#endif
