// Copyright 2026 Google LLC
// Copyright 2010-2017 Benjamin Dobell, Glass Echidna
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const VERSION: &str = "v2.2.2";

const RELEASE_INFO: &str = "Heimdall v2.2.2\n\n\
Copyright (c) 2010-2017 Benjamin Dobell, Glass Echidna https://glassechidna.com.au\n\
Copyright (c) 2021-2024 Henrik Grimler\n\
This software is provided free of charge. Copying and redistribution is encouraged.\n\n";

const EXTRA_INFO: &str = "Heimdall utilises libusb for all USB communication:\n    https://www.libusb.info/\n\nlibusb is licensed under the LGPL-2.1:\n    https://www.gnu.org/licenses/licenses.html#LGPL\n\n";

pub(crate) fn print_version() {
    println!("{}", VERSION);
}

pub(crate) fn print_full_info() {
    print!("{}", RELEASE_INFO);
    print!("{}", EXTRA_INFO);
}
