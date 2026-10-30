// Copyright 2026 John "topjohnwu" Wu
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

#[cfg(not(any(real_backend, mock_backend)))]
compile_error!("At least one USB backend must be enabled!");

#[cfg_attr(not(real_backend), allow(unused_macros))]
macro_rules! print_warning {
    ($($arg:tt)*) => {
        crate::progress::eprintln_verbose(&format!("WARNING: {}", format_args!($($arg)*)));
    };
}

macro_rules! print_verbose {
    ($($arg:tt)*) => {
        crate::progress::eprintln_verbose(&format!($($arg)*));
    };
}

mod backend;
mod discovery;
mod transport;

pub use backend::UsbBackendOption;
pub(crate) use backend::with_backend;
pub(crate) use discovery::DeviceMode;
#[cfg(target_arch = "wasm32")]
pub(crate) use discovery::VID_SAMSUNG;
#[cfg(target_arch = "wasm32")]
pub use discovery::request_device;
pub use discovery::{create_backend, detect_device};
#[cfg(any(feature = "nusb", feature = "rusb"))]
pub(crate) use transport::USB_CLASS_CDC_DATA;
pub use transport::{UsbBackend, UsbTransfer};

#[cfg(feature = "rusb")]
pub use rusb::RusbBackend;

#[cfg(feature = "rusb")]
mod rusb;

#[cfg(feature = "serialport")]
pub use serial::SerialBackend;

#[cfg(feature = "serialport")]
mod serial;

#[cfg(feature = "nusb")]
pub use nusb::NusbBackend;

#[cfg(feature = "nusb")]
mod nusb;

#[cfg(mock_backend)]
#[allow(unused_imports)]
pub use mock::{DeviceProfile, DeviceProfileBuilder, MockBackend, MockEvent};

#[cfg(test)]
pub(crate) use mock::yield_now;

#[cfg(mock_backend)]
mod mock;
