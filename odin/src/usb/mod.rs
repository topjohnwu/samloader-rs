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

#[cfg(not(any(real_backend, feature = "mock", test)))]
compile_error!("At least one USB backend must be enabled!");

#[cfg_attr(not(real_backend), allow(unused_macros))]
macro_rules! print_warning {
    ($($arg:tt)*) => {
        crate::progress::eprintln(&format!("WARNING: {}", format_args!($($arg)*)));
    };
}

macro_rules! print_verbose {
    ($($arg:tt)*) => {
        crate::progress::println_verbose(|| format!($($arg)*));
    };
}

mod backend;
mod discovery;
mod transport;

pub use backend::UsbBackendOption;
pub(crate) use backend::with_backend;
pub use discovery::DeviceMode;
#[cfg(all(target_arch = "wasm32", any(feature = "nusb", feature = "serialport")))]
pub(crate) use discovery::VID_SAMSUNG;
#[cfg(target_arch = "wasm32")]
pub use discovery::request_device;
pub use discovery::{create_backend, detect_device};
#[cfg(any(feature = "nusb", feature = "rusb"))]
pub(crate) use transport::USB_CLASS_CDC_DATA;
pub(crate) use transport::UsbBackend;
pub use transport::UsbTransfer;

#[cfg(feature = "rusb")]
pub(crate) use rusb::RusbBackend;

#[cfg(feature = "rusb")]
mod rusb;

#[cfg(all(feature = "serialport", not(target_arch = "wasm32")))]
pub(crate) use serial::SerialBackend;

#[cfg(all(feature = "serialport", not(target_arch = "wasm32")))]
mod serial;

#[cfg(all(feature = "serialport", target_arch = "wasm32"))]
pub(crate) use web_serial::WebSerialBackend;

#[cfg(all(feature = "serialport", target_arch = "wasm32"))]
pub(crate) use web_serial::request_port;

#[cfg(all(feature = "serialport", target_arch = "wasm32"))]
mod web_serial;

/// The backend behind [`UsbBackendOption::Vcom`] on the current target.
#[cfg(all(feature = "serialport", not(target_arch = "wasm32")))]
pub(crate) type VcomBackend = SerialBackend;

/// The backend behind [`UsbBackendOption::Vcom`] on the current target.
#[cfg(all(feature = "serialport", target_arch = "wasm32"))]
pub(crate) type VcomBackend = WebSerialBackend;

#[cfg(feature = "nusb")]
pub(crate) use nusb::NusbBackend;

#[cfg(feature = "nusb")]
mod nusb;

#[cfg(any(feature = "mock", test))]
mod mock;

#[cfg(any(feature = "mock", test))]
pub(crate) use mock::MockBackend;

#[cfg(test)]
pub(crate) use mock::{DeviceProfile, MockEvent, yield_now};
