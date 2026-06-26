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

#[cfg(not(any(feature = "rusb", feature = "nusb", feature = "serialport")))]
compile_error!("At least one USB backend must be enabled!");

use crate::error::OdinError;
use std::time::Duration;

#[cfg(feature = "nusb")]
use ::nusb::MaybeFuture;

#[cfg(feature = "rusb")]
use ::rusb::{Context, DeviceHandle, UsbContext};

#[cfg(feature = "serialport")]
use std::io::{Read, Write};

macro_rules! print_warning {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose {
            eprint!("WARNING: ");
            eprintln!($($arg)*);
        }
    };
}

macro_rules! print_verbose {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose {
            eprintln!($($arg)*);
        }
    };
}

pub(crate) const VID_SAMSUNG: u16 = 0x04E8;
const PID_GALAXY_S: u16 = 0x6601;
const PID_GALAXY_S2: u16 = 0x685D;
const PID_DROID_CHARGE: u16 = 0x68C3;

const SUPPORTED_DEVICES: &[(u16, u16)] = &[
    (VID_SAMSUNG, PID_GALAXY_S),
    (VID_SAMSUNG, PID_GALAXY_S2),
    (VID_SAMSUNG, PID_DROID_CHARGE),
];

#[allow(dead_code)]
const USB_CLASS_CDC_DATA: u8 = 0x0A;

/// Trait representing a duplex data transport layer for USB or serial communication.
pub trait UsbTransfer {
    /// Resets the transport connection state and buffers.
    fn reset(&mut self);
    /// Sends a buffer of data across the transport with a timeout.
    fn send_data(&mut self, data: &[u8], timeout: i32, retry: bool) -> bool;
    /// Receives data from the transport into a buffer, returning the number of bytes read.
    fn receive_data(&mut self, data: &mut [u8], timeout: i32, retry: bool) -> i32;
}

/// Trait representing a backend factory and device locator for USB or serial transports.
pub trait UsbBackend: Sized + UsbTransfer {
    /// The associated device type identifier.
    type UsbDevice;

    /// Instantiates a new backend session wrapper for a given device.
    fn new(device: Self::UsbDevice, verbose: bool) -> Result<Self, OdinError>;
    /// Searches for a matching connected device based on a predicate.
    fn find_device<F>(wait: bool, predicate: F) -> Result<Self::UsbDevice, OdinError>
    where
        F: FnMut(u16, u16) -> bool;

    /// Searches for a connected device in Download Mode.
    fn find_download_device(wait: bool) -> Result<Self::UsbDevice, OdinError> {
        Self::find_device(wait, |vid, pid| SUPPORTED_DEVICES.contains(&(vid, pid)))
    }
}

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

/// Supported USB backend options.
#[derive(Debug, Clone, Copy)]
pub enum UsbBackendOption {
    /// libusb (rusb) backend.
    #[cfg(feature = "rusb")]
    Libusb,
    /// Virtual COM port (serialport) backend.
    #[cfg(feature = "serialport")]
    Vcom,
    /// nusb backend.
    #[cfg(feature = "nusb")]
    Nusb,
}

impl TryFrom<&str> for UsbBackendOption {
    type Error = OdinError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            #[cfg(feature = "rusb")]
            "libusb" => Ok(UsbBackendOption::Libusb),
            #[cfg(feature = "serialport")]
            "vcom" => Ok(UsbBackendOption::Vcom),
            #[cfg(feature = "nusb")]
            "nusb" => Ok(UsbBackendOption::Nusb),
            _ => Err(OdinError::ParseError(format!("Unknown USB backend: {s}"))),
        }
    }
}

impl std::str::FromStr for UsbBackendOption {
    type Err = OdinError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl From<UsbBackendOption> for &'static str {
    fn from(opt: UsbBackendOption) -> Self {
        match opt {
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => "libusb",
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => "vcom",
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => "nusb",
        }
    }
}

impl std::fmt::Display for UsbBackendOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", <&'static str>::from(*self))
    }
}

/// Creates and initializes the requested USB/VCOM communication backend interface.
pub fn create_backend(
    usb_backend: UsbBackendOption,
    verbose: bool,
    wait: bool,
) -> Result<Box<dyn UsbTransfer>, OdinError> {
    match usb_backend {
        #[cfg(feature = "serialport")]
        UsbBackendOption::Vcom => {
            let device = SerialBackend::find_download_device(wait)?;
            let backend = SerialBackend::new(device, verbose)?;
            Ok(Box::new(backend))
        }
        #[cfg(feature = "nusb")]
        UsbBackendOption::Nusb => {
            let device = NusbBackend::find_download_device(wait)?;
            let backend = NusbBackend::new(device, verbose)?;
            Ok(Box::new(backend))
        }
        #[cfg(feature = "rusb")]
        UsbBackendOption::Libusb => {
            let device = RusbBackend::find_download_device(wait)?;
            let backend = RusbBackend::new(device, verbose)?;
            Ok(Box::new(backend))
        }
    }
}

/// Helper function to detect a compatible download-mode device on a given backend.
pub fn detect_device(usb_backend: UsbBackendOption, wait: bool) -> bool {
    match usb_backend {
        #[cfg(feature = "serialport")]
        UsbBackendOption::Vcom => SerialBackend::find_download_device(wait).is_ok(),
        #[cfg(feature = "nusb")]
        UsbBackendOption::Nusb => NusbBackend::find_download_device(wait).is_ok(),
        #[cfg(feature = "rusb")]
        UsbBackendOption::Libusb => RusbBackend::find_download_device(wait).is_ok(),
    }
}
