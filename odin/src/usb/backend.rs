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

//! Selection of the USB backend implementation at runtime.

use crate::error::TransportError;

/// Runs `$body` with `$b` bound to the backend type selected by `$option`.
///
/// This is the only place that maps [`UsbBackendOption`] variants to backend
/// types. Prefer passing `$b` to generic functions over calling its methods
/// directly, since inherent methods (e.g. `MockBackend::new`) take precedence
/// over trait methods of the same name.
macro_rules! with_backend {
    ($option:expr, |$b:ident| $body:expr) => {
        match $option {
            #[cfg(feature = "nusb")]
            $crate::usb::UsbBackendOption::Nusb => {
                type $b = $crate::usb::NusbBackend;
                $body
            }
            #[cfg(feature = "rusb")]
            $crate::usb::UsbBackendOption::Libusb => {
                type $b = $crate::usb::RusbBackend;
                $body
            }
            #[cfg(feature = "serialport")]
            $crate::usb::UsbBackendOption::Vcom => {
                type $b = $crate::usb::SerialBackend;
                $body
            }
            #[cfg(mock_backend)]
            $crate::usb::UsbBackendOption::Mock => {
                type $b = $crate::usb::MockBackend;
                $body
            }
        }
    };
}
pub(crate) use with_backend;

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
    /// Mock backend.
    #[cfg(mock_backend)]
    Mock,
}

impl TryFrom<&str> for UsbBackendOption {
    type Error = TransportError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            #[cfg(feature = "rusb")]
            "libusb" => Ok(UsbBackendOption::Libusb),
            #[cfg(feature = "serialport")]
            "vcom" => Ok(UsbBackendOption::Vcom),
            #[cfg(feature = "nusb")]
            "nusb" => Ok(UsbBackendOption::Nusb),
            #[cfg(mock_backend)]
            "mock" => Ok(UsbBackendOption::Mock),
            _ => Err(TransportError::UnknownBackend(s.to_string())),
        }
    }
}

impl std::str::FromStr for UsbBackendOption {
    type Err = TransportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl UsbBackendOption {
    /// All backend options enabled in this build, in order of preference.
    pub const ALL: &'static [UsbBackendOption] = &[
        #[cfg(feature = "nusb")]
        UsbBackendOption::Nusb,
        #[cfg(feature = "rusb")]
        UsbBackendOption::Libusb,
        #[cfg(feature = "serialport")]
        UsbBackendOption::Vcom,
        #[cfg(mock_backend)]
        UsbBackendOption::Mock,
    ];

    /// Returns the string representation of the backend option.
    pub const fn to_str(self) -> &'static str {
        match self {
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => "libusb",
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => "vcom",
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => "nusb",
            #[cfg(mock_backend)]
            UsbBackendOption::Mock => "mock",
        }
    }
}

impl std::fmt::Display for UsbBackendOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_backends_round_trip() {
        assert!(!UsbBackendOption::ALL.is_empty());
        for backend in UsbBackendOption::ALL {
            let parsed = UsbBackendOption::try_from(backend.to_str()).unwrap();
            assert_eq!(parsed.to_str(), backend.to_str());
        }
    }
}
