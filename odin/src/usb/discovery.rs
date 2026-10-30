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

//! Discovery of Samsung devices: which connected USB devices to talk to in
//! each mode, and waiting for and pairing with them.

use crate::error::TransportError;
use crate::usb::{UsbBackend, UsbBackendOption, UsbTransfer, with_backend};
use std::time::Duration;

pub(crate) const VID_SAMSUNG: u16 = 0x04E8;
const PID_GALAXY_S: u16 = 0x6601;
const PID_GALAXY_S2: u16 = 0x685D;
const PID_DROID_CHARGE: u16 = 0x68C3;

/// VID/PID pairs that Samsung devices enumerate with in Download Mode.
const DOWNLOAD_MODE_DEVICES: &[(u16, u16)] = &[
    (VID_SAMSUNG, PID_GALAXY_S),
    (VID_SAMSUNG, PID_GALAXY_S2),
    (VID_SAMSUNG, PID_DROID_CHARGE),
];

/// Which mode a Samsung device is expected to be in.
#[derive(Clone, Copy)]
pub(crate) enum DeviceMode {
    /// Download Mode, where Odin flashing happens.
    Download,
    /// Normal mode, where the modem interface accepts AT commands.
    Normal,
}

impl DeviceMode {
    /// Returns whether a device with the given VID/PID is a Samsung device in this mode.
    fn matches(self, vid: u16, pid: u16) -> bool {
        let download = DOWNLOAD_MODE_DEVICES.contains(&(vid, pid));
        match self {
            DeviceMode::Download => download,
            DeviceMode::Normal => vid == VID_SAMSUNG && !download,
        }
    }

    /// Finds the first connected device in this mode.
    async fn find<B: UsbBackend>(self) -> Result<B::UsbDevice, TransportError> {
        B::find_device(move |vid, pid| self.matches(vid, pid)).await
    }

    /// Opens a connected device in this mode.
    ///
    /// In normal mode, other Samsung USB devices (e.g. portable SSDs) also
    /// match, so devices that do not expose a usable interface are skipped.
    async fn open<B: UsbBackend>(self) -> Result<B, TransportError> {
        match self {
            DeviceMode::Download => B::new(self.find::<B>().await?).await,
            DeviceMode::Normal => {
                match open_first_usable(|vid, pid| self.matches(vid, pid)).await {
                    Err(TransportError::DeviceNotFound) => {
                        Err(TransportError::NormalModeDeviceNotFound)
                    }
                    res => res,
                }
            }
        }
    }

    /// Checks whether a device in this mode is connected, using the selected backend.
    pub(crate) async fn find_with(
        self,
        usb_backend: UsbBackendOption,
    ) -> Result<(), TransportError> {
        with_backend!(usb_backend, |B| self.find::<B>().await.map(drop))
    }

    /// Opens a device in this mode with the selected backend.
    pub(crate) async fn open_with(
        self,
        usb_backend: UsbBackendOption,
    ) -> Result<Box<dyn UsbTransfer>, TransportError> {
        with_backend!(usb_backend, |B| Ok(Box::new(self.open::<B>().await?)))
    }
}

/// Opens the first device matching `predicate` that the backend can initialize.
///
/// Unlike [`UsbBackend::find_device`], which returns only the first match, this
/// moves on to the next match when a device fails to open, e.g. an unrelated
/// device from the same vendor without a usable CDC data interface.
async fn open_first_usable<B, P>(predicate: P) -> Result<B, TransportError>
where
    B: UsbBackend,
    P: Fn(u16, u16) -> bool + Sync,
{
    // Errors that only indicate an unsuitable device are replaced by more
    // meaningful errors (e.g. permission denied) from later candidates.
    let mut error = TransportError::DeviceNotFound;
    let mut skip = 0usize;
    loop {
        // `find_device` returns only the first match, so devices are re-enumerated
        // on every attempt and the first `skip` matches are passed over. This
        // assumes a stable enumeration order; hotplug events between attempts
        // can at worst cause a device to be retried or skipped.
        let mut seen = 0usize;
        let mut id = (0u16, 0u16);
        let device = B::find_device(|vid, pid| {
            if predicate(vid, pid) {
                seen += 1;
                if seen > skip {
                    id = (vid, pid);
                    return true;
                }
            }
            false
        })
        .await;

        let device = match device {
            Ok(device) => device,
            Err(TransportError::DeviceNotFound) => return Err(error),
            Err(e) => return Err(e),
        };

        match B::new(device).await {
            Ok(backend) => return Ok(backend),
            Err(e) => {
                crate::progress::eprintln_verbose(&format!(
                    "Skipping device {:04X}:{:04X}: {e}",
                    id.0, id.1
                ));
                if matches!(
                    error,
                    TransportError::DeviceNotFound
                        | TransportError::InterfaceConfigurationNotFound
                        | TransportError::ConfigDescriptorRetrieval
                ) {
                    error = e;
                }
            }
        }
        skip += 1;
    }
}

async fn poll_device<T, F, Fut>(wait: bool, mut f: F) -> Result<T, TransportError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, TransportError>>,
{
    let mut waiting = false;
    loop {
        match f().await {
            Ok(val) => return Ok(val),
            Err(TransportError::DeviceNotFound) if wait => {
                if !waiting {
                    crate::progress::on_event(crate::progress::FlashEvent::WaitingForDevice);
                    waiting = true;
                }
                futures_timer::Delay::new(Duration::from_secs(1)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Creates and initializes the requested USB/VCOM communication backend interface.
pub async fn create_backend(
    usb_backend: UsbBackendOption,
    wait: bool,
) -> Result<Box<dyn UsbTransfer>, TransportError> {
    poll_device(wait, || DeviceMode::Download.open_with(usb_backend)).await
}

/// Helper function to detect a compatible download-mode device on a given backend.
pub async fn detect_device(usb_backend: UsbBackendOption, wait: bool) -> bool {
    poll_device(wait, || DeviceMode::Download.find_with(usb_backend))
        .await
        .is_ok()
}

/// Helper function to prompt user pairing for a compatible download-mode device on WASM.
#[cfg(target_arch = "wasm32")]
pub async fn request_device(usb_backend: UsbBackendOption) -> Result<(), TransportError> {
    match usb_backend {
        #[cfg(feature = "nusb")]
        UsbBackendOption::Nusb => {
            let selectors: Vec<::nusb::DeviceSelector> = DOWNLOAD_MODE_DEVICES
                .iter()
                .map(|&(vid, pid)| ::nusb::DeviceSelector::all().with_vid_pid(vid, pid))
                .collect();

            ::nusb::request_device(&selectors)
                .await
                .map_err(|e| TransportError::DeviceAccess(Box::new(e)))?
                .ok_or(TransportError::DeviceNotFound)?;
            Ok(())
        }
        #[cfg(mock_backend)]
        UsbBackendOption::Mock => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::MaybeSend;
    use std::cell::RefCell;

    const PID_NORMAL: u16 = 0x6860;
    const PID_PORTABLE_SSD: u16 = 0x61F5;

    #[derive(Clone, Copy)]
    enum Open {
        Ok,
        NoInterface,
        ClaimFailed,
    }

    type FakeDevice = (u16, u16, Open);

    thread_local! {
        static DEVICES: RefCell<Vec<FakeDevice>> = const { RefCell::new(Vec::new()) };
    }

    struct FakeBackend {
        pid: u16,
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl UsbTransfer for FakeBackend {
        async fn reset(&mut self) {}
        async fn send(&mut self, _data: &[u8], _timeout: Duration) -> Result<(), TransportError> {
            Ok(())
        }
        async fn receive(
            &mut self,
            _data: &mut [u8],
            _timeout: Duration,
        ) -> Result<usize, TransportError> {
            Ok(0)
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl UsbBackend for FakeBackend {
        type UsbDevice = FakeDevice;

        async fn new(device: Self::UsbDevice) -> Result<Self, TransportError> {
            match device.2 {
                Open::Ok => Ok(Self { pid: device.1 }),
                Open::NoInterface => Err(TransportError::InterfaceConfigurationNotFound),
                Open::ClaimFailed => Err(TransportError::InterfaceClaimFailed),
            }
        }

        async fn find_device<'a, F>(mut predicate: F) -> Result<Self::UsbDevice, TransportError>
        where
            F: FnMut(u16, u16) -> bool + MaybeSend + 'a,
        {
            DEVICES
                .with_borrow(|d| d.iter().copied().find(|&(vid, pid, _)| predicate(vid, pid)))
                .ok_or(TransportError::DeviceNotFound)
        }
    }

    fn open_normal_mode(devices: &[FakeDevice]) -> Result<FakeBackend, TransportError> {
        DEVICES.set(devices.to_vec());
        futures::executor::block_on(DeviceMode::Normal.open())
    }

    #[test]
    fn test_normal_mode_skips_download_mode_and_unusable_devices() {
        let backend = open_normal_mode(&[
            (VID_SAMSUNG, PID_GALAXY_S2, Open::Ok),
            (VID_SAMSUNG, PID_PORTABLE_SSD, Open::NoInterface),
            (0x18D1, 0x4EE7, Open::Ok),
            (VID_SAMSUNG, PID_NORMAL, Open::Ok),
        ])
        .unwrap();
        assert_eq!(backend.pid, PID_NORMAL);
    }

    #[test]
    fn test_normal_mode_tries_devices_sharing_vid_pid() {
        let backend = open_normal_mode(&[
            (VID_SAMSUNG, PID_NORMAL, Open::NoInterface),
            (VID_SAMSUNG, PID_NORMAL, Open::Ok),
        ])
        .unwrap();
        assert_eq!(backend.pid, PID_NORMAL);
    }

    #[test]
    fn test_normal_mode_not_found() {
        let res = open_normal_mode(&[(VID_SAMSUNG, PID_GALAXY_S2, Open::Ok)]);
        assert!(matches!(res, Err(TransportError::NormalModeDeviceNotFound)));
    }

    #[test]
    fn test_normal_mode_prefers_meaningful_error() {
        let res = open_normal_mode(&[
            (VID_SAMSUNG, PID_NORMAL, Open::ClaimFailed),
            (VID_SAMSUNG, PID_PORTABLE_SSD, Open::NoInterface),
        ]);
        assert!(matches!(res, Err(TransportError::InterfaceClaimFailed)));

        let res = open_normal_mode(&[(VID_SAMSUNG, PID_PORTABLE_SSD, Open::NoInterface)]);
        assert!(matches!(
            res,
            Err(TransportError::InterfaceConfigurationNotFound)
        ));
    }
}
