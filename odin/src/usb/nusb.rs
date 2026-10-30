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

use super::USB_CLASS_CDC_DATA;
use super::{UsbBackend, UsbTransfer};
use crate::compat::MaybeSend;
use crate::error::TransportError;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ::nusb::transfer::{Buffer, BulkOrInterrupt, Completion, EndpointDirection};
use futures_timer::Delay;

struct TransferFuture<'a, EpType: BulkOrInterrupt, Dir: EndpointDirection> {
    ep: &'a mut ::nusb::Endpoint<EpType, Dir>,
    delay: Delay,
    #[cfg(not(target_arch = "wasm32"))]
    cancelled: bool,
    #[cfg(target_arch = "wasm32")]
    pending_buf: Option<Buffer>,
}

impl<'a, EpType: BulkOrInterrupt, Dir: EndpointDirection> Future
    for TransferFuture<'a, EpType, Dir>
{
    type Output = Completion;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Poll::Ready(completion) = this.ep.poll_next_complete(cx) {
                return Poll::Ready(completion);
            }
            if !this.cancelled && Pin::new(&mut this.delay).poll(cx).is_ready() {
                this.ep.cancel_all();
                this.cancelled = true;
                if let Poll::Ready(completion) = this.ep.poll_next_complete(cx) {
                    return Poll::Ready(completion);
                }
            }
            Poll::Pending
        }
        #[cfg(target_arch = "wasm32")]
        {
            if let Poll::Ready(completion) = this.ep.poll_next_complete(cx) {
                if completion.status.is_err()
                    && let Some(buf) = this.pending_buf.take()
                {
                    this.ep.submit(buf);
                    if let Poll::Ready(completion) = this.ep.poll_next_complete(cx) {
                        return Poll::Ready(completion);
                    }
                } else {
                    return Poll::Ready(completion);
                }
            }
            this.pending_buf = None;
            if Pin::new(&mut this.delay).poll(cx).is_ready() {
                return Poll::Ready(Completion {
                    buffer: Buffer::new(0),
                    actual_len: 0,
                    status: Err(::nusb::transfer::TransferError::Cancelled),
                });
            }
            Poll::Pending
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn drain_pending<EpType: BulkOrInterrupt, Dir: EndpointDirection>(
    ep: &mut ::nusb::Endpoint<EpType, Dir>,
) -> Result<(), ()> {
    ep.cancel_all();
    while ep.pending() > 0 {
        let mut delay = Delay::new(Duration::from_secs(1));
        let completed = futures::future::poll_fn(|cx| {
            if let Poll::Ready(_completion) = ep.poll_next_complete(cx) {
                Poll::Ready(true)
            } else if Pin::new(&mut delay).poll(cx).is_ready() {
                Poll::Ready(false)
            } else {
                Poll::Pending
            }
        })
        .await;

        if !completed {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn wait_pending<EpType: BulkOrInterrupt, Dir: EndpointDirection>(
    ep: &mut ::nusb::Endpoint<EpType, Dir>,
    timeout: Duration,
) -> Completion {
    TransferFuture {
        ep,
        delay: Delay::new(timeout),
        pending_buf: None,
    }
    .await
}

async fn transfer_async<EpType: BulkOrInterrupt, Dir: EndpointDirection>(
    ep: &mut ::nusb::Endpoint<EpType, Dir>,
    buf: Buffer,
    timeout: Duration,
) -> Completion {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if ep.pending() > 0 && drain_pending(ep).await.is_err() {
            return Completion {
                buffer: buf,
                actual_len: 0,
                status: Err(::nusb::transfer::TransferError::Cancelled),
            };
        }
        ep.submit(buf);
        TransferFuture {
            ep,
            delay: Delay::new(timeout),
            cancelled: false,
        }
        .await
    }
    #[cfg(target_arch = "wasm32")]
    {
        let submit_now = ep.pending() == 0;
        let mut pending_buf = Some(buf);
        if submit_now && let Some(b) = pending_buf.take() {
            ep.submit(b);
        }
        TransferFuture {
            ep,
            delay: Delay::new(timeout),
            pending_buf,
        }
        .await
    }
}

/// Maps an `nusb` transfer error. Transfers are only cancelled when they time
/// out, or when an earlier transfer could not be drained in time.
fn transfer_error(e: ::nusb::transfer::TransferError) -> TransportError {
    match e {
        ::nusb::transfer::TransferError::Cancelled => TransportError::Timeout,
        e => TransportError::backend(e),
    }
}

/// USB communication backend using `nusb`.
pub struct NusbBackend {
    ep_in: ::nusb::Endpoint<::nusb::transfer::Bulk, ::nusb::transfer::In>,
    ep_out: ::nusb::Endpoint<::nusb::transfer::Bulk, ::nusb::transfer::Out>,
    product: Option<String>,
}

impl NusbBackend {
    fn print_device_info(device: &::nusb::DeviceInfo) {
        if let Some(manufacturer) = device.manufacturer_string() {
            print_verbose!("      Manufacturer: \"{}\"", manufacturer);
        }
        if let Some(product) = device.product_string() {
            print_verbose!("           Product: \"{}\"", product);
        }
        if let Some(serial) = device.serial_number() {
            print_verbose!("         Serial No: \"{}\"", serial);
        }

        print_verbose!("\n      device class: {}", device.class());
        print_verbose!(
            "           VID:PID: {:04X}:{:04X}",
            device.vendor_id(),
            device.product_id()
        );
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl UsbBackend for NusbBackend {
    type UsbDevice = ::nusb::DeviceInfo;

    async fn new(device: Self::UsbDevice) -> Result<Self, TransportError> {
        let handle = device
            .open()
            .await
            .map_err(|e| TransportError::DeviceAccess(Box::new(e)))?;

        // Traverse configuration and select the class USB_CLASS_CDC_DATA interface with 2 endpoints
        let mut interface_index = -1;
        let mut alt_setting_index = -1;
        let mut in_endpoint = 0;
        let mut out_endpoint = 0;

        if let Ok(config) = handle.active_configuration() {
            for interface in config.interface_alt_settings() {
                let mut in_endpoint_address = None;
                let mut out_endpoint_address = None;

                for endpoint in interface.endpoints() {
                    let addr = endpoint.address();
                    if addr & 0x80 != 0 {
                        in_endpoint_address = Some(addr);
                    } else {
                        out_endpoint_address = Some(addr);
                    }
                }

                if interface_index < 0
                    && interface.endpoints().count() == 2
                    && interface.class() == USB_CLASS_CDC_DATA
                    && let (Some(in_addr), Some(out_addr)) =
                        (in_endpoint_address, out_endpoint_address)
                {
                    interface_index = interface.interface_number() as i32;
                    alt_setting_index = interface.alternate_setting() as i32;
                    in_endpoint = in_addr;
                    out_endpoint = out_addr;
                }
            }
        }

        if interface_index < 0 {
            return Err(TransportError::InterfaceConfigurationNotFound);
        }

        Self::print_device_info(&device);

        let interface = handle
            .detach_and_claim_interface(interface_index as u8)
            .await
            .map_err(|_| TransportError::InterfaceClaimFailed)?;

        if alt_setting_index != 0 {
            interface
                .set_alt_setting(alt_setting_index as u8)
                .await
                .map_err(|_| TransportError::InterfaceSetupFailed)?;
        }

        let ep_in = interface
            .endpoint::<::nusb::transfer::Bulk, ::nusb::transfer::In>(in_endpoint)
            .map_err(|e| TransportError::Setup("Failed to open IN endpoint".into(), Box::new(e)))?;
        let ep_out = interface
            .endpoint::<::nusb::transfer::Bulk, ::nusb::transfer::Out>(out_endpoint)
            .map_err(|e| {
                TransportError::Setup("Failed to open OUT endpoint".into(), Box::new(e))
            })?;

        let product = device.product_string().map(|s| s.to_string());

        Ok(Self {
            ep_in,
            ep_out,
            product,
        })
    }

    async fn find_device<'a, F>(mut predicate: F) -> Result<Self::UsbDevice, TransportError>
    where
        F: FnMut(u16, u16) -> bool + MaybeSend + 'a,
    {
        if let Ok(devices) = ::nusb::list_devices().await {
            for device in devices {
                if predicate(device.vendor_id(), device.product_id()) {
                    return Ok(device);
                }
            }
        }
        Err(TransportError::DeviceNotFound)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl UsbTransfer for NusbBackend {
    async fn reset(&mut self) {
        if let Err(e) = self.ep_in.clear_halt().await {
            print_warning!("Failed to clear IN endpoint halt: {}", e);
        }
        if let Err(e) = self.ep_out.clear_halt().await {
            print_warning!("Failed to clear OUT endpoint halt: {}", e);
        }

        #[cfg(target_arch = "wasm32")]
        {
            if self.ep_in.pending() > 0 {
                let _ = wait_pending(&mut self.ep_in, Duration::from_millis(10)).await;
            }
            if self.ep_out.pending() > 0 {
                let _ = wait_pending(&mut self.ep_out, Duration::from_millis(10)).await;
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let max_packet_size = self.ep_in.max_packet_size();
            let buf_size = if max_packet_size > 0 {
                max_packet_size
            } else {
                1024
            };
            loop {
                let buf = Buffer::new(buf_size);
                let completion =
                    transfer_async(&mut self.ep_in, buf, Duration::from_millis(10)).await;
                match completion.status {
                    Ok(()) if completion.actual_len > 0 => continue,
                    _ => break,
                }
            }
        }
    }

    async fn send(&mut self, data: &[u8], timeout: Duration) -> Result<(), TransportError> {
        #[cfg(target_arch = "wasm32")]
        if self.ep_out.pending() > 0 {
            let _ = wait_pending(&mut self.ep_out, timeout).await;
            if self.ep_out.pending() > 0 {
                return Err(TransportError::Timeout);
            }
        }
        let buf = Buffer::from(data.to_vec());
        let completion = transfer_async(&mut self.ep_out, buf, timeout).await;
        completion.status.map_err(transfer_error)?;
        if completion.actual_len != data.len() {
            return Err(TransportError::ShortWrite {
                sent: completion.actual_len,
                expected: data.len(),
            });
        }
        Ok(())
    }

    async fn receive(
        &mut self,
        data: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransportError> {
        let max_packet_size = self.ep_in.max_packet_size().max(1);
        let requested_len = data.len().max(1).next_multiple_of(max_packet_size);
        let mut total_copied = 0;

        loop {
            let rem_req_len = (requested_len - total_copied).max(max_packet_size);
            let buf = Buffer::new(rem_req_len);
            let completion = transfer_async(&mut self.ep_in, buf, timeout).await;
            if let Err(e) = completion.status {
                return if total_copied > 0 {
                    Ok(total_copied)
                } else {
                    Err(transfer_error(e))
                };
            }
            let to_copy = std::cmp::min(completion.actual_len, data.len() - total_copied);
            data[total_copied..total_copied + to_copy]
                .copy_from_slice(&completion.buffer[..to_copy]);
            total_copied += to_copy;

            let prev_req_len = completion.buffer.requested_len();
            if prev_req_len < rem_req_len
                && completion.actual_len == prev_req_len
                && total_copied < data.len()
            {
                continue;
            }

            return Ok(total_copied);
        }
    }

    fn product_name(&self) -> Option<&str> {
        self.product.as_deref()
    }
}
