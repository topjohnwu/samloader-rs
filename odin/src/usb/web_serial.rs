// Copyright 2026 John "topjohnwu" Wu
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

//! Serial communication backend using the [Web Serial API](https://wicg.github.io/serial/).

use super::{UsbBackend, UsbTransfer};
use crate::compat::MaybeSend;
use crate::error::TransportError;
use futures::future::{Either, select};
use futures_timer::Delay;
use js_sys::{Promise, Uint8Array};
use std::cell::RefCell;
use std::time::Duration;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    ReadableStreamDefaultReader, ReadableStreamReadResult, Serial, SerialOptions, SerialPort,
    SerialPortFilter, SerialPortRequestOptions, Window, WorkerGlobalScope,
    WritableStreamDefaultWriter,
};

/// The baud rate to open ports with. USB CDC ACM devices ignore it, but Web
/// Serial requires one.
const BAUD_RATE: u32 = 115_200;

/// The size of the read and write buffers, which holds a full Odin data
/// packet. Web Serial defaults to only 255 bytes.
const BUFFER_SIZE: u32 = 0x100000;

/// How long to wait for a dropped backend to close its port.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

thread_local! {
    /// Ports that dropped backends are closing. Closing is asynchronous, and a
    /// port cannot be opened again until it is closed.
    static CLOSING: RefCell<Vec<Promise>> = const { RefCell::new(Vec::new()) };
}

/// An error reported by the Web Serial API.
#[derive(Debug)]
struct WebSerialError(String);

impl WebSerialError {
    fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }

    /// Returns the name of a JavaScript error, e.g. `NotFoundError`.
    fn name_of(e: &JsValue) -> Option<String> {
        e.dyn_ref::<js_sys::Error>().map(|e| e.name().into())
    }
}

impl From<JsValue> for WebSerialError {
    fn from(e: JsValue) -> Self {
        if let Some(err) = e.dyn_ref::<js_sys::Error>() {
            Self(format!(
                "{}: {}",
                String::from(err.name()),
                String::from(err.message())
            ))
        } else if let Some(s) = e.as_string() {
            Self(s)
        } else {
            Self(format!("{e:?}"))
        }
    }
}

impl std::fmt::Display for WebSerialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WebSerialError {}

/// Maps a JavaScript error from a transfer.
fn js_error(e: JsValue) -> TransportError {
    TransportError::backend(WebSerialError::from(e))
}

/// Maps a JavaScript error from accessing the Web Serial API.
fn access_error(e: JsValue) -> TransportError {
    TransportError::DeviceAccess(Box::new(WebSerialError::from(e)))
}

fn port_closed() -> TransportError {
    TransportError::backend(WebSerialError::new("Serial port is closed"))
}

/// Returns `navigator.serial` from either a window or a worker.
fn serial() -> Result<Serial, TransportError> {
    let global = js_sys::global();
    let serial = if let Some(window) = global.dyn_ref::<Window>() {
        window.navigator().serial()
    } else if let Some(scope) = global.dyn_ref::<WorkerGlobalScope>() {
        scope.navigator().serial()
    } else {
        return Err(TransportError::DeviceAccess(Box::new(WebSerialError::new(
            "Could not obtain Window or WorkerGlobalScope",
        ))));
    };

    if serial.is_undefined() {
        return Err(TransportError::DeviceAccess(Box::new(WebSerialError::new(
            "Web Serial is not available",
        ))));
    }
    Ok(serial)
}

/// Waits for dropped backends to close their ports.
async fn wait_for_closing_ports() {
    for closing in CLOSING.take() {
        let _ = select(JsFuture::from(closing), Delay::new(CLOSE_TIMEOUT)).await;
    }
}

/// Prompts the user to grant access to a serial port matching one of the
/// `(vendor ID, product ID)` filters, where a `None` product ID matches any
/// product of the vendor.
pub(crate) async fn request_port(filters: &[(u16, Option<u16>)]) -> Result<(), TransportError> {
    let filters: Vec<SerialPortFilter> = filters
        .iter()
        .map(|&(vid, pid)| {
            let filter = SerialPortFilter::new();
            filter.set_usb_vendor_id(vid);
            if let Some(pid) = pid {
                filter.set_usb_product_id(pid);
            }
            filter
        })
        .collect();
    let options = SerialPortRequestOptions::new();
    options.set_filters(&filters);

    match JsFuture::from(serial()?.request_port_with_options(&options)).await {
        Ok(_) => Ok(()),
        // The user dismissed the prompt without selecting a port.
        Err(e) if WebSerialError::name_of(&e).as_deref() == Some("NotFoundError") => {
            Err(TransportError::DeviceNotFound)
        }
        Err(e) => Err(access_error(e)),
    }
}

/// Serial communication backend using the Web Serial API.
///
/// Browsers only expose ports the user has granted access to, so a port must
/// first be paired with [`request_device`](crate::request_device) or
/// [`request_reboot_device`](crate::request_reboot_device).
pub struct WebSerialBackend {
    port: SerialPort,
    /// The reader locking the readable stream, acquired on first read.
    reader: Option<ReadableStreamDefaultReader>,
    writer: WritableStreamDefaultWriter,
    /// A read that timed out, which the next receive resumes. Cancelling it
    /// instead would drop the data it may still return.
    pending_read: Option<JsFuture>,
    /// The part of the last chunk that did not fit in the receive buffer.
    leftover: Option<Uint8Array>,
    /// An error from a read after data was already received, which the next
    /// receive reports.
    deferred_error: Option<TransportError>,
}

impl WebSerialBackend {
    /// Starts reading the next chunk, acquiring a reader if needed.
    fn start_read(&mut self) -> Result<JsFuture, TransportError> {
        let reader = match self.reader.take() {
            Some(reader) => reader,
            None => {
                let readable = self.port.readable();
                if readable.is_null() {
                    return Err(port_closed());
                }
                ReadableStreamDefaultReader::new(&readable).map_err(js_error)?
            }
        };
        let read = JsFuture::from(reader.read());
        self.reader = Some(reader);
        Ok(read)
    }

    /// Releases the reader after the stream it locks is closed or errored.
    ///
    /// After a non-fatal error such as a parity error, the port replaces its
    /// readable stream, which the next read acquires a new reader for.
    fn release_reader(&mut self) {
        if let Some(reader) = self.reader.take() {
            reader.release_lock();
        }
    }

    /// Waits up to `timeout` for the next chunk of data from the port.
    async fn read_chunk(&mut self, timeout: Duration) -> Result<Uint8Array, TransportError> {
        let read = match self.pending_read.take() {
            Some(read) => read,
            None => self.start_read()?,
        };

        let result = match select(read, Delay::new(timeout)).await {
            Either::Left((result, _)) => result,
            Either::Right(((), read)) => {
                self.pending_read = Some(read);
                return Err(TransportError::Timeout);
            }
        };

        match result {
            Ok(result) => {
                let result: ReadableStreamReadResult = result.unchecked_into();
                if result.get_done().unwrap_or(false) {
                    self.release_reader();
                    return Err(port_closed());
                }
                Ok(result.get_value().unchecked_into())
            }
            Err(e) => {
                self.release_reader();
                Err(js_error(e))
            }
        }
    }

    /// Copies the start of `chunk` into `data`, keeping the rest for the next
    /// receive, and returns the number of bytes copied.
    fn copy_chunk(&mut self, chunk: Uint8Array, data: &mut [u8]) -> usize {
        let len = chunk.length();
        let n = len.min(data.len() as u32);
        chunk.subarray(0, n).copy_to(&mut data[..n as usize]);
        if n < len {
            self.leftover = Some(chunk.subarray(n, len));
        }
        n as usize
    }
}

#[async_trait::async_trait(?Send)]
impl UsbBackend for WebSerialBackend {
    type UsbDevice = SerialPort;

    async fn new(port: Self::UsbDevice) -> Result<Self, TransportError> {
        let info = port.get_info();
        print_verbose!(
            "           VID:PID: {:04X}:{:04X}",
            info.get_usb_vendor_id().unwrap_or_default(),
            info.get_usb_product_id().unwrap_or_default()
        );

        wait_for_closing_ports().await;

        let options = SerialOptions::new(BAUD_RATE);
        options.set_buffer_size(BUFFER_SIZE);
        JsFuture::from(port.open(&options)).await.map_err(|e| {
            TransportError::Setup(
                "Failed to open serial port".into(),
                Box::new(WebSerialError::from(e)),
            )
        })?;

        let writer = match port.writable().get_writer() {
            Ok(writer) => writer,
            Err(e) => {
                // Nothing locks the streams yet, so the port can be closed right away.
                CLOSING.with_borrow_mut(|c| c.push(port.close().unchecked_into()));
                return Err(TransportError::Setup(
                    "Failed to set up serial port".into(),
                    Box::new(WebSerialError::from(e)),
                ));
            }
        };

        Ok(Self {
            port,
            reader: None,
            writer,
            pending_read: None,
            leftover: None,
            deferred_error: None,
        })
    }

    async fn find_device<'a, F>(mut predicate: F) -> Result<Self::UsbDevice, TransportError>
    where
        F: FnMut(u16, u16) -> bool + MaybeSend + 'a,
    {
        let ports = JsFuture::from(serial()?.get_ports())
            .await
            .map_err(access_error)?;

        for port in ports.iter() {
            let port: SerialPort = port.unchecked_into();
            let info = port.get_info();
            // Ports that are not USB devices (e.g. Bluetooth) have no USB IDs.
            if let (Some(vid), Some(pid)) = (info.get_usb_vendor_id(), info.get_usb_product_id())
                && predicate(vid, pid)
            {
                return Ok(port);
            }
        }

        Err(TransportError::DeviceNotFound)
    }
}

#[async_trait::async_trait(?Send)]
impl UsbTransfer for WebSerialBackend {
    async fn reset(&mut self) {
        self.leftover = None;
        self.deferred_error = None;
        while self.read_chunk(Duration::from_millis(10)).await.is_ok() {}
    }

    async fn send(&mut self, data: &[u8], timeout: Duration) -> Result<(), TransportError> {
        // A serial port is a byte stream, which has no zero-length packets.
        if data.is_empty() {
            return Ok(());
        }

        let write = JsFuture::from(self.writer.write_with_chunk(&Uint8Array::from(data)));
        match select(write, Delay::new(timeout)).await {
            Either::Left((result, _)) => result.map(drop).map_err(js_error),
            // The write stays queued in the stream and completes in the background.
            Either::Right(_) => Err(TransportError::Timeout),
        }
    }

    async fn receive(
        &mut self,
        data: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransportError> {
        if data.is_empty() {
            return Ok(0);
        }
        if let Some(e) = self.deferred_error.take() {
            return Err(e);
        }

        let chunk = match self.leftover.take() {
            Some(chunk) => chunk,
            None => self.read_chunk(timeout).await?,
        };
        let mut received = self.copy_chunk(chunk, data);

        // Chunk boundaries do not necessarily match USB packets, so also take
        // any data that has already arrived without waiting for more. A read
        // that has not completed yet is resumed by the next receive, and any
        // other error is reported by it, as data was already received.
        while received < data.len() {
            match self.read_chunk(Duration::ZERO).await {
                Ok(chunk) => received += self.copy_chunk(chunk, &mut data[received..]),
                Err(TransportError::Timeout) => break,
                Err(e) => {
                    self.deferred_error = Some(e);
                    break;
                }
            }
        }

        Ok(received)
    }
}

impl Drop for WebSerialBackend {
    fn drop(&mut self) {
        let port = self.port.clone();
        let reader = self.reader.take();
        let writer = self.writer.clone();

        let closing = wasm_bindgen_futures::future_to_promise(async move {
            if let Some(reader) = reader {
                // Cancelling settles any pending read, so the lock can then
                // be released.
                let _ = JsFuture::from(reader.cancel()).await;
                reader.release_lock();
            }
            writer.release_lock();
            if let Err(e) = JsFuture::from(port.close()).await {
                print_warning!("Failed to close serial port: {}", WebSerialError::from(e));
            }
            Ok(JsValue::UNDEFINED)
        });
        CLOSING.with_borrow_mut(|c| c.push(closing));
    }
}
