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

//! Shared internal test fixtures and helpers.

use futures::io::AsyncRead;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use zlib_rs::{Deflate, DeflateFlush, Status};

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn block_on_tokio<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build test Tokio runtime")
        .block_on(fut)
}

pub(crate) struct TrickleReader {
    data: Vec<u8>,
    pos: usize,
    step: usize,
    reads: usize,
}

impl TrickleReader {
    pub(crate) fn new(data: Vec<u8>, step: usize) -> Self {
        Self {
            data,
            pos: 0,
            step,
            reads: 0,
        }
    }
}

impl AsyncRead for TrickleReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.reads += 1;
        if self.reads.is_multiple_of(5) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.reads.is_multiple_of(3) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "eintr")));
        }
        let n = (self.data.len() - self.pos).min(self.step).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(n))
    }
}

pub(crate) fn parse_http_range(range_hdr: Option<&str>, len: usize) -> (usize, usize) {
    match range_hdr {
        None => (0, len),
        Some(spec) => {
            let spec = spec.strip_prefix("bytes=").expect("bytes= prefix");
            let (s, e) = spec.split_once('-').expect("range separator");
            let start = s.parse::<usize>().expect("range start");
            let end = if e.is_empty() {
                len
            } else {
                (e.parse::<usize>().expect("range end") + 1).min(len)
            };
            (start, end)
        }
    }
}

pub(crate) fn compress_multi_block(data: &[u8], chunk_sizes: &[usize]) -> Vec<u8> {
    let mut def = Deflate::new(6, false, 15);
    let mut out = vec![0u8; zlib_rs::compress_bound(data.len()) + 4096];
    let mut in_off = 0usize;
    let mut out_off = 0usize;
    let mut idx = 0;
    while in_off < data.len() {
        let chunk = chunk_sizes[idx % chunk_sizes.len()].min(data.len() - in_off);
        idx += 1;
        let prev_in = def.total_in();
        let prev_out = def.total_out();
        let is_last = in_off + chunk == data.len();
        let flush = if is_last {
            DeflateFlush::Finish
        } else {
            DeflateFlush::Block
        };
        let status = def
            .compress(&data[in_off..in_off + chunk], &mut out[out_off..], flush)
            .unwrap();
        in_off += (def.total_in() - prev_in) as usize;
        out_off += (def.total_out() - prev_out) as usize;
        if is_last {
            assert_eq!(status, Status::StreamEnd);
        }
    }
    out.truncate(out_off);
    out
}
