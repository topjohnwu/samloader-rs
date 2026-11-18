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

//! Transport- and concurrency-agnostic byte source abstraction.

use crate::compat::{MaybeSend, MaybeSync};
use futures::io::{AsyncRead, AsyncReadExt};
use std::future::Future;
use std::io;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

/// Resolves any [`RangeBounds<u64>`] into `Some((start, exclusive_end))` if non-empty,
/// or `None` if the range is empty (`end <= start` or excluded `u64::MAX` start).
///
/// An `exclusive_end` of `None` means unbounded (read to the end of the source).
pub(crate) fn resolve_range_bounds(range: impl RangeBounds<u64>) -> Option<(u64, Option<u64>)> {
    let start = match range.start_bound() {
        Bound::Unbounded => 0,
        Bound::Included(&s) => s,
        Bound::Excluded(&s) => s.checked_add(1)?,
    };
    let end = match range.end_bound() {
        Bound::Unbounded => None,
        Bound::Excluded(&e) if e <= start => return None,
        Bound::Excluded(&e) => Some(e),
        Bound::Included(&e) if e < start => return None,
        Bound::Included(&e) => e.checked_add(1),
    };
    Some((start, end))
}

/// Concurrency- and transport-agnostic random-access byte source.
pub trait DataSource: MaybeSend + MaybeSync {
    /// Inclusive `(min_size, max_size)` byte length bounds of the source.
    ///
    /// Exact-size sources return `(len, len)`. Encrypted FUS streams whose trailing
    /// `1..=16` PKCS#7 padding bytes are stripped at EOF return
    /// `(enc_size.saturating_sub(16), enc_size)`.
    fn size_bounds(&self) -> (u64, u64);

    /// Opens an async sequential reader over `range`.
    fn fetch_range(
        &self,
        range: impl RangeBounds<u64> + Send,
    ) -> impl Future<Output = io::Result<impl AsyncRead + MaybeSend + Unpin>> + MaybeSend;

    /// Opens an async sequential reader over the entire source (`..`).
    fn fetch(
        &self,
    ) -> impl Future<Output = io::Result<impl AsyncRead + MaybeSend + Unpin>> + MaybeSend {
        self.fetch_range(..)
    }

    /// Reads bytes starting at `offset` into `buf`, filling `buf` completely
    /// unless the end of the source is reached first.
    fn read_at(
        &self,
        buf: &mut [u8],
        offset: u64,
    ) -> impl Future<Output = io::Result<usize>> + MaybeSend {
        async move {
            if buf.is_empty() {
                return Ok(0);
            }
            let end = offset.saturating_add(buf.len() as u64);
            let mut reader = self.fetch_range(offset..end).await?;
            let mut filled = 0;
            while filled < buf.len() {
                match reader.read(&mut buf[filled..]).await {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            Ok(filled)
        }
    }
}

impl DataSource for [u8] {
    fn size_bounds(&self) -> (u64, u64) {
        let len = self.len() as u64;
        (len, len)
    }

    async fn fetch_range(
        &self,
        range: impl RangeBounds<u64> + Send,
    ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
        let len = self.len() as u64;
        let slice = match resolve_range_bounds(range) {
            Some((start, end)) if start < len => {
                let e = end.map_or(self.len(), |e| e.min(len) as usize);
                &self[start as usize..e]
            }
            _ => &[],
        };
        Ok(slice)
    }
}

macro_rules! impl_deref_data_source {
    ($($({$($generics:tt)+})? $ty:ty => $target:ty),+ $(,)?) => {
        $(
            impl$(<$($generics)+>)? DataSource for $ty {
                fn size_bounds(&self) -> (u64, u64) {
                    (**self).size_bounds()
                }

                fn fetch_range(
                    &self,
                    range: impl RangeBounds<u64> + Send,
                ) -> impl Future<Output = io::Result<impl AsyncRead + MaybeSend + Unpin>> + MaybeSend {
                    (**self).fetch_range(range)
                }

                fn read_at(
                    &self,
                    buf: &mut [u8],
                    offset: u64,
                ) -> impl Future<Output = io::Result<usize>> + MaybeSend {
                    (**self).read_at(buf, offset)
                }
            }
        )+
    };
}

impl_deref_data_source!(
    Vec<u8> => [u8],
    {D: DataSource + ?Sized} &D => D,
    {D: DataSource + ?Sized} Arc<D> => D,
    {D: DataSource + ?Sized} Box<D> => D,
);

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn test_resolve_range_bounds() {
        assert_eq!(resolve_range_bounds(..), Some((0, None)));
        assert_eq!(resolve_range_bounds(5..), Some((5, None)));
        assert_eq!(resolve_range_bounds(5..10), Some((5, Some(10))));
        assert_eq!(resolve_range_bounds(..10), Some((0, Some(10))));
        assert_eq!(resolve_range_bounds(..0), None);
        assert_eq!(resolve_range_bounds(5..=9), Some((5, Some(10))));
        assert_eq!(resolve_range_bounds(..=9), Some((0, Some(10))));
        assert_eq!(resolve_range_bounds(0..=u64::MAX), Some((0, None)));
        assert_eq!(
            resolve_range_bounds((Bound::Excluded(4), Bound::Included(9))),
            Some((5, Some(10)))
        );
        assert_eq!(
            resolve_range_bounds((Bound::Excluded(u64::MAX), Bound::Unbounded)),
            None
        );
        assert_eq!(resolve_range_bounds(10..10), None);
        #[allow(clippy::reversed_empty_ranges)]
        {
            assert_eq!(resolve_range_bounds(10..5), None);
            assert_eq!(resolve_range_bounds(10..=5), None);
        }
        assert_eq!(resolve_range_bounds(5..=5), Some((5, Some(6))));
    }

    #[test]
    fn test_in_memory_data_sources() {
        let data: Vec<u8> = (0..64_u8).collect();
        let slice: &[u8] = &data;
        let arc: Arc<[u8]> = Arc::from(slice);
        let boxed: Box<[u8]> = slice.into();

        assert_eq!(slice.size_bounds(), (64, 64));
        assert_eq!(data.size_bounds(), (64, 64));
        assert_eq!(arc.size_bounds(), (64, 64));
        assert_eq!(boxed.size_bounds(), (64, 64));

        block_on(async {
            // fetch()
            let mut full = Vec::new();
            data.fetch()
                .await
                .unwrap()
                .read_to_end(&mut full)
                .await
                .unwrap();
            assert_eq!(full, data);

            // fetch_range() across &D, Arc<D>, and Box<D> wrappers
            let mut sub = Vec::new();
            let arc_ref = &arc;
            DataSource::fetch_range(&arc_ref, 10..=25)
                .await
                .unwrap()
                .read_to_end(&mut sub)
                .await
                .unwrap();
            assert_eq!(sub, &data[10..=25]);

            let mut clamped = Vec::new();
            boxed
                .fetch_range(50..200)
                .await
                .unwrap()
                .read_to_end(&mut clamped)
                .await
                .unwrap();
            assert_eq!(clamped, &data[50..]);

            // Empty and out-of-bounds ranges
            #[allow(clippy::reversed_empty_ranges)]
            let empty_cases = [0..0, 20..10, 64..64, 100..200];
            for r in empty_cases {
                let mut empty = Vec::new();
                slice
                    .fetch_range(r.clone())
                    .await
                    .unwrap()
                    .read_to_end(&mut empty)
                    .await
                    .unwrap();
                assert!(empty.is_empty(), "range={r:?}");
            }
            let mut oob = Vec::new();
            slice
                .fetch_range(64..)
                .await
                .unwrap()
                .read_to_end(&mut oob)
                .await
                .unwrap();
            assert!(oob.is_empty());

            // read_at()
            let mut buf = [0u8; 20];
            assert_eq!(slice.read_at(&mut buf, 12).await.unwrap(), 20);
            assert_eq!(&buf, &data[12..32]);

            assert_eq!(arc.read_at(&mut buf, 54).await.unwrap(), 10);
            assert_eq!(&buf[..10], &data[54..]);

            assert_eq!(data.read_at(&mut buf[..0], 0).await.unwrap(), 0);
            assert_eq!(data.read_at(&mut buf, 64).await.unwrap(), 0);
        });
    }
}
