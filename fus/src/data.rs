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

//! Transport- and concurrency-agnostic random-access byte source abstraction.

use crate::compat::{MaybeSend, MaybeSync};
use futures::io::{AsyncRead, AsyncReadExt};
use std::future::Future;
use std::io;
use std::ops::{Bound, Range, RangeBounds};
use std::sync::Arc;

/// Clamps any [`RangeBounds<u64>`] against `[0..len)` and returns `Some(start..end)` if
/// non-empty, or `None` if the range is empty or out of bounds.
pub(crate) fn resolve_range_bounds(range: impl RangeBounds<u64>, len: u64) -> Option<Range<u64>> {
    let start = match range.start_bound() {
        Bound::Unbounded => 0,
        Bound::Included(&s) => s,
        Bound::Excluded(&s) => s.checked_add(1)?,
    };
    if start >= len {
        return None;
    }
    let end = match range.end_bound() {
        Bound::Unbounded => len,
        Bound::Excluded(&e) => e.min(len),
        Bound::Included(&e) => e.saturating_add(1).min(len),
    };
    (start < end).then_some(start..end)
}

/// Concurrency- and transport-agnostic random-access byte source.
pub trait DataSource: MaybeSend + MaybeSync {
    /// Exact byte length of the source.
    fn size(&self) -> u64;

    /// Opens an async sequential reader over `range`.
    fn fetch_range(
        &self,
        range: impl RangeBounds<u64> + MaybeSend,
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
    fn size(&self) -> u64 {
        self.len() as u64
    }

    async fn fetch_range(
        &self,
        range: impl RangeBounds<u64> + MaybeSend,
    ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
        let slice = match resolve_range_bounds(range, self.len() as u64) {
            Some(r) => &self[r.start as usize..r.end as usize],
            None => &[],
        };
        Ok(slice)
    }
}

macro_rules! impl_deref_data_source {
    ($($({$($generics:tt)+})? $ty:ty),+ $(,)?) => {
        $(
            impl$(<$($generics)+>)? DataSource for $ty {
                fn size(&self) -> u64 {
                    (**self).size()
                }

                fn fetch_range(
                    &self,
                    range: impl RangeBounds<u64> + MaybeSend,
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
    Vec<u8>,
    {D: DataSource + ?Sized} &D,
    {D: DataSource + ?Sized} Arc<D>,
    {D: DataSource + ?Sized} Box<D>,
);

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn test_resolve_range_bounds() {
        assert_eq!(resolve_range_bounds(.., 100), Some(0..100));
        assert_eq!(resolve_range_bounds(.., 0), None);
        assert_eq!(resolve_range_bounds(5.., 100), Some(5..100));
        assert_eq!(resolve_range_bounds(100.., 100), None);
        assert_eq!(resolve_range_bounds(5..10, 100), Some(5..10));
        assert_eq!(resolve_range_bounds(5..200, 100), Some(5..100));
        assert_eq!(resolve_range_bounds(..10, 100), Some(0..10));
        assert_eq!(resolve_range_bounds(..0, 100), None);
        assert_eq!(resolve_range_bounds(5..=9, 100), Some(5..10));
        assert_eq!(resolve_range_bounds(..=9, 100), Some(0..10));
        assert_eq!(resolve_range_bounds(0..=u64::MAX, 100), Some(0..100));
        assert_eq!(
            resolve_range_bounds((Bound::Excluded(4), Bound::Included(9)), 100),
            Some(5..10)
        );
        assert_eq!(
            resolve_range_bounds((Bound::Excluded(u64::MAX), Bound::Unbounded), u64::MAX),
            None
        );
        assert_eq!(resolve_range_bounds(10..10, 100), None);
        #[allow(clippy::reversed_empty_ranges)]
        {
            assert_eq!(resolve_range_bounds(10..5, 100), None);
            assert_eq!(resolve_range_bounds(10..=5, 100), None);
        }
        assert_eq!(resolve_range_bounds(5..=5, 100), Some(5..6));
    }

    #[test]
    fn test_in_memory_data_sources() {
        let data: Vec<u8> = (0..64_u8).collect();
        let slice: &[u8] = &data;
        let arc: Arc<[u8]> = Arc::from(slice);
        let boxed: Box<[u8]> = slice.into();

        assert_eq!(slice.size(), 64);
        assert_eq!(data.size(), 64);
        assert_eq!(arc.size(), 64);
        assert_eq!(boxed.size(), 64);

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
