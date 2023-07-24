use chrono::NaiveDate;
use chrono::Duration as OldDuration;
use std::iter::FusedIterator;
use std::ops::{Range, RangeInclusive};
use crate::utils::date_range_chunks::DateRangeChunks;

mod date_range_chunks {
    use super::*;
    use std::ops::Range;
    use std::cmp;
    use std::convert::TryInto;

    #[derive(Debug, Clone)]
    pub struct DateRangeChunks {
        remaining: Range<NaiveDate>,
        step_days: OldDuration,
    }

    impl DateRangeChunks {
        pub fn new(remaining: Range<NaiveDate>, step_days: u64) -> Self {
            Self {
                remaining,
                step_days: OldDuration::days(step_days.try_into().expect("Out of range"))
            }
        }
    }

    impl Iterator for DateRangeChunks {
        type Item = Range<NaiveDate>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining.is_empty() {
                return None;
            }

            let start = self.remaining.start;
            let end = cmp::min(start + self.step_days, self.remaining.end);
            self.remaining = end..self.remaining.end;

            Some(start..end)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let dur = (self.remaining.end - self.remaining.start).num_days();
            let step = self.step_days.num_days();
            let size = (dur + step) / step;
            (size as usize, Some(size as usize))
        }
    }

    impl ExactSizeIterator for DateRangeChunks {}
}

pub trait DateRangeChunksExt {
    fn chunks(self, step_days: u64) -> date_range_chunks::DateRangeChunks;
}

impl DateRangeChunksExt for Range<NaiveDate> {
    fn chunks(self, step_days: u64) -> DateRangeChunks {
        DateRangeChunks::new(self, step_days)
    }
}

impl DateRangeChunksExt for RangeInclusive<NaiveDate> {
    fn chunks(self, step_days: u64) -> DateRangeChunks {
        let remaining = self.start().to_owned()..self.end().succ();
        DateRangeChunks::new(remaining, step_days)
    }
}

#[derive(Debug, Clone)]
pub enum TakeWhileThen<I, P, T, TIntoIter>
where
    T: FnOnce(TIntoIter::Item, I) -> TIntoIter,
    TIntoIter: IntoIterator
{
    While(Option<(I, P, T)>),
    Then {
        iter: TIntoIter::IntoIter,
    }
}

impl<I, P, T, TIntoIter> TakeWhileThen<I, P, T, TIntoIter>
where
    T: FnOnce(TIntoIter::Item, I) -> TIntoIter,
    TIntoIter: IntoIterator
{
    fn new(iter: I, predicate: P, then: T) -> Self {
        Self::While(Some((iter, predicate, then)))
    }
}

impl<I, P, T, TIntoIter> Iterator for TakeWhileThen<I, P, T, TIntoIter>
where
    I: Iterator,
    P: FnMut(&I::Item) -> bool,
    T: FnOnce(TIntoIter::Item, I) -> TIntoIter,
    TIntoIter: IntoIterator<Item=I::Item>
{
    type Item = I::Item;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::While(this) => {
                let x = if let Some((iter, predicate, _)) = this {
                    let x = iter.next()?;
                    if predicate(&x) {
                        return Some(x);
                    }
                    x
                } else {
                    return None;
                };
                if let Some((iter, _, then)) = this.take() {
                    let iter = then(x, iter).into_iter();
                    *self = Self::Then{ iter };
                    self.next()
                } else {
                    None
                }
            },
            Self::Then {iter} => {
                iter.next()
            },
        }
    }
}

impl<I, P, T, TIntoIter> FusedIterator for TakeWhileThen<I, P, T, TIntoIter>
where
    I: FusedIterator,
    P: FnMut(&I::Item) -> bool,
    T: FnOnce(TIntoIter::Item, I) -> TIntoIter,
    TIntoIter: IntoIterator<Item=I::Item>,
    TIntoIter::IntoIter: FusedIterator
{
}

pub trait TakeWhileThenExt : Iterator {
    fn take_while_then<P, T, TIntoIter>(self, predicate: P, then: T) -> TakeWhileThen<Self, P, T, TIntoIter>
    where
        Self: Sized,
        P: FnMut(&Self::Item) -> bool,
        T: FnOnce(Self::Item, Self) -> TIntoIter,
        TIntoIter: IntoIterator<Item=Self::Item>,
    {
        TakeWhileThen::new(self, predicate, then)
    }
}

impl<I> TakeWhileThenExt for I where I: Iterator { }


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn date_chunks() {
        let min_date = NaiveDate::from_ymd(2020, 1, 1);
        let max_date = NaiveDate::from_ymd(2020, 1, 5);
        let step_days = 2;

        let mut chunks = (min_date..=max_date).chunks(step_days);
        assert_eq!(chunks.next(), Some(NaiveDate::from_ymd(2020, 1, 1)..NaiveDate::from_ymd(2020, 1, 3)));
        assert_eq!(chunks.next(), Some(NaiveDate::from_ymd(2020, 1, 3)..NaiveDate::from_ymd(2020, 1, 5)));
        assert_eq!(chunks.next(), Some(NaiveDate::from_ymd(2020, 1, 5)..NaiveDate::from_ymd(2020, 1, 6)));
        assert_eq!(chunks.next(), None);
    }
}
