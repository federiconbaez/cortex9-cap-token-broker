use crate::ports::Clock;
use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Manually driven clock for tests.
#[derive(Debug, Default)]
pub struct ManualClock(Cell<u64>);

impl ManualClock {
    pub fn at(t: u64) -> Self {
        Self(Cell::new(t))
    }
    pub fn set(&self, t: u64) {
        self.0.set(t);
    }
    pub fn advance(&self, s: u64) {
        self.0.set(self.0.get() + s);
    }
}

impl Clock for ManualClock {
    fn now_unix(&self) -> u64 {
        self.0.get()
    }
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now_unix(&self) -> u64 {
        (**self).now_unix()
    }
}
