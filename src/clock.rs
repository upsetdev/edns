//! A wall clock that tests can freeze and advance.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, Default)]
pub struct Clock(Option<Arc<Mutex<SystemTime>>>);

impl Clock {
    /// The real system clock.
    pub fn system() -> Self {
        Clock(None)
    }

    pub fn now(&self) -> SystemTime {
        match &self.0 {
            None => SystemTime::now(),
            Some(t) => *t.lock().unwrap(),
        }
    }

    /// A clock frozen at `t` until advanced.
    #[cfg(test)]
    pub fn fixed(t: SystemTime) -> Self {
        Clock(Some(Arc::new(Mutex::new(t))))
    }

    #[cfg(test)]
    pub fn advance(&self, d: Duration) {
        let t = self.0.as_ref().expect("advance on the system clock");
        *t.lock().unwrap() += d;
    }
}

/// Seconds since the Unix epoch, saturating at zero for pre-epoch times.
pub fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `later - earlier`, or zero if the clock went backwards.
pub fn since(later: SystemTime, earlier: SystemTime) -> Duration {
    later.duration_since(earlier).unwrap_or_default()
}
