#[derive(Clone, Debug)]
pub struct SystemTimeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Duration {
    secs: u64,
}

impl Duration {
    pub fn as_secs(&self) -> u64 {
        self.secs
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SystemTime(u64);

pub const UNIX_EPOCH: SystemTime = SystemTime(0);

impl SystemTime {
    pub fn duration_since(&self, time: SystemTime) -> Result<Duration, SystemTimeError> {
        if self.0 - time.0 > 0 {
            Ok(Duration {
                secs: self.0 - time.0,
            })
        } else {
            Err(SystemTimeError)
        }
    }

    pub fn as_secs(&self) -> u64 {
        self.0
    }

    pub fn now() -> SystemTime {
        now()
    }
}

pub fn now() -> SystemTime {
    SystemTime(sys_time::get_sys_time().unwrap_or(0) as u64)
}
