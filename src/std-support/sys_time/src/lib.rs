// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
// use chrono::NaiveDate;

use core::convert::TryFrom;

use rtc::read_rtc;
use time::{Date, Month, PrimitiveDateTime, Time};

pub mod rtc;

pub fn get_sys_time() -> Option<i64> {
    let data_time = read_rtc()?;

    let date_time = PrimitiveDateTime::new(
        Date::from_calendar_date(
            data_time.year as i32,
            Month::try_from(data_time.month).ok()?,
            data_time.day,
        )
        .ok()?,
        Time::from_hms(data_time.hour, data_time.minute, data_time.second).ok()?,
    );
    Some(date_time.assume_utc().unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::get_sys_time;
    #[test]
    fn it_works() {
        assert_ne!(get_sys_time().unwrap(), 0);
    }
}
