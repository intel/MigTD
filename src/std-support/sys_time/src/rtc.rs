// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Untrusted time get from CMOS/RTC device commonly seen on x86 I/O port 0x70/0x71

use lazy_static::lazy_static;
use x86_64::instructions::port::{PortRead, PortWrite};

const CMOS_ADDRESS_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16 = 0x71;

// Select the register through port 0x70, and read the value from port 0x71
const CMOS_SECOND_REGISTER: u8 = 0x00;
const CMOS_MINUTE_REGISTER: u8 = 0x02;
const CMOS_HOUR_REGISTER: u8 = 0x04;
const CMOS_DAY_REGISTER: u8 = 0x07;
const CMOS_MONTH_REGISTER: u8 = 0x08;
const CMOS_YEAR_REGISTER: u8 = 0x09;
const CMOS_STATUS_REGISTER_A: u8 = 0x0A;
const CMOS_STATUS_REGISTER_B: u8 = 0x0B;

const CMOS_NMI_DISABLE_BIT: u8 = 1 << 7;
// Status Register A, Bit 7
const CMOS_UPDATE_IN_PROGRESS_FLAG: u8 = 1 << 7;
// Status Register B, Bit 1
const CMOS_24_HOUR_FORMAT_FLAG: u8 = 1 << 1;
// Status Register B, Bit 2
const CMOS_BINARY_MODE_FLAG: u8 = 1 << 2;

// In 12 hour mode, if the hour is pm, then the 0x80 bit is set on the hour byte
const CMOS_PM_BIT: u8 = 0x80;

const CMOS_YEARS_OFFSET: u16 = 2000;

// Format bits of status register b cannot be changed.
lazy_static! {
    static ref STATUS_REGISTER_B: u8 = read_cmos_register(CMOS_STATUS_REGISTER_B);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub second: u8,
    pub minute: u8,
    /// Hours in current day, 24 hour format.
    pub hour: u8,
    pub day: u8,
    pub month: u8,
    pub year: u16,
}

pub fn read_rtc() -> Option<DateTime> {
    // It is possible to read the time and date while an update is in progress and get inconsistent
    // values, for example, at 9:00 o'clock we might get 8:59, or 8:60, or 8:00, or 9:00.
    // The solution here is to read all the values we need twice, and make sure the update_in_progress
    // flag is clear before each reading. If the two values are the same, then we get a correct value.

    // Retry for up to 500 times for the RTC to be ready, it takes about 100ms.
    let mut retries = 500;
    while retries > 0 {
        // Wait until RTC finishes its update
        while get_update_in_progress_flag() > 0 {}
        let first_read = read_date_time();

        // If the flag is set before our second reading, we can't get the same value
        if get_update_in_progress_flag() > 0 {
            retries -= 1;
            continue;
        }
        let second_read = read_date_time();

        // Compare the values read out twice. If they are equal, then we get a correct value
        if first_read == second_read {
            return Some(first_read);
        } else {
            retries -= 1;
        }
    }

    None
}

/// Convert a value in BCD format into binary mode
const fn bcd_to_binary(bcd: u8) -> u8 {
    (bcd & 0xF) + ((bcd / 16) * 10)
}

fn is_24_hour_format() -> bool {
    *STATUS_REGISTER_B & CMOS_24_HOUR_FORMAT_FLAG > 0
}

fn is_binary_mode() -> bool {
    *STATUS_REGISTER_B & CMOS_BINARY_MODE_FLAG > 0
}

fn read_cmos_register(reg: u8) -> u8 {
    unsafe {
        u8::write_to_port(CMOS_ADDRESS_PORT, CMOS_NMI_DISABLE_BIT | reg);
        u8::read_from_port(CMOS_DATA_PORT)
    }
}

fn get_update_in_progress_flag() -> u8 {
    read_cmos_register(CMOS_STATUS_REGISTER_A) & CMOS_UPDATE_IN_PROGRESS_FLAG
}

fn read_datetime_register(register: u8) -> u8 {
    let value = read_cmos_register(register);

    if is_binary_mode() {
        value
    } else {
        bcd_to_binary(value)
    }
}

fn read_hour_register() -> u8 {
    let mut hour = read_cmos_register(CMOS_HOUR_REGISTER);
    if !is_binary_mode() {
        // Mask the possible PM flag
        hour = ((hour & 0xF) + (((hour & !CMOS_PM_BIT) / 16) * 10)) | (hour & CMOS_PM_BIT);
    }

    // Convert from 12 hour format to 24 hour format if necessary
    if !is_24_hour_format() && (hour & CMOS_PM_BIT != 0) {
        // midnight is 12, 1am is 1
        ((hour & !CMOS_PM_BIT) + 12) % 24
    } else {
        hour
    }
}

fn read_date_time() -> DateTime {
    let year = CMOS_YEARS_OFFSET + read_datetime_register(CMOS_YEAR_REGISTER) as u16;
    let month = read_datetime_register(CMOS_MONTH_REGISTER);
    let day = read_datetime_register(CMOS_DAY_REGISTER);
    let minute = read_datetime_register(CMOS_MINUTE_REGISTER);
    let second = read_datetime_register(CMOS_SECOND_REGISTER);
    let hour = read_hour_register();

    DateTime {
        year,
        month,
        day,
        minute,
        second,
        hour,
    }
}
