#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZonInfo {
    pub version: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ZonInfo {}

impl ZonInfo {
    pub fn new() -> Self {
        Self { version: VERSION }
    }
}

const VERSION: u32 = 0x0000001;
