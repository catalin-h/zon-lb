#![no_std]

use bitflags;

pub const VERSION: u32 = 0x0000001;
pub const MAX_LB: u32 = 64;
pub const MAX_BACKENDS: u32 = 1024;

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

bitflags::bitflags! {
#[derive(Clone, Copy, Debug, Default)]
pub struct LBFlags: u32 {
    const ENABLE = 1;
    const IPV4 = 2;
    const IPV6 = 4;
    const PORT = 8;
}
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LB {
    first: usize,
    last: usize,
    flags: LBFlags,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LB {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EP6 {
    address: [u8; 16],
    port: u16,
    proto: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EP6 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EP4 {
    address: u32,
    port: u16,
    proto: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EP4 {}
