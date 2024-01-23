#![no_std]

use bitflags;

pub const VERSION: u32 = 0x0000001;
pub const MAX_GROUPS: u32 = 64;
pub const MAX_BACKENDS: u32 = 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZonInfo {
    pub version: u32,
    // TODO: add attach mode, skb or driver
    // TODO: add debug log mode
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
pub struct EPFlags: u32 {
    const ENABLE = 1;
    const IPV4 = 2;
    const IPV6 = 4;
    const PORT = 8;
}
}

/// Holds the backends info (count, group id) for the endpoint that needs load balacing.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BEGroup {
    /// The backend group id
    pub gid: u64,
    /// The current backends count in this group
    pub becount: u16,
    /// The flags instructs the xdp program to update the IP or/and Port
    pub flags: EPFlags,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BEGroup {}

impl BEGroup {
    pub fn new(id: u64) -> Self {
        Self {
            gid: id,
            becount: 0_u16,
            flags: EPFlags::default(),
        }
    }
}

// TODO: add 32-bit hash for generic hashing for different ip protocols

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EP6 {
    pub address: [u8; 16],
    pub port: u16,
    pub proto: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EP6 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EP4 {
    pub address: [u8; 4],
    pub port: u16,
    pub proto: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EP4 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BEKey {
    pub gid: u16,
    pub index: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BEKey {}

impl From<u32> for BEKey {
    fn from(key: u32) -> Self {
        Self {
            gid: (key >> 16) as u16,
            index: (key & 0xFFFF) as u16,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BE {
    /// Holds both an IPv4 and IPv6 address (big-endian)
    pub address: [u8; 16],
    /// The backend listening port and it should be used
    /// only if PORT is set in the LB flags.
    /// The default value is 0 and it should be ignored regardless of
    /// the LB flag.
    pub port: u16,
    /// The group id for current backend. It allows to group backends
    /// servicing an LB frontend.
    pub gid: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BE {}
