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

/// Holds the group data that the xdp program needs to load balance between backends.
/// The HasMap containing this data is shared only "within" a certain interface.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BEGroup {
    /// The backend group id
    pub gid: u64,
    /// The current backends count in this group
    pub becount: u16,
    /// The flags instructs the xdp program to update the IP or/and Port
    pub flags: EPFlags,
    /// Interface index
    pub ifindex: u32,
}

impl BEGroup {
    pub fn new(id: u64) -> Self {
        Self {
            gid: id,
            becount: 0_u16,
            flags: EPFlags::default(),
            ifindex: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BEGroup {}

/// Holds the backends metadata required by user space application to manage
/// the groups and backends. The HashMap contaning this data is shared for
/// multiple groups on multiple interfaces and should start with ZLBX_*.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GroupInfo {
    /// The current backends count in this group
    pub becount: u64,
    /// The flags instructs the xdp program to update the IP or/and Port
    pub flags: EPFlags,
    /// Interface index
    pub ifindex: u32,
    /// Group endpoint details
    pub key: EPX,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum EPX {
    V4(EP4),
    V6(EP6),
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GroupInfo {}

#[cfg(feature = "user")]
impl EPX {
    pub fn port(&self) -> u16 {
        match self {
            Self::V4(ep4) => ep4.port,
            Self::V6(ep6) => ep6.port,
        }
    }
    pub fn proto(&self) -> u8 {
        match self {
            Self::V4(ep4) => ep4.proto as u8,
            Self::V6(ep6) => ep6.proto as u8,
        }
    }
}

// TODO: add 32-bit hash for generic hashing for different ip protocols
// TODO: add ifindex field to search per interface
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
    pub address: u32,
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
#[derive(Clone, Copy)]
pub union INET {
    pub v4: u32,
    pub v6: [u8; 16],
}

impl From<u32> for INET {
    fn from(value: u32) -> Self {
        Self { v4: value }
    }
}

impl From<[u8; 16]> for INET {
    fn from(value: [u8; 16]) -> Self {
        Self { v6: value }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for INET {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BE {
    /// Holds both an IPv4 and IPv6 address (big-endian)
    pub address: INET,
    /// The backend listening port and it should be used
    /// only if PORT flag is set. The default value is 0
    // and it should be ignored regardless of the LB flag.
    pub port: u16,
    /// The group id for current backend. It allows to group backends
    /// servicing an LB frontend.
    pub gid: u16,
    /// Used to decode the address field intro IPv4 or v6.
    /// If the PORT flag is enabled the LB port should be replaced
    /// with the backend port.
    pub flags: EPFlags,
    /// The protocol from LB.
    pub proto: u8,
    // TODO: add precomputed inet csum
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BE {}
