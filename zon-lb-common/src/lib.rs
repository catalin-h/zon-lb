#![no_std]

use bitflags;

pub const VERSION: u32 = 0x0000001;
pub const MAX_GROUPS: u32 = 64;
pub const MAX_BACKENDS: u32 = 1024;
pub const MAX_CONNTRACKS: u32 = 10; // tmp dev, actual = 1 << 15;

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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EPFlags: u32 {
    const DISABLE = 1;
    // TODO: Use only IPV4
    const IPV4 = 2;
    const IPV6 = 4;
    /// Forward the packet to the same interface it came.
    const XDP_TX = 8;
    /// TBD: redirect the packet to another interface.
    /// This flag affects both ingress and egress flows.
    const XDP_REDIRECT = 1 << 4;
    /// Disable connection tracking and NAT for the backend connection.
    const NO_CONNTRACK = 1 << 8;
}
}

/// Holds the group data that the xdp program needs to load balance between backends.
/// The HasMap containing this data is shared only "within" a certain interface.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BEGroup {
    /// The backend group id
    pub gid: u16,
    /// The current backends count in this group
    pub becount: u16,
    /// The flags instructs the xdp program to update the IP or/and Port
    pub flags: EPFlags,
    /// Interface index
    pub ifindex: u32,
}

impl BEGroup {
    pub fn new(id: u16) -> Self {
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
/// all  groups.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GroupInfo {
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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
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

// The aya bpf translator does not know about unions and the verifier
// will throw an error for using invalid stack access as the union is
// 16 bytes but we use only 4 for the IPv4 address.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct INET {
    pub v4: u32,
    pub v6: [u8; 16],
}

impl From<u32> for INET {
    fn from(value: u32) -> Self {
        Self {
            v4: value,
            v6: [0; 16],
        }
    }
}

impl From<[u8; 16]> for INET {
    fn from(value: [u8; 16]) -> Self {
        Self { v6: value, v4: 0 }
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

/// IPV4 connection tracking map key.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NAT4Key {
    /// The backend will respond with this address
    pub ip_be_src: u32,
    /// The backend will respond to this address
    pub ip_lb_dst: u32,
    /// The backend will respond with this port
    pub port_be_src: u16,
    /// The backend will respond to this port
    pub port_lb_dst: u16,
    /// The used IP protocol. The field is 8-bits wide
    /// but we need to be 32-bit for performance reasons
    /// (fewer instructions)
    pub proto: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NAT4Key {}

/// IPV4 connection tracking map value.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NAT4Value {
    /// The source address
    pub ip_src: u32,
    /// The saved lb port. Use a 32-bit value in order to
    /// align to 32-bit and avoid bpf verifier error.
    pub port_lb: u32,
    /// The interface index to redirect the reply packet from
    /// the backend. This is the interface index that the
    /// request packet was received by the LB.
    /// See `EPFlags::XDP_REDIRECT`.
    pub ifindex: u32,
    /// Destination and source MAC addresses. The MAC addresses
    /// are stored so they are just copied in the reply Ethernet
    /// frame. It is used only on redirect the flow and is computed
    /// from the request frame.
    /// See `EPFlags::XDP_REDIRECT`.
    pub mac_addresses: [u32; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NAT4Value {}

// TODO: add hasher function
