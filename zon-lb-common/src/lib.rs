#![no_std]

use bitflags;

pub const VERSION: u32 = 0x0000001;
pub const MAX_GROUPS: u32 = 64;
pub const MAX_BACKENDS: u32 = 1024;
pub const MAX_CONNTRACKS: u32 = 10; // tmp dev, actual = 1 << 15;

// ARP table it should at least the number of supported backends
pub const MAX_ARP_ENTRIES: u32 = MAX_BACKENDS;
// It depends on number of cores x 2 (ingres + egress) x parallel flows ?
pub const MAX_FRAG6_ENTRIES: u32 = 128;
// It depends on number of cores x 2 (ingres + egress) x parallel flows ?
pub const MAX_FRAG4_ENTRIES: u32 = 128;

pub const FIB_ENTRY_EXPIRY_INTERVAL: u32 = 120;
pub const NEIGH_ENTRY_EXPIRY_INTERVAL: u32 = 120;

/// Runtime variables allows the user app to dynamically set the
/// logging level, enable or disable some bpf features like conntrack
/// or just read statistics. The variable are accessed using the
/// ZLB_RUNVAR array map where each entry represents variable as
/// a 64-bit value. The bellow enum values represent the index
/// where each variable is stored.
/// NOTE: some variables are `fused` meaning they represent a
/// readonly variable that can't be changed at runtime even if
/// this runvar is changed. This kind of variable can only be
/// set at program load and
pub mod runvars {
    /// Get the current app version.
    pub const VERSION: u32 = 0;
    /// Get app feature flags; eg. enable logging or enable ipv6.
    pub const FEATURES: u32 = 1;
    /// Set or get the current log level.
    ///
    /// The values start from `1` (error) and are the same enum
    /// values defined by [aya_log_common::Level]. To turn off
    /// all logging set it to `0`.
    pub const LOG_FILTER: u32 = 2;
    pub const MAX: u32 = 3;
    /// Max size of the runtime variable map
    pub const MAX_RUNTIME_VARS: u32 = 16;
}

/// Program statistics
pub mod stats {
    pub const PACKETS: u32 = 0;
    pub const XDP_PASS: u32 = 1;
    pub const XDP_REDIRECT: u32 = 2;
    pub const XDP_REDIRECT_MAP: u32 = 3;
    pub const XDP_REDIRECT_FULL_NAT: u32 = 4;
    pub const XDP_REDIRECT_ERRORS: u32 = 5;
    pub const XDP_TX: u32 = 6;
    pub const XDP_DROP: u32 = 7;

    pub const FIB_LOOKUPS: u32 = 8;
    pub const FIB_LOOKUP_FAILS: u32 = 9;

    pub const RT_ERRORS: u32 = 10;
    pub const LB_ERROR_NO_BE: u32 = 11;
    pub const LB_ERROR_BAD_BE: u32 = 12;
    pub const CT_ERROR_UPDATE: u32 = 13;
    pub const FIB_ERROR_UPDATE: u32 = 14;

    pub const IP_FRAGMENTS: u32 = 15;
    pub const IPV6_FRAGMENTS: u32 = 16;
    pub const IP_FRAGMENT_ERRORS: u32 = 17;
    /// Cache first fragment errors.
    pub const IPV6_FRAGMENT_ERRORS: u32 = 18;

    pub const ARP_REPLY: u32 = 19;
    pub const ICMPV6_PTB: u32 = 20;
    pub const ICMPV6_ND_SOL_ADVERT: u32 = 21;
    /// Destination unreachable, fragmentation required
    pub const ICMP_DU_FR: u32 = 22;
    /// Packets embedded in Ip6tnl tunnel
    pub const IP6TNL_IPV6: u32 = 23;
    /// IPv6 unknown fragments. This counter is useful to debug cases
    /// when the LB doesn't forward fragments.
    pub const IPV6_UNKNOWN_FRAGMENTS: u32 = 24;
    /// IPv4 unknown fragments. This counter is useful to debug cases
    /// when the LB doesn't forward fragments.
    pub const IPV4_UNKNOWN_FRAGMENTS: u32 = 25;

    pub const MAX: u32 = 26;
}

// TODO: add per backend statistics

bitflags::bitflags! {
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EPFlags: u32 {
    const DISABLE = 1;
    // TODO: Use only IPV4
    const IPV4 = 2;
    const IPV6 = 4;
    /// Forward the packet to the same interface it came when the
    /// XDP_REDIRECT bit is off. When XDP_REDIRECT is on the packet
    /// is redirected to the interface returned after consulting
    /// the FIB (forward informational base).
    const XDP_TX = 8;
    /// Redirect the packet to another interface.
    const XDP_REDIRECT = 1 << 4;
    /// Set for a backend which was configured for Layer 2 Direct Server Return.
    /// In this mode only the MAC addresses are changed. As in case of redirect
    /// FIB is also performed but only to obtain the source and destination
    /// MAC addresses. In DSR mode the loopback interface in the backend network
    /// namespace must be configured with the same address as the backend group IP.
    const DSR_L2 = 1 << 5;
    /// Use DSR over a IPv6 tunnel.
    const DSR_L3 = 1 << 6;
    /// Disable connection tracking and NAT for the backend connection.
    const NO_CONNTRACK = 1 << 8;
    /// TODO: Enable logging on this object and dimiss the runvar that controls
    /// the log level.
    const ENABLE_LOGGING = 1 << 10;
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

// NOTE: explicitly align this struct to 8B
// in order to use the 64-bit operations.
// #[repr(C, align(8))]
#[repr(C)]
#[derive(Clone, Copy)]
pub union Inet6U {
    pub addr8: [u8; 16usize],
    pub addr32: [u32; 4usize],
    // NOTE: for some reason aya generates code that is rejected
    // by verifier when using 2 x 64bit array because the struct
    // is not aligned to 8B (64bit).
    //pub addr64: [u64; 2usize],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Inet6U {}

impl PartialEq for Inet6U {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            self.addr32[3] == other.addr32[3]
                && self.addr32[2] == other.addr32[2]
                && self.addr32[1] == other.addr32[1]
                && self.addr32[0] == other.addr32[0]
        }
    }
}

impl Inet6U {
    pub fn eq32(&self, other: &[u32; 4usize]) -> bool {
        unsafe {
            self.addr32[3] == other[3]
                && self.addr32[2] == other[2]
                && self.addr32[1] == other[1]
                && self.addr32[0] == other[0]
        }
    }
}

impl From<&[u8; 16usize]> for Inet6U {
    fn from(value: &[u8; 16usize]) -> Self {
        Self { addr8: *value }
    }
}

impl From<[u8; 16usize]> for Inet6U {
    fn from(value: [u8; 16usize]) -> Self {
        Self { addr8: value }
    }
}

impl From<&[u32; 4usize]> for Inet6U {
    fn from(value: &[u32; 4usize]) -> Self {
        Self {
            // BUG: can't copy the array directly because there are some cases
            // where aya generates code that bpf verifier rejects.
            // The workaround is manually copy each array item:
            addr32: [value[0], value[1], value[2], value[3]],
        }
    }
}

// TODO: add 32-bit hash for generic hashing for different ip protocols
// TODO: add ifindex field to search per interface
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EP6 {
    pub address: Inet6U,
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

// NOTE: the aya bpf translator does not know about unions and the verifier
// will throw an error for using invalid stack access as the union is
// 16 bytes but we use only 4 for the IPv4 address.
// #[repr(C)]
// #[derive(Clone, Copy)]
// pub struct INET {
//    pub v4: u32,
//    pub v6: [u8; 16],
// }

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BE {
    /// Holds the IPv4 or IPv6 address (big-endian) of the
    /// destination backend.
    /// In case of L3 DSR this only serves as destination address
    /// for FIB lookups. Note that in case of DSR the original
    /// addresses are preserved.
    pub address: [u32; 4],
    /// Prefered source ip for this backend instead of the LB ip.
    /// It is used as source address in FIB lookup if it is different
    /// than 0.0.0.0 or ::0.
    /// In case of L3 DSR this represents the outer source address
    /// than must be used for the tunnel connection through which
    /// the backend endpoint is accessed.
    /// Usually the address is from the same pool as the VIP or LB.
    pub src_ip: [u32; 4],
    /// Alternative address that can be used for tunnel connections
    /// as outer destination address. Depending on the tunnel type
    /// the field can store both IPv4 or IPv6 addresses.
    /// Storing the destination tunnel address per backend allows
    /// balancing requests over multiple methods: dsr_l2, dsr_l3 or NAT.
    pub alt_address: [u32; 4usize],
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

/// IPv4 connection tracking map key.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NAT4Key {
    /// The backend will respond with this address
    pub ip_be_src: u32,
    /// The backend will respond to this address
    pub ip_lb_dst: u32,
    /// The backend will respond with this port.
    pub port_be_src: u16,
    /// The backend will respond to this port
    /// For ICMP it is set with the echo id.
    pub port_lb_dst: u16,
    /// The used IP protocol. The field is 8-bits wide
    /// but we need to be 32-bit for performance reasons
    /// (fewer instructions)
    pub proto: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NAT4Key {}

/// IPv4 connection tracking map value.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NAT4Value {
    /// The source address
    pub ip_src: u32,
    /// The saved lb port. Use a 32-bit value in order to
    /// align to 32-bit and avoid bpf verifier error.
    pub port_lb: u16,
    /// The interface MTU used to compare the reply size.
    pub mtu: u16,
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
    /// The VLAN 802.1q header that needs to be inserted on reply frame.
    /// NOTE: this is separate from the mac combo because this header needs
    /// to be inserted between the src mac and the actual ethernet type:
    /// ---------------------------------------------
    ///  dst | src | [[802.ad |] 802.1q] | ether type | IP hdr
    /// --------------------------------------------
    pub vlan_hdr: u32,
    /// Flags that control the way to forward the packet,
    /// for e.g. pass to net stack to redirect it to
    /// another interface.
    pub flags: EPFlags,
    /// The original LB IP when the NAT changed this address also.
    /// On reply flow the destination IP must be replaced with this
    /// address if it's different than the current destination ip.
    pub lb_ip: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NAT4Value {}

/// IPv6 connection tracking map key.
///
/// TODO: The key can change an replaced by ipv6 src, dst and flow label
/// NOTE: align this struct to 8Bytes in order to:
/// 1. allocated it on stack at this bound
/// 2. allow optimized copy of the first two ipv6 addresses
/// using 4 x 8B copy operations.
/// NOTE: the verifier will check if the address to read is aligned to the
/// data type.
/// NOTE: the order of addresses should match
/// the one in the IPv6 packet on reply flow
/// in order to optimize copying the addresses
/// to the actual packet as 4 x 64-bit moves.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NAT6Key {
    /// The backend will respond to this address
    pub ip_lb_dst: Inet6U,
    /// The backend will respond with this address
    pub ip_be_src: Inet6U,
    /// The backend will respond with this port
    pub port_be_src: u32,
    /// The backend will respond to this port
    /// For ICMP it is set with the echo id.
    pub port_lb_dst: u32,
    /// The used IP protocol. The field is 8-bits wide
    /// but we need to be 32-bit for performance reasons
    /// (fewer instructions)
    pub next_hdr: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NAT6Key {}

/// IPV4 connection tracking map value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NAT6Value {
    /// The source address
    pub ip_src: Inet6U,
    /// The saved lb port. Use a 32-bit value in order to
    /// align to 32-bit and avoid bpf verifier error.
    pub port_lb: u16,
    /// The interface MTU used to compare the reply size.
    pub mtu: u16,
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
    /// The VLAN 802.1q header that needs to be inserted on reply frame.
    /// NOTE: this is separate from the mac combo because this header needs
    /// to be inserted between the src mac and the actual ethernet type:
    /// ---------------------------------------------
    ///  dst | src | [[802.ad |] 802.1q] | ether type | IP hdr
    /// --------------------------------------------
    pub vlan_hdr: u32,
    /// Flags that control the way to forward the packet,
    /// for e.g. pass to net stack to redirect it to
    /// another interface.
    pub flags: EPFlags,
    /// The original LB IP when the NAT changed this address also.
    /// On reply flow the destination IP must be replaced with this
    /// address if it's different than the current destination ip.
    pub lb_ip: Inet6U,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NAT6Value {}

/// Fib table entry
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FibEntry {
    /// Interface index
    pub ifindex: u32,
    /// The dmac and smac combo
    pub macs: [u32; 3],
    /// TBD: Derived source IP combo for both IPv4/v6.
    pub ip_src: [u32; 4],
    /// The expiry timestamp
    pub expiry: u32,
    /// The MTU computed for current interface (16bit)
    pub mtu: u32,
    // TODO: available from struct bpf_fib_lookup
    // The VLAN header: protocol type (e.g. 801.1Q) and
    // tag control information (TCI)
    // pub vlan_hdr: u32,
    // Route metric value
    // pub rt_metric: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FibEntry {}

/// IPv4 FIB cache key
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Fib4Key {
    pub addr: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Fib4Key {}

/// IPv6 FIB cache key
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Fib6Key {
    pub addr32: [u32; 4usize],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Fib6Key {}

/// ARP table entry (IPv4 only).
/// The ARP entry is used to deduce the sMAC/dMAC on packet redirect or
/// answer to ARP requests from within VLANs for IPs that the application
/// is interested to provide connectivity, e.g. LB groups.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ArpEntry {
    /// Interface index
    pub ifindex: u32,
    /// The hardware address associated with an IPv4 address (key)
    pub mac: [u8; 6],
    /// The destination hardware address when this arp entry was updated.
    /// This field can be used to deduce the hw address of the interface.
    /// Unless the interface is in promiscuous mode (no MAC filtering)
    /// the XDP program will receive frames with dest MACs that match
    /// the interface MAC or m/bcast frames (these are ignored for it).
    /// Since there is no easy way to detect MAC addr changes, if this
    /// field matches the `mac` field it is certain that this is the
    /// interface address. This is can be used by zon-lb ARP responder
    /// to fill requests about certain IPs.
    pub if_mac: [u8; 6],
    /// The expiry timestamp
    pub expiry: u32,
    /// The VLAN ID for the IP address (key) as big-endian value
    pub vlan_id: u16,
    /// The interface MTU
    pub mtu: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ArpEntry {}

/// IPv4 ARP cache key
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ArpKey {
    pub addr: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ArpKey {}

/// IPv6 neighbor discovery cache key
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NDKey {
    pub addr32: [u32; 4usize],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NDKey {}

// TODO: Add hasher function for choosing the backend.

// NOTE: Use IPv6 header Flow label in order to track connections.
// The usage of the 3-tuple of the Flow Label, Source Address, and
// Destination Address fields enables efficient IPv6 flow classification,
//  where only IPv6 main header fields in fixed positions are used.
// See: https://www.rfc-editor.org/rfc/rfc6437
// NOTE: IPv6 flow label can be used to find a conntrack entry enven
// if the transport information is not available. However, the flow label
// is not always set by the source, it can be disabled, it can be changed
// by intermediary nodes or the receiving endpoint doesn't enable flow label
// reflection (net.ipv6.flowlabel_reflect) or using the same flow label
// on return. For e.g. the ICMPv6 echo reply message will have a different
// flow label than the request and to enable flow lable reflection on Linux
// only to ICMP packet set net.ipv6.flowlabel_reflect=4 on the receiver endpoint.
// NOTE: If the flow label is not very usefull for connection tracking it can
// be usefull for identifying the conntrack of IPv6 fragments as all fragments
// received by LB have the same Flow Label.
// However, note that the Flow Label is 20-bit where as the fragment identifier
// is 32-bit and the latter is always set as it is used to identify fragments
// instead of flows.

/// In order to forward all fragments from a bigger (than interface MTU)
/// IPv6 packet must cache the Transport header details in order to fetch
/// the backend group or the conntrack entry as only the first fragment
/// (offset 0) contains the L4 info. The Ipv4 doesn't have this issue as
/// all IP fragments contain the L4 info.
///
/// From Ipv6 RFC8200:
/// For every packet that is to be fragmented, the source node generates
/// an Identification value.  The Identification must be different than
/// that of any other fragmented packet sent recently* with the same
/// Source Address and Destination Address.  If a Routing header is
/// present, the Destination Address of concern is that of the final
/// destination.
/// See: https://datatracker.ietf.org/doc/html/rfc8200#section-4.5
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6FragId {
    /// The packet identification field from the Ipv6 fragment extention header.
    pub id: u32,
    /// Source address
    pub src: Inet6U,
    /// Destination address
    pub dst: Inet6U,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6FragInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub reserved: u32,
}

/// As mentioned in RFC 791 IPv4 the fragments are reassembled as follows:
///  "The internet identification field (ID) is used together with the
///   source and destination address, and the protocol fields, to identify
///   datagram fragments for reassembly." (RFC 791)
///
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4FragId {
    /// The packet identification field from the Ipv4 header
    pub id: u16,
    /// The protocol of this fragment
    pub proto: u16,
    /// Source address
    pub src: u32,
    /// Destination address
    pub dst: u32,
}

/// Used to hold session info like sequence ids for IP protocol that
/// don't split data into segments, like ICMPv4.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4FragInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub reserved: u32,
}
