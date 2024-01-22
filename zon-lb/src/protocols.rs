use clap::ValueEnum;

/// Generated with awk
/// awk '{$1=toupper(substr($1,0,1))substr($1,2);
/// if ($2 >= 1 && $2 < 255 && $1 != "#") { printf("/// %s \n%s = %d,\n", $0, $1, $2)} }'
/// /etc/protocols | tee -a zon-lb/src/protocols.rs
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Debug)]
pub enum Protocol {
    /// No protocol
    None = 0,
    /// Icmp 1 ICMP # internet control message protocol
    Icmp = 1,
    /// Igmp 2 IGMP # Internet Group Management
    Igmp = 2,
    /// Ggp 3 GGP # gateway-gateway protocol
    Ggp = 3,
    /// Ipencap 4 IP-ENCAP # IP encapsulated in IP (officially ``IP'')
    Ipencap = 4,
    /// St 5 ST # ST datagram mode
    St = 5,
    /// Tcp 6 TCP # transmission control protocol
    Tcp = 6,
    /// Egp 8 EGP # exterior gateway protocol
    Egp = 8,
    /// Igp 9 IGP # any private interior gateway (Cisco)
    Igp = 9,
    /// Pup 12 PUP # PARC universal packet protocol
    Pup = 12,
    /// Udp 17 UDP # user datagram protocol
    Udp = 17,
    /// Hmp 20 HMP # host monitoring protocol
    Hmp = 20,
    /// Xns-idp 22 XNS-IDP # Xerox NS IDP
    XnsIdp = 22,
    /// Rdp 27 RDP # "reliable datagram" protocol
    Rdp = 27,
    /// Iso-tp4 29 ISO-TP4 # ISO Transport Protocol class 4 [RFC905]
    IsoTp4 = 29,
    /// Dccp 33 DCCP # Datagram Congestion Control Prot. [RFC4340]
    Dccp = 33,
    /// Xtp 36 XTP # Xpress Transfer Protocol
    Xtp = 36,
    /// Ddp 37 DDP # Datagram Delivery Protocol
    Ddp = 37,
    /// Idpr-cmtp 38 IDPR-CMTP # IDPR Control Message Transport
    IdprCmtp = 38,
    /// Ipv6 41 IPv6 # Internet Protocol, version 6
    Ipv6 = 41,
    /// Ipv6-route 43 IPv6-Route # Routing Header for IPv6
    Ipv6Route = 43,
    /// Ipv6-frag 44 IPv6-Frag # Fragment Header for IPv6
    Ipv6Frag = 44,
    /// Idrp 45 IDRP # Inter-Domain Routing Protocol
    Idrp = 45,
    /// Rsvp 46 RSVP # Reservation Protocol
    Rsvp = 46,
    /// Gre 47 GRE # General Routing Encapsulation
    Gre = 47,
    /// Esp 50 IPSEC-ESP # Encap Security Payload [RFC2406]
    Esp = 50,
    /// Ah 51 IPSEC-AH # Authentication Header [RFC2402]
    Ah = 51,
    /// Skip 57 SKIP # SKIP
    Skip = 57,
    /// Ipv6-icmp 58 IPv6-ICMP # ICMP for IPv6
    Ipv6Icmp = 58,
    /// Ipv6-nonxt 59 IPv6-NoNxt # No Next Header for IPv6
    Ipv6NoNxt = 59,
    /// Ipv6-opts 60 IPv6-Opts # Destination Options for IPv6
    Ipv6Opts = 60,
    /// Rspf 73 RSPF CPHB # Radio Shortest Path First (officially CPHB)
    Rspf = 73,
    /// Vmtp 81 VMTP # Versatile Message Transport
    Vmtp = 81,
    /// Eigrp 88 EIGRP # Enhanced Interior Routing Protocol (Cisco)
    Eigrp = 88,
    /// Ospf 89 OSPFIGP # Open Shortest Path First IGP
    Ospf = 89,
    /// Ax.25 93 AX.25 # AX.25 frames
    Ax25 = 93,
    /// Ipip 94 IPIP # IP-within-IP Encapsulation Protocol
    Ipip = 94,
    /// Etherip 97 ETHERIP # Ethernet-within-IP Encapsulation [RFC3378]
    Etherip = 97,
    /// Encap 98 ENCAP # Yet Another IP encapsulation [RFC1241]
    Encap = 98,
    /// Pim 103 PIM # Protocol Independent Multicast
    Pim = 103,
    /// Ipcomp 108 IPCOMP # IP Payload Compression Protocol
    Ipcomp = 108,
    /// Vrrp 112 VRRP # Virtual Router Redundancy Protocol [RFC5798]
    Vrrp = 112,
    /// L2tp 115 L2TP # Layer Two Tunneling Protocol [RFC2661]
    L2tp = 115,
    /// Isis 124 ISIS # IS-IS over IPv4
    Isis = 124,
    /// Sctp 132 SCTP # Stream Control Transmission Protocol
    Sctp = 132,
    /// Fc 133 FC # Fibre Channel
    Fc = 133,
    /// Mobility-header 135 Mobility-Header # Mobility Support for IPv6 [RFC3775]
    MobilityHeader = 135,
    /// Udplite 136 UDPLite # UDP-Lite [RFC3828]
    Udplite = 136,
    /// Mpls-in-ip 137 MPLS-in-IP # MPLS-in-IP [RFC4023]
    MplsInIp = 137,
    /// Manet 138 # MANET Protocols [RFC5498]
    Manet = 138,
    /// Hip 139 HIP # Host Identity Protocol
    Hip = 139,
    /// Shim6 140 Shim6 # Shim6 Protocol [RFC5533]
    Shim6 = 140,
    /// Wesp 141 WESP # Wrapped Encapsulating Security Payload
    Wesp = 141,
    /// Rohc 142 ROHC # Robust Header Compression
    Rohc = 142,
    /// Ethernet 143 Ethernet # Ethernet encapsulation for SRv6 [RFC8986]
    Ethernet = 143,
}

impl From<u8> for Protocol {
    fn from(v: u8) -> Self {
        for e in Self::value_variants() {
            if *e as u8 == v {
                return e.clone();
            }
        }
        Self::None
    }
}
