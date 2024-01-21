/// Welknown services with that listen on known protocols and ports.
///
/// Generated using the following script:
/// awk '{$1=toupper(substr($1,0,1))substr($1,2); \
/// if ($1 != "" && $1 != "#" && substr($1,0,1) != "#") { \
/// split($2, a, "/"); nr=split($1, m, "-"); n=m[0]; \
/// for (i=1; i<=nr;i++) {n=n toupper(substr(m[i],0,1))substr(m[i],2);}; \
/// n=n toupper(substr(a[2],0,1))substr(a[2],2); \
/// if (a[2] == "tcp") v=6; else if (a[2] == "udp") v=17; else v=0; \
/// if (v != 0) {printf("/// %s\n%s = %d,\n", $0, n, lshift(v,16) + a[1]); last=n;} }\
/// }' /etc/services | tee -a zon-lb/src/services.rs
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Debug)]
pub enum Service {
    /// Tcpmux 1/tcp # TCP port service multiplexer
    TcpmuxTcp = 393217,
    /// Echo 7/tcp
    EchoTcp = 393223,
    /// Echo 7/udp
    EchoUdp = 1114119,
    /// Discard 9/tcp sink null
    DiscardTcp = 393225,
    /// Discard 9/udp sink null
    DiscardUdp = 1114121,
    /// Systat 11/tcp users
    SystatTcp = 393227,
    /// Daytime 13/tcp
    DaytimeTcp = 393229,
    /// Daytime 13/udp
    DaytimeUdp = 1114125,
    /// Netstat 15/tcp
    NetstatTcp = 393231,
    /// Qotd 17/tcp quote
    QotdTcp = 393233,
    /// Chargen 19/tcp ttytst source
    ChargenTcp = 393235,
    /// Chargen 19/udp ttytst source
    ChargenUdp = 1114131,
    /// Ftp-data 20/tcp
    FtpDataTcp = 393236,
    /// Ftp 21/tcp
    FtpTcp = 393237,
    /// Fsp 21/udp fspd
    FspUdp = 1114133,
    /// Ssh 22/tcp # SSH Remote Login Protocol
    SshTcp = 393238,
    /// Telnet 23/tcp
    TelnetTcp = 393239,
    /// Smtp 25/tcp mail
    SmtpTcp = 393241,
    /// Time 37/tcp timserver
    TimeTcp = 393253,
    /// Time 37/udp timserver
    TimeUdp = 1114149,
    /// Whois 43/tcp nicname
    WhoisTcp = 393259,
    /// Tacacs 49/tcp # Login Host Protocol (TACACS)
    TacacsTcp = 393265,
    /// Tacacs 49/udp
    TacacsUdp = 1114161,
    /// Domain 53/tcp # Domain Name Server
    DomainTcp = 393269,
    /// Domain 53/udp
    DomainUdp = 1114165,
    /// Bootps 67/udp
    BootpsUdp = 1114179,
    /// Bootpc 68/udp
    BootpcUdp = 1114180,
    /// Tftp 69/udp
    TftpUdp = 1114181,
    /// Gopher 70/tcp # Internet Gopher
    GopherTcp = 393286,
    /// Finger 79/tcp
    FingerTcp = 393295,
    /// Http 80/tcp www # WorldWideWeb HTTP
    HttpTcp = 393296,
    /// Kerberos 88/tcp kerberos5 krb5 kerberos-sec # Kerberos v5
    KerberosTcp = 393304,
    /// Kerberos 88/udp kerberos5 krb5 kerberos-sec # Kerberos v5
    KerberosUdp = 1114200,
    /// Iso-tsap 102/tcp tsap # part of ISODE
    IsoTsapTcp = 393318,
    /// Acr-nema 104/tcp dicom # Digital Imag. & Comm. 300
    AcrNemaTcp = 393320,
    /// Pop3 110/tcp pop-3 # POP version 3
    Pop3Tcp = 393326,
    /// Sunrpc 111/tcp portmapper # RPC 4.0 portmapper
    SunrpcTcp = 393327,
    /// Sunrpc 111/udp portmapper
    SunrpcUdp = 1114223,
    /// Auth 113/tcp authentication tap ident
    AuthTcp = 393329,
    /// Nntp 119/tcp readnews untp # USENET News Transfer Protocol
    NntpTcp = 393335,
    /// Ntp 123/udp # Network Time Protocol
    NtpUdp = 1114235,
    /// Epmap 135/tcp loc-srv # DCE endpoint resolution
    EpmapTcp = 393351,
    /// Netbios-ns 137/udp # NETBIOS Name Service
    NetbiosNsUdp = 1114249,
    /// Netbios-dgm 138/udp # NETBIOS Datagram Service
    NetbiosDgmUdp = 1114250,
    /// Netbios-ssn 139/tcp # NETBIOS session service
    NetbiosSsnTcp = 393355,
    /// Imap2 143/tcp imap # Interim Mail Access P 2 and 4
    Imap2Tcp = 393359,
    /// Snmp 161/tcp # Simple Net Mgmt Protocol
    SnmpTcp = 393377,
    /// Snmp 161/udp
    SnmpUdp = 1114273,
    /// Snmp-trap 162/tcp snmptrap # Traps for SNMP
    SnmpTrapTcp = 393378,
    /// Snmp-trap 162/udp snmptrap
    SnmpTrapUdp = 1114274,
    /// Cmip-man 163/tcp # ISO mgmt over IP (CMOT)
    CmipManTcp = 393379,
    /// Cmip-man 163/udp
    CmipManUdp = 1114275,
    /// Cmip-agent 164/tcp
    CmipAgentTcp = 393380,
    /// Cmip-agent 164/udp
    CmipAgentUdp = 1114276,
    /// Mailq 174/tcp # Mailer transport queue for Zmailer
    MailqTcp = 393390,
    /// Xdmcp 177/udp # X Display Manager Control Protocol
    XdmcpUdp = 1114289,
    /// Bgp 179/tcp # Border Gateway Protocol
    BgpTcp = 393395,
    /// Smux 199/tcp # SNMP Unix Multiplexer
    SmuxTcp = 393415,
    /// Qmtp 209/tcp # Quick Mail Transfer Protocol
    QmtpTcp = 393425,
    /// Z3950 210/tcp wais # NISO Z39.50 database
    Z3950Tcp = 393426,
    /// Ipx 213/udp # IPX [RFC1234]
    IpxUdp = 1114325,
    /// Ptp-event 319/udp
    PtpEventUdp = 1114431,
    /// Ptp-general 320/udp
    PtpGeneralUdp = 1114432,
    /// Pawserv 345/tcp # Perf Analysis Workbench
    PawservTcp = 393561,
    /// Zserv 346/tcp # Zebra server
    ZservTcp = 393562,
    /// Rpc2portmap 369/tcp
    Rpc2portmapTcp = 393585,
    /// Rpc2portmap 369/udp # Coda portmapper
    Rpc2portmapUdp = 1114481,
    /// Codaauth2 370/tcp
    Codaauth2Tcp = 393586,
    /// Codaauth2 370/udp # Coda authentication server
    Codaauth2Udp = 1114482,
    /// Clearcase 371/udp Clearcase
    ClearcaseUdp = 1114483,
    /// Ldap 389/tcp # Lightweight Directory Access Protocol
    LdapTcp = 393605,
    /// Ldap 389/udp
    LdapUdp = 1114501,
    /// Svrloc 427/tcp # Server Location
    SvrlocTcp = 393643,
    /// Svrloc 427/udp
    SvrlocUdp = 1114539,
    /// Https 443/tcp # http protocol over TLS/SSL
    HttpsTcp = 393659,
    /// Https 443/udp # HTTP/3
    HttpsUdp = 1114555,
    /// Snpp 444/tcp # Simple Network Paging Protocol
    SnppTcp = 393660,
    /// Microsoft-ds 445/tcp # Microsoft Naked CIFS
    MicrosoftDsTcp = 393661,
    /// Kpasswd 464/tcp
    KpasswdTcp = 393680,
    /// Kpasswd 464/udp
    KpasswdUdp = 1114576,
    /// Submissions 465/tcp ssmtp smtps urd # Submission over TLS [RFC8314]
    SubmissionsTcp = 393681,
    /// Saft 487/tcp # Simple Asynchronous File Transfer
    SaftTcp = 393703,
    /// Isakmp 500/udp # IPSEC key management
    IsakmpUdp = 1114612,
    /// Rtsp 554/tcp # Real Time Stream Control Protocol
    RtspTcp = 393770,
    /// Rtsp 554/udp
    RtspUdp = 1114666,
    /// Nqs 607/tcp # Network Queuing system
    NqsTcp = 393823,
    /// Asf-rmcp 623/udp # ASF Remote Management and Control Protocol
    AsfRmcpUdp = 1114735,
    /// Qmqp 628/tcp
    QmqpTcp = 393844,
    /// Ipp 631/tcp # Internet Printing Protocol
    IppTcp = 393847,
    /// Ldp 646/tcp # Label Distribution Protocol
    LdpTcp = 393862,
    /// Ldp 646/udp
    LdpUdp = 1114758,
    /// Exec 512/tcp
    ExecTcp = 393728,
    /// Biff 512/udp comsat
    BiffUdp = 1114624,
    /// Login 513/tcp
    LoginTcp = 393729,
    /// Who 513/udp whod
    WhoUdp = 1114625,
    /// Shell 514/tcp cmd syslog # no passwords used
    ShellTcp = 393730,
    /// Syslog 514/udp
    SyslogUdp = 1114626,
    /// Printer 515/tcp spooler # line printer spooler
    PrinterTcp = 393731,
    /// Talk 517/udp
    TalkUdp = 1114629,
    /// Ntalk 518/udp
    NtalkUdp = 1114630,
    /// Route 520/udp router routed # RIP
    RouteUdp = 1114632,
    /// Gdomap 538/tcp # GNUstep distributed objects
    GdomapTcp = 393754,
    /// Gdomap 538/udp
    GdomapUdp = 1114650,
    /// Uucp 540/tcp uucpd # uucp daemon
    UucpTcp = 393756,
    /// Klogin 543/tcp # Kerberized `rlogin' (v5)
    KloginTcp = 393759,
    /// Kshell 544/tcp krcmd # Kerberized `rsh' (v5)
    KshellTcp = 393760,
    /// Dhcpv6-client 546/udp
    Dhcpv6ClientUdp = 1114658,
    /// Dhcpv6-server 547/udp
    Dhcpv6ServerUdp = 1114659,
    /// Afpovertcp 548/tcp # AFP over TCP
    AfpovertcpTcp = 393764,
    /// Nntps 563/tcp snntp # NNTP over SSL
    NntpsTcp = 393779,
    /// Submission 587/tcp # Submission [RFC4409]
    SubmissionTcp = 393803,
    /// Ldaps 636/tcp # LDAP over SSL
    LdapsTcp = 393852,
    /// Ldaps 636/udp
    LdapsUdp = 1114748,
    /// Tinc 655/tcp # tinc control port
    TincTcp = 393871,
    /// Tinc 655/udp
    TincUdp = 1114767,
    /// Silc 706/tcp
    SilcTcp = 393922,
    /// Kerberos-adm 749/tcp # Kerberos `kadmin' (v5)
    KerberosAdmTcp = 393965,
    /// Domain-s 853/tcp # DNS over TLS [RFC7858]
    DomainSTcp = 394069,
    /// Domain-s 853/udp # DNS over DTLS [RFC8094]
    DomainSUdp = 1114965,
    /// Rsync 873/tcp
    RsyncTcp = 394089,
    /// Ftps-data 989/tcp # FTP over SSL (data)
    FtpsDataTcp = 394205,
    /// Ftps 990/tcp
    FtpsTcp = 394206,
    /// Telnets 992/tcp # Telnet over SSL
    TelnetsTcp = 394208,
    /// Imaps 993/tcp # IMAP over SSL
    ImapsTcp = 394209,
    /// Pop3s 995/tcp # POP-3 over SSL
    Pop3sTcp = 394211,
    /// Socks 1080/tcp # socks proxy server
    SocksTcp = 394296,
    /// Proofd 1093/tcp
    ProofdTcp = 394309,
    /// Rootd 1094/tcp
    RootdTcp = 394310,
    /// Openvpn 1194/tcp
    OpenvpnTcp = 394410,
    /// Openvpn 1194/udp
    OpenvpnUdp = 1115306,
    /// Rmiregistry 1099/tcp # Java RMI Registry
    RmiregistryTcp = 394315,
    /// Lotusnote 1352/tcp lotusnotes # Lotus Note
    LotusnoteTcp = 394568,
    /// Ms-sql-s 1433/tcp # Microsoft SQL Server
    MsSqlSTcp = 394649,
    /// Ms-sql-m 1434/udp # Microsoft SQL Monitor
    MsSqlMUdp = 1115546,
    /// Ingreslock 1524/tcp
    IngreslockTcp = 394740,
    /// Datametrics 1645/tcp old-radius
    DatametricsTcp = 394861,
    /// Datametrics 1645/udp old-radius
    DatametricsUdp = 1115757,
    /// Sa-msg-port 1646/tcp old-radacct
    SaMsgPortTcp = 394862,
    /// Sa-msg-port 1646/udp old-radacct
    SaMsgPortUdp = 1115758,
    /// Kermit 1649/tcp
    KermitTcp = 394865,
    /// Groupwise 1677/tcp
    GroupwiseTcp = 394893,
    /// L2f 1701/udp l2tp
    L2fUdp = 1115813,
    /// Radius 1812/tcp
    RadiusTcp = 395028,
    /// Radius 1812/udp
    RadiusUdp = 1115924,
    /// Radius-acct 1813/tcp radacct # Radius Accounting
    RadiusAcctTcp = 395029,
    /// Radius-acct 1813/udp radacct
    RadiusAcctUdp = 1115925,
    /// Cisco-sccp 2000/tcp # Cisco SCCP
    CiscoSccpTcp = 395216,
    /// Nfs 2049/tcp # Network File System
    NfsTcp = 395265,
    /// Nfs 2049/udp # Network File System
    NfsUdp = 1116161,
    /// Gnunet 2086/tcp
    GnunetTcp = 395302,
    /// Gnunet 2086/udp
    GnunetUdp = 1116198,
    /// Rtcm-sc104 2101/tcp # RTCM SC-104 IANA 1/29/99
    RtcmSc104Tcp = 395317,
    /// Rtcm-sc104 2101/udp
    RtcmSc104Udp = 1116213,
    /// Gsigatekeeper 2119/tcp
    GsigatekeeperTcp = 395335,
    /// Gris 2135/tcp # Grid Resource Information Server
    GrisTcp = 395351,
    /// Cvspserver 2401/tcp # CVS client/server operations
    CvspserverTcp = 395617,
    /// Venus 2430/tcp # codacon port
    VenusTcp = 395646,
    /// Venus 2430/udp # Venus callback/wbc interface
    VenusUdp = 1116542,
    /// Venus-se 2431/tcp # tcp side effects
    VenusSeTcp = 395647,
    /// Venus-se 2431/udp # udp sftp side effect
    VenusSeUdp = 1116543,
    /// Codasrv 2432/tcp # not used
    CodasrvTcp = 395648,
    /// Codasrv 2432/udp # server port
    CodasrvUdp = 1116544,
    /// Codasrv-se 2433/tcp # tcp side effects
    CodasrvSeTcp = 395649,
    /// Codasrv-se 2433/udp # udp sftp side effect
    CodasrvSeUdp = 1116545,
    /// Mon 2583/tcp # MON traps
    MonTcp = 395799,
    /// Mon 2583/udp
    MonUdp = 1116695,
    /// Dict 2628/tcp # Dictionary server
    DictTcp = 395844,
    /// F5-globalsite 2792/tcp
    F5GlobalsiteTcp = 396008,
    /// Gsiftp 2811/tcp
    GsiftpTcp = 396027,
    /// Gpsd 2947/tcp
    GpsdTcp = 396163,
    /// Gds-db 3050/tcp gds_db # InterBase server
    GdsDbTcp = 396266,
    /// Icpv2 3130/udp icp # Internet Cache Protocol
    Icpv2Udp = 1117242,
    /// Isns 3205/tcp # iSNS Server Port
    IsnsTcp = 396421,
    /// Isns 3205/udp # iSNS Server Port
    IsnsUdp = 1117317,
    /// Iscsi-target 3260/tcp
    IscsiTargetTcp = 396476,
    /// Mysql 3306/tcp
    MysqlTcp = 396522,
    /// Ms-wbt-server 3389/tcp
    MsWbtServerTcp = 396605,
    /// Nut 3493/tcp # Network UPS Tools
    NutTcp = 396709,
    /// Nut 3493/udp
    NutUdp = 1117605,
    /// Distcc 3632/tcp # distributed compiler
    DistccTcp = 396848,
    /// Daap 3689/tcp # Digital Audio Access Protocol
    DaapTcp = 396905,
    /// Svn 3690/tcp subversion # Subversion protocol
    SvnTcp = 396906,
    /// Suucp 4031/tcp # UUCP over SSL
    SuucpTcp = 397247,
    /// Sysrqd 4094/tcp # sysrq daemon
    SysrqdTcp = 397310,
    /// Sieve 4190/tcp # ManageSieve Protocol
    SieveTcp = 397406,
    /// Epmd 4369/tcp # Erlang Port Mapper Daemon
    EpmdTcp = 397585,
    /// Remctl 4373/tcp # Remote Authenticated Command Service
    RemctlTcp = 397589,
    /// F5-iquery 4353/tcp # F5 iQuery
    F5IqueryTcp = 397569,
    /// Ntske 4460/tcp # Network Time Security Key Establishment
    NtskeTcp = 397676,
    /// Ipsec-nat-t 4500/udp # IPsec NAT-Traversal [RFC3947]
    IpsecNatTUdp = 1118612,
    /// Iax 4569/udp # Inter-Asterisk eXchange
    IaxUdp = 1118681,
    /// Mtn 4691/tcp # monotone Netsync Protocol
    MtnTcp = 397907,
    /// Radmin-port 4899/tcp # RAdmin Port
    RadminPortTcp = 398115,
    /// Sip 5060/tcp # Session Initiation Protocol
    SipTcp = 398276,
    /// Sip 5060/udp
    SipUdp = 1119172,
    /// Sip-tls 5061/tcp
    SipTlsTcp = 398277,
    /// Sip-tls 5061/udp
    SipTlsUdp = 1119173,
    /// Xmpp-client 5222/tcp jabber-client # Jabber Client Connection
    XmppClientTcp = 398438,
    /// Xmpp-server 5269/tcp jabber-server # Jabber Server Connection
    XmppServerTcp = 398485,
    /// Cfengine 5308/tcp
    CfengineTcp = 398524,
    /// Mdns 5353/udp # Multicast DNS
    MdnsUdp = 1119465,
    /// Postgresql 5432/tcp postgres # PostgreSQL Database
    PostgresqlTcp = 398648,
    /// Freeciv 5556/tcp rptp # Freeciv gameplay
    FreecivTcp = 398772,
    /// Amqps 5671/tcp # AMQP protocol over TLS/SSL
    AmqpsTcp = 398887,
    /// Amqp 5672/tcp
    AmqpTcp = 398888,
    /// X11 6000/tcp x11-0 # X Window System
    X11Tcp = 399216,
    /// X11-1 6001/tcp
    X111Tcp = 399217,
    /// X11-2 6002/tcp
    X112Tcp = 399218,
    /// X11-3 6003/tcp
    X113Tcp = 399219,
    /// X11-4 6004/tcp
    X114Tcp = 399220,
    /// X11-5 6005/tcp
    X115Tcp = 399221,
    /// X11-6 6006/tcp
    X116Tcp = 399222,
    /// X11-7 6007/tcp
    X117Tcp = 399223,
    /// Gnutella-svc 6346/tcp # gnutella
    GnutellaSvcTcp = 399562,
    /// Gnutella-svc 6346/udp
    GnutellaSvcUdp = 1120458,
    /// Gnutella-rtr 6347/tcp # gnutella
    GnutellaRtrTcp = 399563,
    /// Gnutella-rtr 6347/udp
    GnutellaRtrUdp = 1120459,
    /// Redis 6379/tcp
    RedisTcp = 399595,
    /// Sge-qmaster 6444/tcp sge_qmaster # Grid Engine Qmaster Service
    SgeQmasterTcp = 399660,
    /// Sge-execd 6445/tcp sge_execd # Grid Engine Execution Service
    SgeExecdTcp = 399661,
    /// Mysql-proxy 6446/tcp # MySQL Proxy
    MysqlProxyTcp = 399662,
    /// Babel 6696/udp # Babel Routing Protocol
    BabelUdp = 1120808,
    /// Ircs-u 6697/tcp # Internet Relay Chat via TLS/SSL
    IrcsUTcp = 399913,
    /// Bbs 7000/tcp
    BbsTcp = 400216,
    /// Afs3-fileserver 7000/udp
    Afs3FileserverUdp = 1121112,
    /// Afs3-callback 7001/udp # callbacks to cache managers
    Afs3CallbackUdp = 1121113,
    /// Afs3-prserver 7002/udp # users & groups database
    Afs3PrserverUdp = 1121114,
    /// Afs3-vlserver 7003/udp # volume location database
    Afs3VlserverUdp = 1121115,
    /// Afs3-kaserver 7004/udp # AFS/Kerberos authentication
    Afs3KaserverUdp = 1121116,
    /// Afs3-volser 7005/udp # volume managment server
    Afs3VolserUdp = 1121117,
    /// Afs3-bos 7007/udp # basic overseer process
    Afs3BosUdp = 1121119,
    /// Afs3-update 7008/udp # server-to-server updater
    Afs3UpdateUdp = 1121120,
    /// Afs3-rmtsys 7009/udp # remote cache manager service
    Afs3RmtsysUdp = 1121121,
    /// Font-service 7100/tcp xfs # X Font Service
    FontServiceTcp = 400316,
    /// Http-alt 8080/tcp webcache # WWW caching service
    HttpAltTcp = 401296,
    /// Puppet 8140/tcp # The Puppet master service
    PuppetTcp = 401356,
    /// Bacula-dir 9101/tcp # Bacula Director
    BaculaDirTcp = 402317,
    /// Bacula-fd 9102/tcp # Bacula File Daemon
    BaculaFdTcp = 402318,
    /// Bacula-sd 9103/tcp # Bacula Storage Daemon
    BaculaSdTcp = 402319,
    /// Xmms2 9667/tcp # Cross-platform Music Multiplexing System
    Xmms2Tcp = 402883,
    /// Nbd 10809/tcp # Linux Network Block Device
    NbdTcp = 404025,
    /// Zabbix-agent 10050/tcp # Zabbix Agent
    ZabbixAgentTcp = 403266,
    /// Zabbix-trapper 10051/tcp # Zabbix Trapper
    ZabbixTrapperTcp = 403267,
    /// Amanda 10080/tcp # amanda backup services
    AmandaTcp = 403296,
    /// Dicom 11112/tcp
    DicomTcp = 404328,
    /// Hkp 11371/tcp # OpenPGP HTTP Keyserver
    HkpTcp = 404587,
    /// Db-lsp 17500/tcp # Dropbox LanSync Protocol
    DbLspTcp = 410716,
    /// Dcap 22125/tcp # dCache Access Protocol
    DcapTcp = 415341,
    /// Gsidcap 22128/tcp # GSI dCache Access Protocol
    GsidcapTcp = 415344,
    /// Wnn6 22273/tcp # wnn6
    Wnn6Tcp = 415489,
    /// Kerberos4 750/udp kerberos-iv kdc # Kerberos (server)
    Kerberos4Udp = 1114862,
    /// Kerberos4 750/tcp kerberos-iv kdc
    Kerberos4Tcp = 393966,
    /// Kerberos-master 751/udp kerberos_master # Kerberos authentication
    KerberosMasterUdp = 1114863,
    /// Kerberos-master 751/tcp
    KerberosMasterTcp = 393967,
    /// Passwd-server 752/udp passwd_server # Kerberos passwd server
    PasswdServerUdp = 1114864,
    /// Krb-prop 754/tcp krb_prop krb5_prop hprop # Kerberos slave propagation
    KrbPropTcp = 393970,
    /// Zephyr-srv 2102/udp # Zephyr server
    ZephyrSrvUdp = 1116214,
    /// Zephyr-clt 2103/udp # Zephyr serv-hm connection
    ZephyrCltUdp = 1116215,
    /// Zephyr-hm 2104/udp # Zephyr hostmanager
    ZephyrHmUdp = 1116216,
    /// Iprop 2121/tcp # incremental propagation
    IpropTcp = 395337,
    /// Supfilesrv 871/tcp # Software Upgrade Protocol server
    SupfilesrvTcp = 394087,
    /// Supfiledbg 1127/tcp # Software Upgrade Protocol debugging
    SupfiledbgTcp = 394343,
    /// Poppassd 106/tcp # Eudora
    PoppassdTcp = 393322,
    /// Moira-db 775/tcp moira_db # Moira database
    MoiraDbTcp = 393991,
    /// Moira-update 777/tcp moira_update # Moira update protocol
    MoiraUpdateTcp = 393993,
    /// Moira-ureg 779/udp moira_ureg # Moira user registration
    MoiraUregUdp = 1114891,
    /// Spamd 783/tcp # spamassassin daemon
    SpamdTcp = 393999,
    /// Skkserv 1178/tcp # skk jisho server port
    SkkservTcp = 394394,
    /// Predict 1210/udp # predict -- satellite tracking
    PredictUdp = 1115322,
    /// Rmtcfg 1236/tcp # Gracilis Packeten remote config server
    RmtcfgTcp = 394452,
    /// Xtel 1313/tcp # french minitel
    XtelTcp = 394529,
    /// Xtelw 1314/tcp # french minitel
    XtelwTcp = 394530,
    /// Zebrasrv 2600/tcp # zebra service
    ZebrasrvTcp = 395816,
    /// Zebra 2601/tcp # zebra vty
    ZebraTcp = 395817,
    /// Ripd 2602/tcp # ripd vty (zebra)
    RipdTcp = 395818,
    /// Ripngd 2603/tcp # ripngd vty (zebra)
    RipngdTcp = 395819,
    /// Ospfd 2604/tcp # ospfd vty (zebra)
    OspfdTcp = 395820,
    /// Bgpd 2605/tcp # bgpd vty (zebra)
    BgpdTcp = 395821,
    /// Ospf6d 2606/tcp # ospf6d vty (zebra)
    Ospf6dTcp = 395822,
    /// Ospfapi 2607/tcp # OSPF-API
    OspfapiTcp = 395823,
    /// Isisd 2608/tcp # ISISd vty (zebra)
    IsisdTcp = 395824,
    /// Fax 4557/tcp # FAX transmission service (old)
    FaxTcp = 397773,
    /// Hylafax 4559/tcp # HylaFAX client-server protocol (new)
    HylafaxTcp = 397775,
    /// Munin 4949/tcp lrrd # Munin
    MuninTcp = 398165,
    /// Rplay 5555/udp # RPlay audio service
    RplayUdp = 1119667,
    /// Nrpe 5666/tcp # Nagios Remote Plugin Executor
    NrpeTcp = 398882,
    /// Nsca 5667/tcp # Nagios Agent - NSCA
    NscaTcp = 398883,
    /// Canna 5680/tcp # cannaserver
    CannaTcp = 398896,
    /// Syslog-tls 6514/tcp # Syslog over TLS [RFC5425]
    SyslogTlsTcp = 399730,
    /// Sane-port 6566/tcp sane saned # SANE network scanner daemon
    SanePortTcp = 399782,
    /// Ircd 6667/tcp # Internet Relay Chat
    IrcdTcp = 399883,
    /// Zope-ftp 8021/tcp # zope management by ftp
    ZopeFtpTcp = 401237,
    /// Tproxy 8081/tcp # Transparent Proxy
    TproxyTcp = 401297,
    /// Omniorb 8088/tcp # OmniORB
    OmniorbTcp = 401304,
    /// Clc-build-daemon 8990/tcp # Common lisp build daemon
    ClcBuildDaemonTcp = 402206,
    /// Xinetd 9098/tcp
    XinetdTcp = 402314,
    /// Git 9418/tcp # Git Version Control System
    GitTcp = 402634,
    /// Zope 9673/tcp # zope server
    ZopeTcp = 402889,
    /// Webmin 10000/tcp
    WebminTcp = 403216,
    /// Kamanda 10081/tcp # amanda backup services (Kerberos)
    KamandaTcp = 403297,
    /// Amandaidx 10082/tcp # amanda backup services
    AmandaidxTcp = 403298,
    /// Amidxtape 10083/tcp # amanda backup services
    AmidxtapeTcp = 403299,
    /// Sgi-cmsd 17001/udp # Cluster membership services daemon
    SgiCmsdUdp = 1131113,
    /// Sgi-crsd 17002/udp
    SgiCrsdUdp = 1131114,
    /// Sgi-gcd 17003/udp # SGI Group membership daemon
    SgiGcdUdp = 1131115,
    /// Sgi-cad 17004/tcp # Cluster Admin daemon
    SgiCadTcp = 410220,
    /// Binkp 24554/tcp # binkp fidonet protocol
    BinkpTcp = 417770,
    /// Asp 27374/tcp # Address Search Protocol
    AspTcp = 420590,
    /// Asp 27374/udp
    AspUdp = 1141486,
    /// Csync2 30865/tcp # cluster synchronization tool
    Csync2Tcp = 424081,
    /// Dircproxy 57000/tcp # Detachable IRC Proxy
    DircproxyTcp = 450216,
    /// Tfido 60177/tcp # fidonet EMSI over telnet
    TfidoTcp = 453393,
    /// Fido 60179/tcp # fidonet EMSI over TCP
    FidoTcp = 453395,
}

impl Service {
    pub fn protocol(&self) -> u16 {
        (*self as u32 >> 16) as u16
    }
    pub fn port(&self) -> u16 {
        *self as u16
    }
}
