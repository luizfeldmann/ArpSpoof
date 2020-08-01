#ifndef _ARP_PROTOCOL_H_
#define _ARP_PROTOCOL_H_
#include <stdint.h>

/// +-----+------------------------+------------------------+-----------------------------------------------+
/// | bit | 0-7                    | 8-15                   | 16-31                                         |
/// +-----+------------------------+------------------------+-----------------------------------------------+
/// | 0   |	Hardware type (HTYPE)                           | Protocol type (PTYPE)                         | 4 bytes
/// +-----+------------------------+------------------------+-----------------------------------------------+
/// | 32  | Hardware length (HLEN) | Protocol length (PLEN) | Operation (OPER)                              | 8 bytes
/// +-----+------------------------+------------------------+-----------------------------------------------+
/// | 64  | Sender hardware address (SHA) (first 32 bits)                                                   | 12
/// +-----+-------------------------------------------------+-----------------------------------------------+
/// | 96  | Sender hardware address (SHA) (last 16 bits)    | Sender protocol address (SPA) (first 16 bits) | 16
/// +-----+-------------------------------------------------+-----------------------------------------------+
/// | 128 | Sender protocol address (SPA) (last 16 bits)    | Target hardware address (THA) (first 16 bits) | 20
/// +-----+-------------------------------------------------+-----------------------------------------------+
/// | 160 |	Target hardware address (THA) (last 32 bits)                                                    | 24
/// +-----+-------------------------------------------------------------------------------------------------+
/// | 192 | Target protocol address (TPA)                                                                   | 28
/// +-----+-------------------------------------------------------------------------------------------------+

#define swap2(data) ( (((data) >> 8) & 0x00FF) | (((data) << 8) & 0xFF00) )
#define swap4(data) ( (((data) >> 24) & 0x000000FF) | (((data) >>  8) & 0x0000FF00) | (((data) <<  8) & 0x00FF0000) | (((data) << 24) & 0xFF000000) )

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    // LITTLE ENDIAN
    #define SWAP(value) _Generic((value), uint16_t : swap2(value), uint32_t : swap4((uint32_t)value) )
#elif
    // BIG ENDIAN
    #define SWAP(value) value
#endif

#define SWAP16(value) SWAP((uint16_t)value)

enum arp_operation { //uint16_t
        arp_oper_None = SWAP16(0),
        arp_oper_Request = SWAP16(1), // [RFC826][RFC5227]
        arp_oper_Reply = SWAP16(2), // [RFC826][RFC5227]
        arp_oper_ReverseRequest = SWAP16(3), // [RFC903]
        arp_oper_ReverseReply = SWAP16(4), // [RFC903]
        arp_oper_DynamicReverseRequest = SWAP16(5), // [RFC1931]
        arp_oper_DynamicReverseReply = SWAP16(6), // [RFC1931]
        arp_oper_DynamicReverseError = SWAP16(7), // [RFC1931]
        arp_oper_InverseRequest = SWAP16(8), // [RFC1293]
        arp_oper_InverseReply = SWAP16(9), // [RFC1293]
        arp_oper_NegativeAsynchronousTransferModeReply = SWAP16(10), // [RFC1577]
        arp_oper_MultipleAccessOverSynchronousOpticalNetworkingOrSynchronousDigitalHierarchyUnsolicitedArp  = SWAP16(23), // [RFC2176]
        arp_oper_Experimental1 = SWAP16(24), // [RFC5494]
        arp_oper_Experimental2 = SWAP16(25) // [RFC5494]
};

enum arp_hardware_type { //uint16_t
        arp_htype_None = SWAP16(0),
        arp_htype_Ethernet = SWAP16(1),
        arp_htype_ExperimentalEthernet = SWAP16(2),
        arp_htype_AmateurRadioAx25 = SWAP16(3),
        arp_htype_ProteonProNetTokenRing = SWAP16(4),
        arp_htype_Chaos = SWAP16(5),
        arp_htype_Ieee802Networks = SWAP16(6),
        arp_htype_AttachedResourceComputerNetwork = SWAP16(7),
        arp_htype_HyperChannel = SWAP16(8),
        arp_htype_LanStar = SWAP16(9),
        arp_htype_AutonetShortAddress = SWAP16(10),
        arp_htype_LocalTalk = SWAP16(11),
        arp_htype_LocalNet = SWAP16(12),
        arp_htype_UltraLink = SWAP16(13),
        arp_htype_SwitchedMultimegabitDataService = SWAP16(14),
        arp_htype_FrameRelay = SWAP16(15),
        arp_htype_AsynchronousTransmissionMode16 = SWAP16(16),
        arp_htype_HighLevelDataLinkControl = SWAP16(17),
        arp_htype_FibreChannel = SWAP16(18),
        arp_htype_AsynchronousTransmissionMode19 = SWAP16(19),
        arp_htype_SerialLine = SWAP16(20),
        arp_htype_AsynchronousTransmissionMode21 = SWAP16(21),
        arp_htype_MilStandard188Hyphen220 = SWAP16(22),
        arp_htype_Metricom = SWAP16(23),
        arp_htype_Ieee1394Dot1995 = SWAP16(24),
        arp_htype_MultipleAccessOverSynchronousOpticalNetworkingOrSynchronousDigitalHierarchy = SWAP16(25),
        arp_htype_Twinaxial = SWAP16(26),
        arp_htype_ExtendedUniqueIdentifier64 = SWAP16(27),
        arp_htype_Hiparp = SWAP16(28),
        arp_htype_IpAndArpOverIso7816Hyphen3 = SWAP16(29),
        arp_htype_ArpSec = SWAP16(30),
        arp_htype_IpSecTunnel = SWAP16(31),
        arp_htype_InfiniBand = SWAP16(32),
        arp_htype_Tia102Project25CommonAirInterface = SWAP16(33),
        arp_htype_WiegandInterface = SWAP16(34),
        arp_htype_PureIp = SWAP16(35),
        arp_htype_Experimental1 = SWAP16(36),
        arp_htype_Experimental2 = SWAP16(256),
};

enum eth_protocol_type { //uint16_t
        ptype_None = SWAP16(0x0000),
        ptype_IpV4 = SWAP16(0x0800),
        ptype_Arp = SWAP16(0x0806),
        ptype_ReverseArp = SWAP16(0x8035),
        ptype_AppleTalk = SWAP16(0x809B),
        ptype_AppleTalkArp = SWAP16(0x80F3),
        ptype_VLanTaggedFrame = SWAP16(0x8100),
        ptype_NovellInternetworkPacketExchange = SWAP16(0x8137),
        ptype_Novell = SWAP16(0x8138),
        ptype_IpV6 = SWAP16(0x86DD),
        ptype_MacControl = SWAP16(0x8808),
        ptype_PointToPointProtocol = SWAP16(0x880B),
        ptype_CobraNet = SWAP16(0x8819),
        ptype_MultiprotocolLabelSwitchingUnicast = SWAP16(0x8847),
        ptype_MultiprotocolLabelSwitchingMulticast = SWAP16(0x8848),
        ptype_PointToPointProtocolOverEthernetDiscoveryStage = SWAP16(0x8863),
        ptype_PointToPointProtocolOverEthernetSessionStage = SWAP16(0x8864),
        ptype_ExtensibleAuthenticationProtocolOverLan = SWAP16(0x888E),
        ptype_HyperScsi = SWAP16(0x889A),
        ptype_AtaOverEthernet = SWAP16(0x88A2),
        ptype_EtherCatProtocol = SWAP16(0x88A4),
        ptype_ProviderBridging = SWAP16(0x88A8),
        ptype_AvbTransportProtocol = SWAP16(0x88B5),
        ptype_SerialRealTimeCommunicationSystemIii = SWAP16(0x88CD),
        ptype_CircuitEmulationServicesOverEthernet = SWAP16(0x88D8),
        ptype_HomePlug = SWAP16(0x88E1),
        ptype_MacSecurity = SWAP16(0x88E5),
        ptype_PrecisionTimeProtocol = SWAP16(0x88f7),
        ptype_ConnectivityFaultManagementOrOperationsAdministrationManagement = SWAP16(0x8902),
        ptype_FibreChannelOverEthernet = SWAP16(0x8906),
        ptype_FibreChannelOverEthernetInitializationProtocol = SWAP16(0x8914),
        ptype_QInQ = SWAP16(0x9100),
        ptype_VeritasLowLatencyTransport = SWAP16(0xCAFE)
};

struct __attribute__((__packed__)) arp_packet {
    uint16_t HTYPE; // hardware type
    uint16_t PTYPE; // protocol type

    uint8_t HLEN; // hardware address length
    uint8_t PLEN; // protocol address length
    uint16_t OPER;

    uint8_t SHA[6]; // source hardware address
    uint32_t SPA; // source protocol address
    uint8_t THA[6]; // target hardware address
    uint32_t TPA; // target hardware address
} arp_packet;

struct __attribute__((__packed__)) ethernet_header
{
	uint8_t mac_dst[6];
	uint8_t mac_src[6];
	uint16_t protocol;
};

struct __attribute__((__packed__)) my_full_packet {
    struct ethernet_header ethernet;
    struct arp_packet arp;
};

#endif // _ARP_PROTOCOL_H_
