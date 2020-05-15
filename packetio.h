#ifndef _MY_H
#define _MY_H

#define IPPROTO_IGMP 2
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

#define	ARPOP_REQUEST    1 /* request to resolve address */
#define	ARPOP_REPLY      2     /* response to previous request */
#define	ARPOP_REVREQUEST 3 /* request protocol address given hardware */
#define	ARPOP_REVREPLY   4 /* response giving protocol address */
#define ARPOP_INVREQUEST 8 /* request to identify peer */
#define ARPOP_INVREPLY   9 /* response identifying peer */

PNET_BUFFER_LIST createpacket(NDIS_HANDLE NdisHandle, NDIS_HANDLE NblPool, PDOT11_MAC_ADDRESS AdapterMac, void* Packet, ULONG PacketSize);
BOOLEAN FilterNetBufferList(PNET_BUFFER_LIST NetBufferList, NDIS_MEDIUM MiniportMediaType, PMS_FILTER pFilter, BOOLEAN is_send_list);

typedef struct _IPV4_HDR {
    USHORT  ihl:4, version:4, tos:8;
    USHORT  tot_len;
    USHORT  id;
    USHORT  frag_off;
    USHORT  ttl:8, protocol:8;
    USHORT  check;
    ULONG   saddr;
    ULONG   daddr;
} IPV4_HDR, *PIPV4_HDR;

typedef struct _TCP_HDR {
    USHORT  source;
    USHORT  dest;
    ULONG   seq;
    ULONG   ack_seq;
	UCHAR   doff;
    //UCHAR   res1:4,
    //        doff:4;
    UCHAR   fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
    USHORT   window;
    USHORT   check;
    USHORT   urg_ptr;
} TCP_HDR, *PTCP_HDR;

typedef struct _UDP_HDR {
    USHORT  sport;
    USHORT  dport;
    SHORT   ulen;
    USHORT  sum;
} UDP_HDR, *PUDP_HDR;

typedef struct _ARP_HDR {
  USHORT htype;
  USHORT ptype;
  UCHAR hlen;
  UCHAR plen;
  USHORT opcode;
  UCHAR sender_mac[6];
  UCHAR sender_ip[4];
  UCHAR target_mac[6];
  UCHAR target_ip[4];
} ARP_HDR, *PARP_HDR;

#pragma pack(push, 1)
typedef struct _DHCP_HDR {
  UCHAR op;
  UCHAR htype;
  UCHAR hlen;
  UCHAR hops;
  ULONG xid;
  USHORT secs;
  USHORT flags;
  ULONG ciaddr;
  ULONG yiaddr;
  ULONG nsiaddr;
  ULONG ngiaddr;
  UCHAR chaddr[16];
  UCHAR sname[64];
  UCHAR file[128];
  ULONG cookie;
} DHCP_HDR, *PDHCP_HDR;
#pragma pack(pop)
 

typedef struct _PSD_HEADER
{
    ULONG saddr;
    ULONG daddr;
    USHORT mbz:8, ptcl:8;
    USHORT tcpl;
} PSD_HEADER, *PPSD_HEADER;

/** DHCP MESSAGE CODES **/
#define DHCP_DISCOVER			1
#define DHCP_OFFER				2
#define DHCP_REQUEST			3
#define DHCP_DECLINE			4
#define DHCP_ACK				5
#define DHCP_NAK				6
#define DHCP_RELEASE			7
#define DHCP_INFORM				8
#define DHCP_FORCE_RENEW		9
#define DHCP_LEASE_QUERY		10
#define DHCP_LEASE_UNASSIGNED	11
#define DHCP_LEASE_UNKNOWN		12
#define DHCP_LEASE_ACTIVE		13

/**	DHCP OPTIONS CODE **/
#define DHO_PAD								0
#define DHO_SUBNET							1
#define DHO_TIME_OFFSET						2
#define DHO_ROUTERS							3
#define DHO_TIME_SERVERS					4
#define DHO_NAME_SERVERS					5
#define DHO_DOMAIN_NAME_SERVERS				6
#define DHO_LOG_SERVER						7
#define DHO_COOKIE_SERVERS					8
#define DHO_LPR_SERVERS						9
#define DHO_IMPRESS_SERVER					10
#define DHO_RESOURCE_LOCATION_SERVERS		11
#define DHO_HOST_NAME						12
#define DHO_BOOT_SIZE                      	13
#define DHO_MERIT_DUMP                     	14
#define DHO_DOMAIN_NAME                    	15
#define DHO_SWAP_SERVER                    	16
#define DHO_ROOT_PATH                      	17
#define DHO_EXTENSIONS_PATH                	18
#define DHO_IP_FORWARDING                  	19
#define DHO_NON_LOCAL_SOURCE_ROUTING       	20
#define DHO_POLICY_FILTER                  	21
#define DHO_MAX_DGRAM_REASSEMBLY           	22
#define DHO_DEFAULT_IP_TTL                 	23
#define DHO_PATH_MTU_AGING_TIMEOUT         	24
#define DHO_PATH_MTU_PLATEAU_TABLE         	25
#define DHO_INTERFACE_MTU                  	26
#define DHO_ALL_SUBNETS_LOCAL              	27
#define DHO_BROADCAST_ADDRESS              	28
#define DHO_PERFORM_MASK_DISCOVERY         	29
#define DHO_MASK_SUPPLIER                  	30
#define DHO_ROUTER_DISCOVERY               	31
#define DHO_ROUTER_SOLICITATION_ADDRESS    	32
#define DHO_STATIC_ROUTES                  	33
#define DHO_TRAILER_ENCAPSULATION          	34
#define DHO_ARP_CACHE_TIMEOUT              	35
#define DHO_IEEE802_3_ENCAPSULATION        	36
#define DHO_DEFAULT_TCP_TTL                	37
#define DHO_TCP_KEEPALIVE_INTERVAL         	38
#define DHO_TCP_KEEPALIVE_GARBAGE          	39
#define DHO_NIS_SERVERS                    	41
#define DHO_NTP_SERVERS                    	42
#define DHO_VENDOR_ENCAPSULATED_OPTIONS    	43
#define DHO_NETBIOS_NAME_SERVERS           	44
#define DHO_NETBIOS_DD_SERVER              	45
#define DHO_NETBIOS_NODE_TYPE              	46
#define DHO_NETBIOS_SCOPE                  	47
#define DHO_FONT_SERVERS                   	48
#define DHO_X_DISPLAY_MANAGER              	49
#define DHO_DHCP_REQUESTED_ADDRESS         	50
#define DHO_DHCP_LEASE_TIME                	51
#define DHO_DHCP_OPTION_OVERLOAD           	52
#define DHO_DHCP_MESSAGE_TYPE              	53
#define DHO_DHCP_SERVER_IDENTIFIER         	54
#define DHO_DHCP_PARAMETER_REQUEST_LIST    	55
#define DHO_DHCP_MESSAGE                   	56
#define DHO_DHCP_MAX_MESSAGE_SIZE          	57
#define DHO_DHCP_RENEWAL_TIME              	58
#define DHO_DHCP_REBINDING_TIME            	59
#define DHO_VENDOR_CLASS_IDENTIFIER        	60
#define DHO_DHCP_CLIENT_IDENTIFIER         	61
#define DHO_NWIP_DOMAIN_NAME               	62
#define DHO_NWIP_SUBOPTIONS                	63
#define DHO_NISPLUS_DOMAIN                 	64
#define DHO_NISPLUS_SERVER                 	65
#define DHO_TFTP_SERVER                    	66
#define DHO_BOOTFILE                       	67
#define DHO_MOBILE_IP_HOME_AGENT           	68
#define DHO_SMTP_SERVER                    	69
#define DHO_POP3_SERVER                    	70
#define DHO_NNTP_SERVER                    	71
#define DHO_WWW_SERVER                     	72
#define DHO_FINGER_SERVER                  	73
#define DHO_IRC_SERVER                     	74
#define DHO_STREETTALK_SERVER              	75
#define DHO_STDA_SERVER                    	76
#define DHO_USER_CLASS                     	77
#define DHO_FQDN                           	81
#define DHO_DHCP_AGENT_OPTIONS             	82
#define DHO_NDS_SERVERS                    	85
#define DHO_NDS_TREE_NAME                  	86
#define DHO_NDS_CONTEXT					   	87
#define DHO_CLIENT_LAST_TRANSACTION_TIME   	91
#define DHO_ASSOCIATED_IP				   	92
#define DHO_USER_AUTHENTICATION_PROTOCOL   	98
#define DHO_AUTO_CONFIGURE                	116
#define DHO_NAME_SERVICE_SEARCH           	117
#define DHO_SUBNET_SELECTION              	118
#define DHO_DOMAIN_SEARCH	              	119
#define DHO_CLASSLESS_ROUTE				  	121
#define DHO_END                            	-1 

#endif  //_MY_H
 
