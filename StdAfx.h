/* 
   $Id: StdAfx.h,v 1.74 2008/12/17 02:47:15 vacuum Exp $
   stdafx.h : include file for standard system include files,
   or project specific include files that are used frequently, but
   are changed infrequently

   This file is part of winfingerprint.
   Copyright 1999-2005 Kirby Kuehl (vacuum@users.sourceforge.net)

   winfingerprint is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   winfingerprint is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with winfingerprint; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#if !defined(AFX_STDAFX_H__15EF0430_57BC_448B_9488_AA47DC2E88A7__INCLUDED_)
#define AFX_STDAFX_H__15EF0430_57BC_448B_9488_AA47DC2E88A7__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers
#define WINVER 0x0501
#include <afxwin.h>         // MFC core and standard components
#include <afxext.h>         // MFC extensions
#include <afxdtctl.h>		// MFC support for Internet Explorer 4 Common Controls
#define  FD_SETSIZE 65535   // Must redefine FD_SETSIZE before including winsock2.h
#include <pcap.h>
#include <Ntddndis.h>
#include <Packet32.h>
#include <ws2tcpip.h>		// WSAIoct Support
#include <iphlpapi.h>       // IP helper
#include <icmpapi.h>
#include <lm.h>				// Lan Manager Support
#include <lmcons.h>
#include <iads.h>			// ADSI Property Methods
#include <adshlp.h>			// ADsGetObject Support 
#include <assert.h>			// Assert macro
#include <sql.h>			// SQL Support
#include <sqlext.h>			// SQL Support
#include <sys/types.h>		// Time Support
#include <sys/timeb.h>		// Time Support
#include <rpcdce.h>         // RPC Support
#include <afxtempl.h>		// CList Support
#include <winbase.h>
#include <chstring.h>		// From WMI SDK
#include <chstrarr.h>		// From WMI SDK
#include <wbemidl.h>		// From WMI SDK
#include <comdef.h>
#include <snmp.h>
#include <mgmtapi.h>
#include <iostream> // cerr
#include <fstream>  // ifstream


#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// MFC support for Windows Common Controls
#endif // _AFX_NO_AFXCMN_SUPPORT

#define BUFFSIZE			 1024
#define GETNEXT				 2  // SNMP
#define RETRIES				 3  // SNMP
#define SCANRANGE			 1  // Winfingerprint scan type
#define SCANLIST			 2  // Winfingerprint scan type
#define SCANHOST			 3  // Winfingerprint scan type
#define SCANNEIGHBORHOOD	 4  // Winfingerprint scan type
#define ARPREDIRECT			 5  // Winfingerprint scan type
#define F_READY				 0x0001 // Non-blocking connect Initialized 
#define F_CONNECTING		 0x0002 // Non-blocking connect in progress 
#define F_READING			 0x0004 // Non-blocking complete; now reading
#define F_DONE				 0x0008 // Non-blocking done
#define	ICMP_ECHOREPLY		 0	 // echo reply 
#define ICMP_TIMEEXCEEDED	 11	 // TTL exceeded error
#define ICMP_ECHOREQ		 8	 // Echo request query
#define ETHER_ADDR_LEN       6
#define ARP_HEADER_LEN       sizeof(ARP_HEADER)
#define ETHER_HEADER_LEN     sizeof(ETHER_HEADER)
#define ETHER_ARP_LEN        sizeof(ETHER_ARP)
#define IP_HEADER_LEN        sizeof(IP_HEADER)
#define TCP_HEADER_LEN       sizeof(TCP_HEADER)
#define PSEUDO_HEADER_LEN    sizeof(PSEUDO_HEADER)
#define PACKET_LEN           (ETHER_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN)
#define MAX_NUM_ADAPTER      10
// TCP/IP Illustrated Volume 2 Figure 21.14 Page 686   
#define ETHERTYPE_IP		 0x0800
#define ETHERTYPE_ARP		 0x0806
#define ETHERTYPE_REVARP	 0x8035
#define ETHERTYPE_IPTRAILERS 0x1000
//  TCP/IP Illustrated Volume 2 Figure 21.14 Page 686         
#define ETHERTYPE_IP		 0x0800
#define ETHERTYPE_ARP		 0x0806
#define ETHERTYPE_REVARP	 0x8035
#define ETHERTYPE_IPTRAILERS 0x1000
#define MIN_ICMP_PACKET_SIZE 8   //minimum 8 byte icmp packet (just header)

#pragma comment (lib,"activeds") // Active Directory Support
#pragma comment (lib,"adsiid")   // Active Directory Support
#pragma comment (lib,"iphlpapi") // ICMP Support
#pragma comment (lib,"mgmtapi")  // SNMP Support
#pragma comment (lib,"mpr")		 // WNetAddConnection3 Support
#pragma comment (lib,"netapi32") // Lan Manager Support
#pragma comment (lib,"odbc32")   // SQL Support
#pragma comment (lib,"rpcrt4")   // RPC Support
#pragma comment (lib,"snmpapi")  // SNMP Support
#pragma comment (lib,"wbemuuid") // From WMI SDK
#pragma comment (lib,"ws2_32")   // Winsock Support

#define REQ_DATASIZE 32		// Echo Request Data size

typedef struct _asnany
{
    BYTE asnType;
     union
	 {
       AsnInteger32         number;      // ASN_INTEGER
                                         // ASN_INTEGER32
       AsnUnsigned32        unsigned32;  // ASN_UNSIGNED32
       AsnCounter64         counter64;   // ASN_COUNTER64
       AsnOctetString       string;      // ASN_OCTETSTRING
       AsnBits              bits;        // ASN_BITS
       AsnObjectIdentifier  object;      // ASN_OBJECTIDENTIFIER
       AsnSequence          sequence;    // ASN_SEQUENCE
       AsnIPAddress         address;     // ASN_IPADDRESS
       AsnCounter32         counter;     // ASN_COUNTER32
       AsnGauge32           gauge;       // ASN_GAUGE32
       AsnTimeticks         ticks;       // ASN_TIMETICKS
       AsnOpaque            arbitrary;   // ASN_OPAQUE
	} asnValue;
} ASNANY;

typedef struct _node
{
	// Populated by Resolver function
	char *ip_address;           // IP Address of host
	char szComputerM[UNCLEN]; // Multibyte UNC of host with room for null termination 
	WCHAR szComputerW[UNCLEN];// WideChar UNC of host with room for null termination
	unsigned long res;          // inet_addr result for in_addr struct
	CString DNS;                // DNS hostname
	CString NetBIOS;
	CString Domain;
	CStringArray MAC_Address;
	CStringArray Patch_Level;
	CStringArray NetBIOS_Shares;
	CStringArray Services;
	CStringArray Users;
	CStringArray Groups;
	CStringArray Sessions;
	CStringArray RPC_Bindings;
	CStringArray Event_Log;
} NODE, *PNODE;

typedef struct _user_data
{
	unsigned short port;
	bool isopen;
}USER_DATA, *PUSER_DATA;

#pragma pack(1) // This is needed for proper struct alignment

/* TCP/IP Illustrated Volume 2 Figure 4.10 Page 102             */
typedef struct _ether_header
{
	u_char	ether_dhost[6];		/* Ethernet destination address */
	u_char	ether_shost[6];		/* Ethernet source address      */
	u_short ether_type;			/* Ethernet frame type			*/
}ETHER_HEADER, *PETHER_HEADER;

typedef struct _tcp_header
{
	u_short th_sport;
	u_short th_dport;
	u_int32_t th_seq;
	u_int32_t th_ack;
	u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
}TCP_HEADER,*PTCP_HEADER;

typedef struct _pseudo_header //TCP pseudo header
{ 
	u_long saddr;
	u_long daddr;
	u_char mbz;
	u_char ptcl;
	u_short tcpl;
}PSEUDO_HEADER,*PPSEUDO_HEADER;

typedef int (*MYPCAP_FINDALLDEVS)(pcap_if_t **, char *);
typedef void (*MYPCAP_CLOSE)(pcap_t *);
typedef pcap_t* (*MYPCAP_OPEN_LIVE)(const char *, int, int, int, char *);
typedef int	(*MYPCAP_DISPATCH)(pcap_t *, int, pcap_handler, u_char *);
typedef int	(*MYPCAP_SETFILTER)(pcap_t *, struct bpf_program *);
typedef char* (*MYPCAP_GETERR)(pcap_t *);
typedef int	(*MYPCAP_COMPILE)(pcap_t *, struct bpf_program *, char *, int, bpf_u_int32);
typedef int	(*MYPCAP_LOOKUPNET)(const char *, bpf_u_int32 *, bpf_u_int32 *, char *);
typedef int (*MYPCAP_SENDPACKET)(pcap_t *, u_char *, int);
typedef LPADAPTER (*MYPACKETOPENADAPTER)(PCHAR);
typedef BOOLEAN (*MYPACKETREQUEST)(LPADAPTER, BOOLEAN,PPACKET_OID_DATA);
typedef void (*MYPACKETCLOSEADAPTER)(LPADAPTER);
typedef HANDLE (WINAPI *MYICMPCREATEFILE)(VOID); 	 
typedef DWORD (WINAPI *MYICMPSENDECHO)(HANDLE, DWORD, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD); 	 
typedef BOOL (WINAPI *MYICMPCLOSEHANDLE)(HANDLE); 	 
  	 
//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__15EF0430_57BC_448B_9488_AA47DC2E88A7__INCLUDED_)