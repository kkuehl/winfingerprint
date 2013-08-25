#pragma once
#include <utility>
#include <pcap.h>
#include <Ntddndis.h>
#include <Packet32.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <lmcons.h>
#include <FwCommon.h> // From WMI SDK
#include <wincrypt.h>
#include <afxtempl.h>
#include <iphlpapi.h>				// IP helper
#include <icmpapi.h>
#include <rpcdce.h>					// RPC Support
#include <snmp.h>
#include <mgmtapi.h>
#include <mysql.h>
#include <iprtrmib.h>					// Process bindings
#include <tlhelp32.h>					// Process bindings
#include <psapi.h>						// Process enumeration

#pragma comment (lib, "ws2_32.lib")		// Winsock Support
#pragma comment (lib, "netapi32.lib")
#pragma comment (lib, "mpr.lib")
#pragma comment (lib, "rpcrt4.lib")		// RPC Support
#pragma comment (lib, "libmysqld.lib")	// MySQL Embedded
#pragma comment (lib, "snmpapi.lib")	// SNMP Support
#pragma comment (lib, "mgmtapi.lib")	// SNMP Support
#pragma comment (lib, "odbc32.lib")		// SQL Support
#pragma comment (lib, "version.lib")	// File Version
#pragma comment (lib, "psapi.lib")		// Process Enumeration
using namespace std;

typedef struct _wfphost {
	CString DNS;
	CString NetBIOS;
	CString Domain;
	char ipaddress[16];
	unsigned long res;
	char szComputerM[UNCLEN];
	WCHAR szComputerW[UNCLEN];
}wfphost_t, *pwfphost_t;

#define REQ_DATASIZE	32		// Echo Request Data size
#define ICMP_ECHOREQ	8		// Echo request query
#define	ICMP_ECHOREPLY	0	 // echo reply 
#define MAXHOSTNAMELEN	256
#define MIN_ICMP_PACKET_SIZE 8   //minimum 8 byte icmp packet (just header)
#define ENUM_USERS		1
#define ENUM_MACHINES	2
#define ENUM_GROUPS		3
#define ENUM_SERVICES	4
#define F_READY			0x0001 // Non-blocking connect Initialized 
#define F_CONNECTING	0x0002 // Non-blocking connect in progress 
#define F_READING		0x0004 // Non-blocking complete; now reading
#define F_DONE			0x0008 // Non-blocking done
//#define BUFFSIZE		2048
#define HASHLEN			41  // MD5=32, SHA-1=40 + 1


enum _smb_access {
	SMB_ADSI,
	SMB_NET,
	SMB_WMI,
};

enum _scan_type {
	SCAN_HOST,
	SCAN_RANGE,
	SCAN_LIST,
	SCAN_NEIGHBORHOOD,
	SCAN_PROCESSES,
	SCAN_FILES
};

typedef struct _wfpoptions {
	// Scan Input Types
	CString host;
	char list[MAX_PATH];
	// Scan Types
	_smb_access smb_type;
	_scan_type scan_type;
	// Scan Options
	bool optionbindings;
	bool optionosversion;
	bool optionopensharetest;
	bool optionping;
	bool optionregistry;
	bool optionservices;
	bool optionsessions;
	bool optionshares;
	bool optionsid;
	bool optiontrace;
	bool optiongroups;
	bool optionusers;
	bool optionmacaddress;
	bool optionMD5;
	bool optionnodirectoryrecurse;
	unsigned int max_connections;
	unsigned int retries;
	unsigned int timeout;
}wfpoptions_t, *pwfpoptions_t;

typedef struct _ip_header
{
// Win32 is LITTLE_ENDIAN
	u_char	ip_hl:4,			/* header length */
			ip_v:4;				/* version */
	u_char  ip_tos;				/* type of service           */
	short   ip_len;				/* total length              */
	u_short ip_id;				/* identification            */
	short	ip_off;				/* fragmentation offset flag */
#define IP_DF 0x4000			/* dont fragment flag        */
#define IP_MF 0x2000			/* more fragments flag       */
#define IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_char ip_ttl;				/* time to live */
	u_char ip_p;				/* protocol */
	u_short ip_sum;				/* checksum */
	struct in_addr ip_src, ip_dst; /* source and destination address */
}IP_HEADER, *PIP_HEADER;

// ICMP common echo request/reply message header
typedef struct _icmp_header
{
	u_char	icmp_type;		// type of message, see below 
	u_char	icmp_code;		// type sub code 
	u_short	icmp_cksum;		// ones complement cksum of struct
	u_short	icmp_id;	    // Identification
	u_short	icmp_seq;		// Sequence
} ICMP_HEADER, *PICMPHEADER;

// ICMP Echo Request
typedef struct _icmp_echo_request
{
	ICMP_HEADER icmpHdr;
	DWORD dwTime;
	char cData[REQ_DATASIZE];
} ECHOREQUEST, *PECHOREQUEST;

// ICMP Echo Reply
typedef struct _icmp_echo_reply
{
	IP_HEADER ipHdr;
	ECHOREQUEST	echoRequest;
	char    cFiller[256];
} ECHOREPLY, *PECHOREPLY;

typedef struct _trace_multi_reply
{
	DWORD    dwError; //GetLastError for this host
	in_addr	 Address; //The IP address of the replier
	DWORD    minRTT;  //Minimum round trip time in milliseconds
	DWORD    avgRTT;  //Average round trip time in milliseconds
	DWORD    maxRTT;  //Maximum round trip time in milliseconds
}TRACE_MULTI_REPLY;

typedef CArray<TRACE_MULTI_REPLY, TRACE_MULTI_REPLY&> traceroute_reply;

typedef struct _trace_single_reply
{
	DWORD dwError;  //GetLastError for this replier
	in_addr	 Address;  //The IP address of the replier
	unsigned long RTT; //Round Trip time in milliseconds for this replier
}TRACE_SINGLE_REPLY;

typedef struct _sock
{
	SOCKET f_fd;		// Descriptor identifying socket                   
	int f_flags;		// Bitwise manipulated to determine socket state
  	u_short portnum;	// 0 to 65,535
	unsigned int status;		// Keep track of number of retries
}SOCK, *PSOCK;

typedef HANDLE (WINAPI *MYICMPCREATEFILE)(VOID); 	 
typedef DWORD (WINAPI *MYICMPSENDECHO)(HANDLE, DWORD, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD); 	 
typedef BOOL (WINAPI *MYICMPCLOSEHANDLE)(HANDLE);
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

//
// Undocumented extended information structures available 
// only on XP and higher
// 
typedef struct _MIB_TCPEXROW
{
	DWORD   dwState;        // state of the connection
	DWORD   dwLocalAddr;    // address on local computer
	DWORD   dwLocalPort;    // port number on local computer
	DWORD   dwRemoteAddr;   // address on remote computer
	DWORD   dwRemotePort;   // port number on remote computer
	DWORD   dwProcessId;
}MIB_TCPEXROW, *PMIB_TCPEXROW;

typedef struct _MIB_TCPEXTABLE
{
	DWORD   dwNumEntries;
	MIB_TCPEXROW table[ANY_SIZE];
}MIB_TCPEXTABLE, *PMIB_TCPEXTABLE;

typedef struct _MIB_UDPEXROW
{
	DWORD   dwLocalAddr;    // address on local computer
	DWORD   dwLocalPort;    // port number on local computer
	DWORD   dwProcessId;
}MIB_UDPEXROW, *PMIB_UDPEXROW;

typedef struct _MIB_UDPEXTABLE
{
	DWORD   dwNumEntries;
	MIB_UDPEXROW table[ANY_SIZE];
}MIB_UDPEXTABLE, *PMIB_UDPEXTABLE;

typedef DWORD (WINAPI *PALLOCATE_AND_GET_TCPEXTABLE_FROM_STACK)(
  PMIB_TCPEXTABLE *pTcpTable,  // buffer for the connection table
  BOOL bOrder,               // sort the table?
  HANDLE heap,
  DWORD zero,
  DWORD flags
);

typedef DWORD (WINAPI *PALLOCATE_AND_GET_UDPEXTABLE_FROM_STACK)(
  PMIB_UDPEXTABLE *pUdpTable,  // buffer for the connection table
  BOOL bOrder,               // sort the table?
  HANDLE heap,
  DWORD zero,
  DWORD flags
);
typedef HANDLE (WINAPI *PCREATE_TOOL_HELP32_SNAPSHOT)(
  DWORD dwFlags,       
  DWORD th32ProcessID  
);
typedef BOOL (WINAPI *PPROCESS32_FIRST)(
  HANDLE hSnapshot,      
  LPPROCESSENTRY32 lppe  
);
typedef BOOL (WINAPI *PPROCESS32_NEXT)(
  HANDLE hSnapshot,      
  LPPROCESSENTRY32 lppe  
);
static PALLOCATE_AND_GET_TCPEXTABLE_FROM_STACK pAllocateAndGetTcpExTableFromStack = NULL;
static PALLOCATE_AND_GET_UDPEXTABLE_FROM_STACK pAllocateAndGetUdpExTableFromStack = NULL;
static PCREATE_TOOL_HELP32_SNAPSHOT pCreateToolhelp32Snapshot = NULL;
static PPROCESS32_FIRST pProcess32First = NULL;
static PPROCESS32_NEXT pProcess32Next = NULL;
//
// Possible TCP endpoint states
//
static char TcpState[][32] = {
 "???",
 "CLOSED",
 "LISTENING",
 "SYN_SENT",
 "SYN_RCVD",
 "ESTABLISHED",
 "FIN_WAIT1",
 "FIN_WAIT2",
 "CLOSE_WAIT",
 "CLOSING",
 "LAST_ACK",
 "TIME_WAIT",
 "DELETE_TCB"
};


class CWfpEngine
{
public:
	CWfpEngine(void);
	~CWfpEngine(void);
	void StartThread();
	static UINT ThreadFunc(LPVOID pParam);
	bool Uninit(void);
	bool ScanFiles(CString directory, CString filemask);
	bool ScanHost(CString address);
	bool ScanList(CString List, bool netmask, bool inverted);
	bool ScanNeighborhood(CString domain);
	bool ScanProcesses(void);
	bool ScanRange(CString startaddress, CString endaddress, bool netmask, bool inverted);
	wfphost_t node;
	wfpoptions_t options;
	CString List;
	CString StartIPAddress;
	CString EndIPAddress;
	CStringArray ScanResults;
	CStringArray Disks;
	CStringArray Errors;
	CStringArray EventLog;
	CStringArray Groups;
	CStringArray MACAddress;
	CStringArray NetBIOSShares;
	CStringArray OperatingSystem;
	CStringArray PatchLevel;
	CStringArray RPCBindings;
	CStringArray Sessions;
	CStringArray Services;
	CStringArray SNMP;
	CStringArray Time;
	CStringArray Users;
	CString Output(CStringArray *Array);
protected:
	void ErrorHandler(char *function, DWORD error);
	virtual bool OperatingSystem_get(void) = 0;
	virtual bool NetBIOSShares_get(void) = 0;
	virtual bool Services_get(void) = 0;
	virtual bool Sessions_get(void) = 0;
	virtual bool Users_get(void) = 0;
	bool Resolve(char *address);	
	bool RPCBindings_get(void);
	bool Registry_get(void);
	virtual bool Groups_get(void) = 0;
	bool CheckXP(void);
	bool DatabaseConnect(void);
	bool DatabaseDisconnect(void);
	bool DirectoryListContents(CString directory, CString filemask);
	bool EnumNeighborhood(LPNETRESOURCE lpnr, CString *result);
	char * HashDigest_get(char *name);
	bool Ping(addrinfo *res);
	bool Trace(addrinfo *res);
	CString SID_get(LPWSTR AccountName);
	PCHAR ProcessPidToName(HANDLE hProcessSnap, DWORD ProcessId, PCHAR ProcessName);
	int ProcessBindings_get(DWORD processID);
	int ProcessNameAndID_get(DWORD processID);
	int ProcessModules_get(DWORD processID);
	bool SNMP_get(void);
	char *SNMP_AnyToStr(AsnObjectSyntax *sAny);
	bool SQLPassword_test(void);
	bool WfpSQLBindParameter(int parameternumber, int datatype, void *data);
	bool WfpSQLQuery(int parameternumber, int datatype, void *data);
	bool TCP_Sockets(bool verbose);
	bool UDP_Sockets(unsigned short UDPStartPort, unsigned short UDPEndPort, int type); // Non-blocking UDP Portscan
	int Win32FindData_get(WIN32_FIND_DATA *findData, char *directory, DWORD pid);
	unsigned short in_cksum(u_short *addr, int len);
	HINSTANCE hicmp;
	HMODULE hwpcap;
	HMODULE hpacket;
	MYPCAP_FINDALLDEVS ppcap_findalldevs; 
	MYPCAP_CLOSE ppcap_close;
	MYPCAP_OPEN_LIVE ppcap_open_live;
	MYPCAP_SETFILTER ppcap_setfilter;
	MYPCAP_GETERR ppcap_geterr;
	MYPCAP_COMPILE ppcap_compile;
	MYPCAP_SENDPACKET ppcap_sendpacket;
	MYPCAP_DISPATCH ppcap_dispatch;
	MYPCAP_LOOKUPNET ppcap_lookupnet;
	MYPACKETCLOSEADAPTER pPacketCloseAdapter;
	MYPACKETREQUEST pPacketRequest;
	MYPACKETOPENADAPTER pPacketOpenAdapter;
	MYICMPCREATEFILE pIcmpCreateFile; 	 
	MYICMPSENDECHO pIcmpSendEcho; 	 
	MYICMPCLOSEHANDLE pIcmpCloseHandle;
	CList<u_short,u_short>tcp_connect_ports; 
	bool have_icmp;
	bool have_wpcap;
	bool nbt;
	bool using_database;
	SQLHDBC hdbc;
	SQLHSTMT hstmt;
	SQLHENV henv;
	char hash[HASHLEN];
	MYSQL *mysql;
	MYSQL_RES *results;
	MYSQL_ROW record;

};
