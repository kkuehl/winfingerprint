#include "StdAfx.h"
#include ".\wfpengine.h"

using namespace std;

CWfpEngine::CWfpEngine(void)
{	
	options.optionbindings = false;
	options.optiongroups = false;
	options.optionmacaddress = false;
	options.optionMD5 = false;
	options.optionnodirectoryrecurse = false;
	options.optionosversion = false;
	options.optionping = false;
	options.optionservices = false;
	options.optionshares = false;
	options.optiontrace = false;
	options.optionusers = false;
	options.optionopensharetest = false; 
	options.optionsid = false;

	WSADATA wsaData;
	have_icmp = true;
	HRESULT hr;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
    CHAR szUserName[100];
    DWORD dwUserNameLen = 100;

	WSAStartup(0x0202, &wsaData);

	// Prevents CoInitializeEx errors that occur during MFC GUI startup.
	CoUninitialize();

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED|COINIT_SPEED_OVER_MEMORY);
	if(hr != S_OK)
	{
		ErrorHandler("CoInitializeEx", hr);
	}

	//return;
	if((hwpcap = LoadLibrary("wpcap")) != NULL)
	{
		ppcap_findalldevs = (MYPCAP_FINDALLDEVS)GetProcAddress(hwpcap, "pcap_findalldevs");
		ppcap_close = (MYPCAP_CLOSE)GetProcAddress(hwpcap, "pcap_close");
		ppcap_open_live = (MYPCAP_OPEN_LIVE)GetProcAddress(hwpcap, "pcap_open_live");
		ppcap_dispatch = (MYPCAP_DISPATCH)GetProcAddress(hwpcap, "pcap_dispatch");
		ppcap_setfilter = (MYPCAP_SETFILTER)GetProcAddress(hwpcap, "pcap_setfilter");
		ppcap_geterr = (MYPCAP_GETERR)GetProcAddress(hwpcap, "pcap_geterr");
		ppcap_compile = (MYPCAP_COMPILE)GetProcAddress(hwpcap, "pcap_compile");
		ppcap_lookupnet = (MYPCAP_LOOKUPNET)GetProcAddress(hwpcap, "pcap_lookupnet");
		ppcap_sendpacket = (MYPCAP_SENDPACKET)GetProcAddress(hwpcap, "pcap_sendpacket");
	}

	if((hpacket = LoadLibrary("packet")) != NULL)
	{
		pPacketOpenAdapter = (MYPACKETOPENADAPTER)GetProcAddress(hpacket, "PacketOpenAdapter");
		pPacketCloseAdapter = (MYPACKETCLOSEADAPTER)GetProcAddress(hpacket, "PacketCloseAdapter");
		pPacketRequest = (MYPACKETREQUEST)GetProcAddress(hpacket, "PacketRequest"); 
	}

	if((hwpcap != NULL) && (hpacket != NULL))
	{
		have_wpcap = true;
		// Sychronize WinPcap device name with selected interface
		// NOTE: We don't have to check for selected_interface != LB_ERR
		// Since we pInterfaces->SetCurSel(0) in OnInitDialog
		
	//	for(pAdapter = pWfpDlg->pAdaptersInfo, i=0; i < pWfpDlg->pInterfaces->GetCurSel(); pAdapter = pAdapter->Next, i++);
	//		_snprintf(device, sizeof(device)-1, "\\Device\\NPF_%s",	pAdapter->AdapterName);
	}

	if((hicmp = LoadLibrary("icmp.dll")) != NULL)
	{
		if((pIcmpCreateFile = (MYICMPCREATEFILE)GetProcAddress(hicmp, "IcmpCreateFile")) != NULL)
			if((pIcmpCloseHandle = (MYICMPCLOSEHANDLE)GetProcAddress(hicmp, "IcmpCloseHandle")) != NULL)
				if((pIcmpSendEcho = (MYICMPSENDECHO)GetProcAddress(hicmp, "IcmpSendEcho")) != NULL)
					have_icmp = true;
	}

	    // Attempt to acquire a handle to the default key container.
    if(!CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, 0))
	{
		// Some sort of error occured.
		// Create default key container.
		if(!CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
		{
			ErrorHandler("CryptAcquireContext", GetLastError());
			return;
		}

		// Get name of default key container.
		if(!CryptGetProvParam(hProv, PP_CONTAINER, (unsigned char *)szUserName, &dwUserNameLen, 0))
		{
			// Error getting key container name.
			szUserName[0] = 0;
		}
    }

    // Attempt to get handle to signature key.
    if(!CryptGetUserKey(hProv, AT_SIGNATURE, &hKey))
	{
		if(GetLastError() == NTE_NO_KEY)
		{
			// Create signature key pair.
			if(!CryptGenKey(hProv,AT_SIGNATURE,0,&hKey))
			{
				ErrorHandler("CryptGenKey", GetLastError());
				return;
			}
			else
			{
			CryptDestroyKey(hKey);
			}
		}
		else
		{
			ErrorHandler("CryptGetUserKey", GetLastError());
			return;
		}
    }

    // Attempt to get handle to exchange key.
    if(!CryptGetUserKey(hProv,AT_KEYEXCHANGE,&hKey))
	{
		if(GetLastError()==NTE_NO_KEY)
		{
			// Create key exchange key pair.
			if(!CryptGenKey(hProv,AT_KEYEXCHANGE,0,&hKey))
			{
				ErrorHandler("CryptGenKey", GetLastError());
				return;
			}
			else
			{
				CryptDestroyKey(hKey);
			}
		}
		else
		{
			ErrorHandler("CryptGetUserKey", GetLastError());
			return;
		}
    }
    CryptReleaseContext(hProv,0);
	//mysql = NULL;
	//DatabaseConnect();
	return;

}

CWfpEngine::~CWfpEngine(void)
{
}

bool CWfpEngine::Resolve(char *address)
{
	struct addrinfo aiHints;
	struct addrinfo *res = NULL, *temp;
	int retVal = 0;
	CString tmp;
	
	memset(&aiHints, 0, sizeof(aiHints));
	aiHints.ai_flags |= AI_CANONNAME;
	aiHints.ai_family = AF_INET;
	aiHints.ai_socktype = SOCK_RAW;
	aiHints.ai_protocol = IPPROTO_ICMP;
	
	if((retVal = getaddrinfo(address, NULL, &aiHints, &res)) != 0) {
		ErrorHandler("getaddrinfo", WSAGetLastError());
		return false;
	}
	
	char buf[NI_MAXHOST];
	if((getnameinfo(res->ai_addr, (socklen_t)res->ai_addrlen,
		buf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
		ErrorHandler("getaddrinfo", WSAGetLastError());
		return false;
	}

	for (temp = res; temp && temp->ai_canonname; temp = temp->ai_next) {
		_snprintf_s(node.szComputerM, _countof(node.szComputerM), _TRUNCATE, "\\\\%s", buf);
		
		if((MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, node.szComputerM, -1,
			node.szComputerW, UNCLEN)) == 0) {
			ErrorHandler("MultiByteToWideChar", GetLastError());
			return false;
		}
		_snprintf_s(node.ipaddress, _countof(node.ipaddress), _TRUNCATE, "%s", buf);
		tmp.Format("Resolved %s %s\n", buf, (temp->ai_canonname) ? temp->ai_canonname : "");
		node.DNS.operator +=(tmp);
	}

	if(options.optionping) {
		Ping(res);
	}

	if(options.optiontrace) {
		Trace(res);
	}
	
	freeaddrinfo(res);
	return true;
}

bool CWfpEngine::RPCBindings_get()
{
	CString tmp;
    unsigned char *pStringBinding	= NULL;
    RPC_BINDING_HANDLE hRpc			= NULL;
    RPC_EP_INQ_HANDLE hInq			= NULL;
    RPC_STATUS rpcErr				= NULL;
    RPC_STATUS rpcErr2				= NULL;
    int numFound = 0, i = 0, j = 0, k = 0;
	char ipstr[10][20];
	RPC_IF_ID IfId; // struct containing the interface UUID 
	RPC_BINDING_HANDLE hEnumBind = NULL;
	unsigned char *strBinding = NULL;
    unsigned char *strObj = NULL;
    unsigned char *strProtseq = NULL;
    unsigned char *strNetaddr = NULL;
    unsigned char *strEndpoint = NULL;
    unsigned char *strNetoptions = NULL;

	char *protocols[] = {
		"ncacn_nb_tcp",   // Connection-oriented NetBIOS over Transmission Control Protocol (TCP)
		"ncacn_nb_ipx",   // Connection-oriented NetBIOS over Internet Packet Exchange (IPX)
	    "ncacn_nb_nb",    // Connection-oriented NetBIOS Enhanced User Interface (NetBEUI)
	    "ncacn_ip_tcp",   // Connection-oriented Transmission Control Protocol/Internet Protocol (TCP/IP)
		"ncacn_np",       // Connection-oriented named pipes
		"ncacn_spx",      // Connection-oriented Sequenced Packet Exchange (SPX)
		"ncacn_dnet_nsp", // Connection-oriented DECnet transport
		"ncacn_at_dsp",   // Connection-oriented AppleTalk DSP
        "ncacn_vns_spp",  // Connection-oriented Vines scalable parallel processing (SPP) transport
		"ncadg_ip_udp",   // Datagram (connectionless) User Datagram Protocol/Internet Protocol (UDP/IP)
		"ncadg_ipx",      // Datagram (connectionless) IPX
        "ncadg_mq",       // Datagram (connectionless) over the Microsoft® Message Queue Server (MSMQ)
		"ncacn_http",     // Connection-oriented TCP/IP using Microsoft Internet Information Server as HTTP proxy
	    "ncalrpc"         // Local procedure call
	};
	for(k = 0; k < 14; k++)
	{
		// Compose the string binding
		rpcErr = RpcStringBindingCompose (NULL,
			(unsigned char *)protocols[k], // protocol sequence
			(unsigned char *)node.szComputerM+2,
			NULL, NULL, &pStringBinding);
		
		if(rpcErr != RPC_S_OK)
		{
			tmp.Format("RpcStringBindingCompose [%s]", protocols[k]);
			ErrorHandler(tmp.GetBuffer(), GetLastError());
			continue;
		}
		
		// Convert to real binding
		
		rpcErr = RpcBindingFromStringBinding (pStringBinding, &hRpc);
		if(rpcErr != RPC_S_OK)
		{
			ErrorHandler(protocols[k], GetLastError());
			RpcStringFree (&pStringBinding);
			continue;
		}
	
		// Begin Endpoint enumumeration
		rpcErr = RpcMgmtEpEltInqBegin (hRpc,
		     RPC_C_EP_ALL_ELTS, //Returns every element from the endpoint map
			 NULL, // Ignored when InquiryType is RPC_C_EP_ALL_ELTS
			 0, // VersOption is Ignored when InquiryType is RPC_C_EP_ALL_ELTS
             NULL, //ObjectUuid is Ignored when InquiryType is RPC_C_EP_ALL_ELTS
			 &hInq); // InquiryContext 

		if(rpcErr != RPC_S_OK)
		{
			ErrorHandler("RpcMgmtEpEltInqBegin", GetLastError());
			RpcStringFree (&pStringBinding);
			RpcBindingFree (&hRpc);
			continue;
		}
		
		memset(ipstr,0,sizeof(ipstr));

		// While Next succeeds
		do
		{
			rpcErr = RpcMgmtEpEltInqNext (hInq, &IfId, &hEnumBind, NULL, NULL);
			if(rpcErr == RPC_S_OK)
			{
				unsigned char *str = NULL;
				unsigned char *princName = NULL;
				numFound++;

				rpcErr = RpcBindingToStringBinding(hEnumBind, &str);
				if(rpcErr == RPC_S_OK)
				{
					rpcErr2 = RpcStringBindingParse(str,
								&strObj,
								&strProtseq,
                                &strNetaddr,
								&strEndpoint,
								&strNetoptions);
  					
					if(rpcErr2 != RPC_S_OK)
					{
						ErrorHandler("RpcMgmtEpEltInqBegin", GetLastError());
						continue;
					}
					tmp.Format("%s UUID %s Address %s EndPoint %s\n",
						strProtseq, strObj, strNetaddr, strEndpoint);
					RPCBindings.Add(tmp);
					RpcStringFree (&str);
				}
				RpcBindingFree(&hEnumBind);
			}
			else
				break;
		} while (rpcErr != RPC_X_NO_MORE_ENTRIES);

		rpcErr = RpcMgmtEpEltInqDone(&hInq);
		if(rpcErr != RPC_S_OK)
			ErrorHandler("RpcMgmtEpEltInqDone", GetLastError());

		RpcStringFree (&pStringBinding);
		RpcBindingFree (&hRpc);
	}
	return false;
}

bool CWfpEngine::SNMP_get(void)
{
    RFC1157VarBindList variableBindings;
    LPSNMP_MGR_SESSION session = NULL;
    AsnObjectIdentifier reqObject;
	int        timeout = options.timeout * 1000; //milliseconds 
    int istart = 0, iend = 12, j = 0;
    BYTE		requestType;
    AsnInteger	errorStatus;
    AsnInteger	errorIndex;
    char        *chkPtr = NULL;
    char		*oid[1024];
    CString		tmp;
    AsnObjectIdentifier rootOid;
    char *string = NULL;
	
	oid[0] = ".1.3.6.1.2.1.1.1"; // SysDescr
	oid[1] = ".1.3.6.1.2.1.1.2"; // SysObjectID
	oid[2] = ".1.3.6.1.2.1.1.3"; // Uptime
	oid[3] = ".1.3.6.1.2.1.1.4"; // sysContact
	oid[4] = ".1.3.6.1.2.1.1.5"; // SysName
	oid[5] = ".1.3.6.1.2.1.1.6"; // sysLocation
	oid[6] = ".1.3.6.1.2.1.1.7"; // sysServices
	oid[7] = ".1.3.6.1.2.1.4.21.1.1"; // routes dest
	oid[8] = ".1.3.6.1.2.1.2.2.1.2"; // NIC list
	oid[9] = ".1.3.6.1.4.1.77.1.2.25.1.1"; // NT users
	oid[10] = ".1.3.6.1.4.1.77.1.2.3.1.1"; // NT services
	oid[11] = ".1.3.6.1.4.1.77.1.2.27.1.1"; // shares
	oid[12]= ".1.3.6.1.2.1.6.13"; // tcp connection table
		
	for(j=istart; j<=iend; j++)
	{
		// Get oid's...
		variableBindings.list = NULL;
		variableBindings.len = 0;

		// Convert the string representation to an internal representation.
		if (SnmpMgrStrToOid(oid[j], &reqObject) == 0)
		{
			tmp.Format("SnmpMgrStrToOid Error: Invalid oid: %s\n", oid[j]);
			Errors.Add(tmp);
			return false;
		}
		else
		{
			// Since sucessfull, add to the variable bindings list.
			variableBindings.len++;
			if ((variableBindings.list = (RFC1157VarBind *)SNMP_realloc(
				variableBindings.list, sizeof(RFC1157VarBind) *
				variableBindings.len)) == false)
			{	
				tmp.Format("Error: Error allocating oid, %s.\n",oid[j]);
				Errors.Add(tmp);
				return false;
			}

			variableBindings.list[variableBindings.len - 1].name = reqObject; 
            	variableBindings.list[variableBindings.len - 1].value.asnType = ASN_NULL;
		}
    
		// Establish a SNMP session to communicate with the remote agent.  The
		// community, communications timeout, and communications retry count
		// for the session are also required.

		if((session = SnmpMgrOpen(node.szComputerM, "public", timeout, options.retries)) == NULL)
		{
			ErrorHandler("SnmpMgrOpen", GetLastError());
			return false;
		}

		requestType = ASN_RFC1157_GETNEXTREQUEST;
		//requestType = GETNEXT;
		SnmpUtilOidCpy(&rootOid, &variableBindings.list->name );

		SnmpMgrOidToStr(&variableBindings.list->name, &string);
		tmp.Format(_T("\t%s : "), string);
		SNMP.Add(tmp);
		if (string)
			SNMP_free(string);
	
		//while(1)
		//{
		// Request that the API carry out the desired operation.
		if(!SnmpMgrRequest(session,
				requestType,
				&variableBindings,
				&errorStatus,
				&errorIndex))
		{
			ErrorHandler("SnmpMgrRequest", GetLastError());
			return false;
		}
		else
		{
			// The API succeeded, errors may be indicated from the remote agent.
			if (errorStatus > 0)
			{
				tmp.Format("Error: errorStatus=%d, errorIndex=%d\n",
                      		errorStatus, errorIndex);
				Errors.Add(tmp);
				return false;
			}
			if (SnmpUtilOidNCmp( &variableBindings.list[0].name, &rootOid, rootOid.idLength ))
				break;
			
			// Display the resulting variable bindings.
			UINT i;
			for(i = 0; i < variableBindings.len; i++)
			{	
				string = SNMP_AnyToStr(&variableBindings.list[i].value);
				if(string)
				{
					tmp.Format(_T("%s\n"), string);
					SNMP.Add(tmp);
					if (string)
						SNMP_free(string);
				}
				else
					SNMP.Add("Not Available\n");
			} // end for()
		} 
//	}

		// Free the variable bindings that have been allocated.

		SnmpUtilVarBindListFree(&variableBindings);

		if (!SnmpMgrClose(session))
		{
			ErrorHandler("SnmpMgrClose", GetLastError());
			return false;
		}
	}
	return(true);
}

char * CWfpEngine::SNMP_AnyToStr(AsnObjectSyntax *sAny)
{
	DWORD dwValue = 0;
    UINT uLen = 0;
    BYTE *puData = 0;
    char *pString = NULL;
    switch ( sAny->asnType )
    {
        case ASN_INTEGER:    
            pString = (char *) SnmpUtilMemAlloc(33);
            if (pString)
               _ltoa_s( sAny->asnValue.number, pString, 10, 32);
            break;
        case ASN_RFC1155_COUNTER:
            dwValue = sAny->asnValue.counter;
			pString = (char *) SnmpUtilMemAlloc(33);
            if (pString)
               _ultoa_s(dwValue, pString, 10, 32);
			break;
        case ASN_RFC1155_GAUGE:
            dwValue = sAny->asnValue.gauge;
             if (pString)
               _ultoa_s(dwValue, pString, 10, 32);
			 break;
        case ASN_RFC1155_TIMETICKS:
            dwValue = sAny->asnValue.ticks;
        case ASN_OCTETSTRING:   // Same as ASN_RFC1213_DISPSTRING 
            uLen = sAny->asnValue.string.length + 1;
            puData = sAny->asnValue.string.stream;
            pString = (char *) SnmpUtilMemAlloc(uLen + 1);
            if(pString)
            {
				if (sAny->asnValue.arbitrary.length)
				{
					strncpy_s(pString, uLen - 1, (const char*)puData, _TRUNCATE);
					pString[uLen] = '\0';
				}
            }
			break;
        case ASN_SEQUENCE:      // Same as ASN_SEQUENCEOF 
            uLen = sAny->asnValue.sequence.length;
            puData = sAny->asnValue.sequence.stream;
            if(pString)
            {
				if (sAny->asnValue.arbitrary.length)
				{
					strncpy_s(pString, uLen -1, (const char*)puData, _TRUNCATE);
					pString[uLen] = '\0';
				}
            }
			break;
        case ASN_RFC1155_IPADDRESS:
        {
            if (sAny->asnValue.address.length )
            {
                UINT i;
                char szBuf[17];

                uLen = sAny->asnValue.address.length;
                puData = sAny->asnValue.address.stream;

                pString = (char *) SnmpUtilMemAlloc(uLen * 4);
                if (pString)
                {
                    pString[0] = '\0';
    
                    for (i = 0; i < uLen; i++)
                    {
						_itoa_s(puData[i], szBuf, 10);
                        strncat_s(pString, uLen * 4, szBuf, _TRUNCATE);    
                        if(i < uLen-1)
                            strncat_s(pString, uLen * 4, ".", _TRUNCATE);
                    }
                }
            }
            else
                pString = NULL;
            break;
        }
        case ASN_RFC1155_OPAQUE:
            if ( sAny->asnValue.arbitrary.length )
            {
                uLen = sAny->asnValue.arbitrary.length;
                puData = sAny->asnValue.arbitrary.stream;
                pString = (char *) SnmpUtilMemAlloc(uLen + 1);
                if (pString)
                {
                    if (sAny->asnValue.arbitrary.length)
					{
                    	strncpy_s(pString, uLen -1,(const char*)puData, _TRUNCATE);
						pString[uLen] = '\0';
					}
                }
            }
            else
                pString = NULL;
            break;
        case ASN_OBJECTIDENTIFIER:
        {
            if ( sAny->asnValue.object.idLength )
            {
                pString = (char *) SnmpUtilMemAlloc( sAny->asnValue.object.idLength * 5 );
                if (pString)
                {
                    UINT i;
                    char szBuf[17];
                    for( i = 0; i < sAny->asnValue.object.idLength; i++)
                    {
						_itoa_s(sAny->asnValue.object.ids[i], szBuf, 10); 
                        lstrcat(pString, szBuf);    
                        if( i < sAny->asnValue.object.idLength - 1)
                            lstrcat(pString, ".");
                    }
                }
            }
            else
                pString = NULL;
            break;
        }
        default:             // Unrecognised data type 
            return( FALSE );
    }
    return( pString );
}

bool CWfpEngine::SQLPassword_test(void) // Check for sa passwords
{
	SQLHENV henv = SQL_NULL_HENV;
	SQLHDBC hdbc1 = SQL_NULL_HDBC;     
	SQLHSTMT hstmt1 = SQL_NULL_HSTMT;
	RETCODE retcode;
    SQLCHAR szOutConn[1024] ;
	SQLSMALLINT szint;
	char constr[55]; //39+ CNLEN + NULL
	CString tmp;

	// Build connection string to pass to ODBC driver
	_snprintf_s(constr, _countof(constr), _TRUNCATE, "DRIVER={SQL Server};SERVER=%s;UID=sa;PWD=", node.szComputerM+2); 
	
    retcode = SQLAllocHandle (SQL_HANDLE_ENV, NULL, &henv);
	if((retcode != SQL_SUCCESS_WITH_INFO) && (retcode != SQL_SUCCESS))
	{
		ErrorHandler("SQLAllocHandle", GetLastError());
		return false;
	}
    

	retcode = SQLSetEnvAttr(henv, SQL_ATTR_ODBC_VERSION, (SQLPOINTER) SQL_OV_ODBC3, SQL_IS_INTEGER);
	if((retcode != SQL_SUCCESS_WITH_INFO) && (retcode != SQL_SUCCESS))
	{
		ErrorHandler("SQLSetEnvAttr", GetLastError());
		return false;
	}
    
	retcode = SQLAllocHandle(SQL_HANDLE_DBC, henv, &hdbc1);
	if((retcode != SQL_SUCCESS_WITH_INFO) &&(retcode != SQL_SUCCESS))
	{
		ErrorHandler("SQLAllocHandle", GetLastError());
		return false;
	}

	retcode = SQLSetConnectAttr(hdbc1, SQL_LOGIN_TIMEOUT, (void *)5, 0);
	if((retcode != SQL_SUCCESS_WITH_INFO) &&(retcode != SQL_SUCCESS))
	{
		ErrorHandler("SQLSetConnectAttr", GetLastError());
		return false;
	}

	// Connect to server
    retcode = SQLDriverConnect(hdbc1, NULL, (SQLTCHAR*)constr, SQL_NTS, szOutConn, 1024, &szint, SQL_DRIVER_NOPROMPT);
	
	// this error is actually important
	if (retcode == SQL_ERROR)
	{
		tmp.Format(_T("\t%s : 'sa' password is not blank.\n"), node.szComputerM+2);
		OperatingSystem.Add(tmp);
		return true;
	}
	else
	{
		tmp.Format(_T("\t%s: Vulnerable Connected with 'sa' and no password\n"),node.szComputerM+2);
		OperatingSystem.Add(tmp);

		retcode = SQLAllocHandle(SQL_HANDLE_STMT, hdbc1, &hstmt1);
		if((retcode != SQL_SUCCESS_WITH_INFO) && (retcode != SQL_SUCCESS))
		{
			ErrorHandler("SQLAllocHandle", GetLastError());
			return false;
		}

		// Exec the statement and increment count
		retcode = SQLExecDirect(hstmt1, (SQLTCHAR*)"xp_cmdshell 'net send localhost The \"sa\" account on this machine does not have a password set. Please set a password. Thank you, Corporate Information Security.'", SQL_NTS);
		if ((retcode != SQL_SUCCESS) && (retcode != SQL_SUCCESS_WITH_INFO))
		{
			ErrorHandler("SQLExecDirect", GetLastError());
			return false;
		}
	}
    // Clean up.
	SQLDisconnect(hdbc1);
	if(hdbc1)
		SQLFreeHandle(SQL_HANDLE_DBC, hdbc1);
	if(henv)
		SQLFreeHandle(SQL_HANDLE_ENV, henv);

	return true;
}

bool CWfpEngine::WfpSQLBindParameter(int parameternumber, int datatype, void *data) // Check for sa passwords
{
	/*RETCODE retcode;
	SQLINTEGER sizeInt = SQL_NTS;

	switch(datatype) {
		case SQL_VARCHAR:
			retcode = SQLBindParameter(hstmt, // statement handle
				parameternumber, // parameter number
				SQL_PARAM_INPUT, // input/output type (we aren't calling a procedure
				SQL_C_DEFAULT, // value type
				SQL_VARCHAR, // data type
				255, // column size
				0,
				(char *)data, 
				0,
				&sizeInt);
				break;
		case SQL_C_TYPE_TIMESTAMP:
			retcode = SQLBindParameter(hstmt, // statement handle
				parameternumber, // parameter number
				SQL_PARAM_INPUT, // input/output type (we aren't calling a procedure
				SQL_C_TYPE_TIMESTAMP, // value type
				SQL_TYPE_TIMESTAMP, // data type
				SQL_TIMESTAMP_LEN, // column size
				0,
				(SQL_TIMESTAMP_STRUCT *)data, 
				0,
				&sizeInt);
				break;
		case SQL_INTEGER:
			retcode = SQLBindParameter(hstmt, // statement handle
				parameternumber, // parameter number
				SQL_PARAM_INPUT, // input/output type (we aren't calling a procedure
				SQL_C_DEFAULT, // value type
				SQL_INTEGER, // data type
				0, // column size
				0,
				(int *)data,
				0,
				&sizeInt);
				break;
	}

	if(retcode != SQL_SUCCESS_WITH_INFO && retcode != SQL_SUCCESS)
	{
		ErrorHandler("SQLBindParameter", retcode);
		return false;
	}
	*/
	return true;
}


bool CWfpEngine::WfpSQLQuery(int parameternumber, int datatype, void *data) // Check for sa passwords
{ 
	/*RETCODE retcode;
	long        lEmpID;
	PBYTE       pPicture = NULL;
	SQLINTEGER  pIndicators[2];

	// Get a statement handle and execute a command.
	retcode = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);
	
	if (SQLExecDirect(hstmt,
		(SQLCHAR*) "SELECT EmployeeID, Photo FROM Employees",
		SQL_NTS) == SQL_ERROR)
		{
		// Handle error and return.
		}

	// Retrieve data from row set.
	SQLBindCol(hstmt, 1, SQL_C_LONG, (SQLPOINTER) &lEmpID, sizeof(long),
		&pIndicators[0]);

	while (SQLFetch(hstmt) == SQL_SUCCESS)
	{
		printf("EmployeeID: %d\n", lEmpID);

		// Call SQLGetData to determine the amount of data that's waiting.
		if (SQLGetData(hstmt, 2, SQL_C_BINARY, pPicture, 0, &pIndicators[1])
			== SQL_SUCCESS_WITH_INFO)
        {
			printf("Photo size: %ld\n\n", pIndicators[1]);

			// Get all the data at once.
			pPicture = new BYTE[pIndicators[1]];
			if (SQLGetData(hstmt, 2, SQL_C_DEFAULT, pPicture,
				pIndicators[1], &pIndicators[1]) != SQL_SUCCESS)
			{
            // Handle error and continue.
            }
			delete [] pPicture;
        }
		else
        {
        // Handle error on attempt to get data length.
        }
    }*/
	return true;
}

bool CWfpEngine::Uninit(void)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	CoUninitialize();
	if(hicmp != NULL)
		FreeLibrary(hicmp);
	if(!WSACleanup( ))
		return true;
	else 
		ErrorHandler("WSACleanup", WSAGetLastError());
	return false;
}

void CWfpEngine::ErrorHandler(char * function, DWORD error)
{
	LPVOID lpMsgBuf;
	CString tmp;
	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR) &lpMsgBuf,0,NULL);
	tmp.Format("%s Error %d %s", function, error, lpMsgBuf);
	Errors.Add(tmp);
	LocalFree(lpMsgBuf);
}

bool CWfpEngine::ScanHost(CString address)
{
	if(!Resolve(address.GetBuffer())) {
		MessageBox(NULL, address, "resolve failure", MB_OK);
		return false;
	}
	
	if(options.optionosversion)
		OperatingSystem_get();

	if(options.optionregistry)
		Registry_get();
	
	if(options.optionbindings)
		RPCBindings_get();	
	
	if(options.optiongroups)
		Groups_get();

	if(options.optionusers)
		Users_get();

	if(options.optionshares)
		NetBIOSShares_get();
	
	if(options.optionservices)
		Services_get();

	if(options.optionsessions)
		Sessions_get();
	
	return true;
}

bool CWfpEngine::ScanRange(CString startaddress, CString endaddress, bool netmask, bool inverted)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	unsigned long counter = 0,
		start = 0,
		end = 0,
		temp = 0,
		mynetmask = 0;
	struct in_addr startip, netmaskaddr, endip;
	struct sockaddr_in sin;

	if((start = inet_addr(startaddress)) != INADDR_NONE)
		startip.S_un.S_addr = start;
	else
		return false;
	
	if(inverted) // inverted netmask
		end = ~inet_addr(endaddress);
	else
		end = inet_addr(endaddress);

	if(netmask)
	{
		netmaskaddr.S_un.S_addr = end;
		//cout << inet_ntoa(netmaskaddr) << endl;
		mynetmask = ntohl(netmaskaddr.S_un.S_addr);
		endip.s_addr = startip.S_un.S_addr |= ~htonl(mynetmask);
		//cout << inet_ntoa(endip) << endl;
	}
	else
		endip.S_un.S_addr = end;

	end = inet_addr(inet_ntoa(endip));

		// Switch starting and ending IP if necessary
		if(ntohl(start) > ntohl(end))
		{
			temp = start;   
			start = end;   
			end = temp;   
		}

		if(ntohl(start) <= ntohl(end)) 
		{
			for (counter = ntohl(start); counter <= ntohl(end); counter++)
			{
				if((counter & 0xff) == 0 || (counter & 0xff) == 255)
					continue;
				
				memset(&sin,0,sizeof(sin));
				*(long *)&sin.sin_addr = htonl(counter);

				if(!ScanHost(inet_ntoa(sin.sin_addr)))
					continue;
			}
		}
	
	return false;
}

bool CWfpEngine::ScanList(CString List, bool netmask, bool inverted)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	ifstream input(List);
	char iptoscan[256];
	char* range_p;
	char* beg_addr_p;
	CString startaddress, endaddress, tmp;
	unsigned long counter = 0,
		start = 0,
		end = 0,
		temp = 0,
		mynetmask = 0;
	struct in_addr startip, netmaskaddr, endip;
	struct sockaddr_in sin;

	if(input.is_open()) {
		while(input.getline(iptoscan,256))
		{
			while (iptoscan[strlen (iptoscan) - 1] == '\r' || iptoscan[strlen (iptoscan) - 1] == '\n')
				iptoscan[strlen (iptoscan) - 1] = '\0';
				
			// Pointer to the first char of the start IP address
			beg_addr_p = iptoscan;

			// Skip spaces at the begining of the line
			while(*beg_addr_p != '\0' && *beg_addr_p <= ' ')
				beg_addr_p++;
			if((range_p = strstr((char*)beg_addr_p, " - ")) != NULL)
			{
				// Found range token
				char* end_addr_p;
					
				// Pointer to first char of the end IP address
				end_addr_p = range_p + strlen(" - ");

				// Skip spaces at the end of the start IP address
				if(range_p > beg_addr_p)
					while(*(range_p - 1) != '\0' && *(range_p - 1) <= ' ')
						range_p--;

				*range_p = '\0';

				// Skip spaces at the begining of end IP address
				while(*end_addr_p != '\0' && *end_addr_p <= ' ')
					end_addr_p++;
					
				startaddress.Format("%s", beg_addr_p);		
				endaddress.Format("%s", end_addr_p);
			
				if((start = inet_addr(startaddress)) != INADDR_NONE)
					startip.S_un.S_addr = start;
					
				if(inverted) // inverted netmask
					end = ~inet_addr(endaddress);
				else
					end = inet_addr(endaddress);
		
				if(netmask)
				{
					netmaskaddr.S_un.S_addr = end;
					mynetmask = ntohl(netmaskaddr.S_un.S_addr);
					endip.s_addr = startip.S_un.S_addr |= ~htonl(mynetmask);
				}
				else
					endip.S_un.S_addr = end;
		
				end = inet_addr(inet_ntoa(endip));

				// Switch starting and ending IP if necessary
				if(ntohl(start) > ntohl(end))
				{
					temp = start;   
					start = end;   
					end = temp;   
				}

				if(ntohl(start) <= ntohl(end)) 
				{
					for (counter = ntohl(start); counter <= ntohl(end); counter++)
					{
//						if(pWfpDlg->m_stop)
//							break;
							
						memset(&sin, 0, sizeof(sin));
						*(long *)&sin.sin_addr = htonl(counter);

						if((counter & 0xff) == 0 || (counter & 0xff) == 255)
							continue;

						ScanHost(inet_ntoa(sin.sin_addr));
					}
				}
			}
			else // was not a range
			{
				ScanHost(iptoscan);
			}	
		}
		input.close();
		return true;
	}
	else {
		tmp.Format("Unable to open %s\n", List);
		Errors.Add(tmp);
		return false;
	}
}

bool CWfpEngine::ScanNeighborhood(CString domain)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	LPNETRESOURCE lpnr = NULL;
	//LPSTR mydomain;
	DWORD cbBuffer = 16384;
	if(domain.IsEmpty()) {
		//NET_Neighborhood(lpnr);
	}
	else {
		if((lpnr = (LPNETRESOURCE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer)) == NULL)
			return false;

		//mydomain = (LPTSTR)malloc(DNLEN+1);
		//mydomain = (LPTSTR)calloc(DNLEN+1, sizeof(TCHAR));
  	    //if(mydomain == NULL)
  	    //{
  		//	ErrorHandler("calloc", GetLastError());
  	    //    return(0);
		//}
		//_sntprintf(mydomain, DNLEN, "%s", domain);
		//lpnr->lpRemoteName = mydomain;             // Domain name (Can't handle CString)
		lpnr->lpRemoteName = domain.GetBuffer();             // Domain name (Can't handle CString)
		lpnr->dwUsage = RESOURCEUSAGE_CONTAINER; // Has to be a container to pass to WNetOpenEnum 
		lpnr->lpLocalName = NULL;
		lpnr->dwType = RESOURCETYPE_ANY;         // All resources
		lpnr->dwScope = RESOURCE_GLOBALNET;      // All resources
		//NET_Neighborhood(lpnr);
//		if(mydomain != NULL)
//			free(mydomain);
		if(lpnr != NULL)
			HeapFree(GetProcessHeap(), 0, lpnr);
	}

	return false;
}

bool CWfpEngine::Ping(addrinfo *res)
{
	//AFX_MANAGE_STATE(AfxGetStaticModuleState());
	SOCKET raw;
	static ECHOREQUEST echo_req;
	ECHOREPLY echo_reply;
	unsigned int rc = 0, addrlen = 0, id = 1, seq = 1;
	DWORD start = 0, elapsed = 0;
	fd_set readfds;
	struct timeval tv;
	SOCKADDR_IN	from_addr;
	CString tmp;
	
	for(int i = 1; i <= 3; i++)
	{
		// Fill in echo request
		echo_req.icmpHdr.icmp_type = ICMP_ECHOREQ; 
		echo_req.icmpHdr.icmp_code = 0;
		echo_req.icmpHdr.icmp_cksum	= 0;
		echo_req.icmpHdr.icmp_id = (u_short) id++;
		echo_req.icmpHdr.icmp_seq = (u_short) seq++;

		if((raw = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == SOCKET_ERROR)
		{
			ErrorHandler("socket", WSAGetLastError());
			return false;
		}
		
		// Send ICMP echo request and note time
		// Fill in some data to send
		memset(echo_req.cData, ' ', REQ_DATASIZE);

		// Save tick count when sent
		echo_req.dwTime = GetTickCount();

		// Compute checksum
		echo_req.icmpHdr.icmp_cksum = in_cksum((u_short *)&echo_req, sizeof(ECHOREQUEST));
		
		// Send the echo request 
		if(sendto(raw, (const char *)&echo_req, sizeof(ECHOREQUEST), 0, res->ai_addr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
		{
			ErrorHandler("sendto", WSAGetLastError());
			shutdown(raw,SD_BOTH);
			closesocket(raw);
			return false;
		}
		
		start = GetTickCount();

		// Wait for data to be returned, allow time-out
		FD_ZERO(&readfds);
		FD_SET(raw, &readfds);
		tv.tv_sec =  1; // select() timeout in seconds
		tv.tv_usec = 0;                  // milliseconds

		if((rc = select(NULL, &readfds, NULL, NULL, &tv)) == SOCKET_ERROR)
		{
			Errors.Add("ICMP Error\n");
			ErrorHandler("select", WSAGetLastError());
			shutdown(raw,SD_BOTH);
			closesocket(raw);
			return false;
		}
	// Check for and report time-out
		if(rc == 0)
		{
			Errors.Add("ICMP Echo Request timeout.\n");
			shutdown(raw,SD_BOTH);
			closesocket(raw);
			if(i <= 3)
				continue;
			else
				break;
		}

		if(FD_ISSET(raw, &readfds))
			FD_CLR(raw, &readfds);
		// Receive reply
		addrlen = sizeof(struct sockaddr_in);
		rc = recvfrom(raw, (char *) &echo_reply, sizeof(ECHOREPLY), 0, (SOCKADDR *) &from_addr, (int *)&addrlen);
		if (rc == SOCKET_ERROR)
		{
			shutdown(raw,SD_BOTH);
			closesocket(raw);
			return false;
		}

		// Determine elapsed time
		elapsed = GetTickCount() - start;

		// Check for valid reply	
		if (echo_reply.echoRequest.icmpHdr.icmp_type != ICMP_ECHOREPLY) 
		{
			tmp.Format(_T("ICMP type %d Code: %d\n"),
				echo_reply.echoRequest.icmpHdr.icmp_type,
				echo_reply.echoRequest.icmpHdr.icmp_code);
			Errors.Add(tmp);
			shutdown(raw,SD_BOTH);
			closesocket(raw);
			if(i <= 3)
				continue;
		}
		else
		{
			shutdown(raw,SD_BOTH);
			closesocket(raw);
			tmp.Format("Reply from %s %d ms(id=%d seq=%d)\n", node.ipaddress,elapsed, echo_reply.echoRequest.icmpHdr.icmp_id, 
				echo_reply.echoRequest.icmpHdr.icmp_seq);
			ScanResults.Add(tmp);
			return true;
		}
	} // end of for loop
	return false;
}

CString CWfpEngine::SID_get(LPWSTR AccountName)
{
	LPTSTR ReferencedDomain = NULL;
	TCHAR Account[256];
    DWORD cbSid = 128;    // initial allocation attempt
    DWORD cchReferencedDomain=16; // initial allocation size
	DWORD dwSubAuthorities;
	DWORD dwSidSize;
	DWORD dwCounter;
	DWORD dwSidRev = SID_REVISION;
    SID_NAME_USE peUse;
	PSID Sid;
	PSID_IDENTIFIER_AUTHORITY psia;
	CString tmp, sid;

	_snprintf_s(Account, _countof(Account), _TRUNCATE, TEXT("%S"), AccountName);
	
	if((Sid = (PSID)HeapAlloc(GetProcessHeap(), 0, cbSid)) == NULL)
		return sid;

    if((ReferencedDomain = (LPTSTR)HeapAlloc(GetProcessHeap(), 0,
			cchReferencedDomain * sizeof(TCHAR))) == NULL)
	{
		if(Sid != NULL)
			HeapFree(GetProcessHeap(), 0, Sid);
		return sid;
	}

    if(LookupAccountName(node.szComputerM,  // machine to lookup account on
		Account,            // account to lookup
        Sid,                // SID of interest
        &cbSid,             // size of SID
        ReferencedDomain,   // domain account was found on
        &cchReferencedDomain,
        &peUse))
	{
		psia = GetSidIdentifierAuthority(Sid);
		dwSubAuthorities = *GetSidSubAuthorityCount(Sid);
		dwSidSize = (15 + 12 + (12 * dwSubAuthorities) + 1) * sizeof(TCHAR);
		
		// Prepare S-SID_REVISION-.
		tmp.Format(TEXT("SID: S-%lu-"), dwSidRev);
		sid.operator +=(tmp);
   
		// Prepare SidIdentifierAuthority.
		if ((psia->Value[0] != 0) || (psia->Value[1] != 0))
		{
			tmp.Format(TEXT("0x%02hx%02hx%02hx%02hx%02hx%02hx"),
				(USHORT) psia->Value[0],
				(USHORT) psia->Value[1],
				(USHORT) psia->Value[2],
				(USHORT) psia->Value[3],
				(USHORT) psia->Value[4],
				(USHORT) psia->Value[5]);
  
		}
		else
		{   
			tmp.Format(TEXT("%lu"),
				(ULONG) (psia->Value[5]      ) +
				(ULONG) (psia->Value[4] <<  8) +
				(ULONG) (psia->Value[3] << 16) +
				(ULONG) (psia->Value[2] << 24));
		}
		sid.operator +=(tmp);

		// Loop through SidSubAuthorities.
		for (dwCounter = 0; dwCounter < dwSubAuthorities; dwCounter++)
		{
			tmp.Format(TEXT("-%lu"),*GetSidSubAuthority(Sid, dwCounter));
			sid.operator +=(tmp);
		}
	}
	else
	{
		ErrorHandler("LookupAccountName", GetLastError());
		if(ReferencedDomain != NULL)
			HeapFree(GetProcessHeap(), 0, ReferencedDomain);
		if(Sid != NULL)
			HeapFree(GetProcessHeap(), 0, Sid);
		return sid;
	}

    if(ReferencedDomain != NULL)
		HeapFree(GetProcessHeap(), 0, ReferencedDomain);

    if(Sid != NULL)
		HeapFree(GetProcessHeap(), 0, Sid);
  
	return sid;
}

bool CWfpEngine::TCP_Sockets(bool verbose) // Non-blocking connect TCP Portscan for ports with banners
{
	struct sockaddr_in sin;
	struct servent *se;
	struct timeval tv;
	struct linger l_data;
	CList<PSOCK,PSOCK> connect_list, read_list;
	PSOCK lpsock;
	POSITION pos, pos2;
	fd_set readfds, writefds, exceptfds;
	int                n           = 0, // connect() and select() return value;
		               error       = 0, // getsocktopt() SO_ERROR return value
					   timeo       = options.timeout * 1000, // setsockopt() timeout in milliseconds
					   sopts1      = 1;
	
	unsigned short int nchecks     = 0, // Total number of ports to checks
	                   nlefttoread = 0, // Number of ports left to read
	                   nconn       = 0, // Number of current connections
	                   i           = 0; // for loop iterator
			
	unsigned long      icmd        = 1; // ioctlsocket()
    char recvbuff[BUFFSIZE];
	char *line, *next_token;
	CString tmp;
	
	nchecks = (u_short)tcp_connect_ports.GetCount();

	if(nchecks < options.max_connections)
		options.max_connections = nchecks;

	memset(&sin,0,sizeof(sin));
    FD_ZERO(&writefds);
    FD_ZERO(&readfds);
	FD_ZERO(&exceptfds);

	nlefttoread			= nchecks;
	sin.sin_addr.s_addr = node.res;
    tv.tv_sec			= (long)options.timeout; // seconds
    tv.tv_usec			= 0;					    // milliseconds
	l_data.l_linger		= 0;  // desired timeout
	l_data.l_onoff		= 1 ; // enable SO_LINGER
	sin.sin_family      = AF_INET;
  
	while(tcp_connect_ports.GetCount() > 0)
	{
		lpsock = new SOCK;
		lpsock->f_flags  = 0;
		lpsock->f_flags |= F_READY;
		lpsock->portnum  = tcp_connect_ports.GetHead();
		lpsock->status   = 0;
		connect_list.AddTail(lpsock);
		tcp_connect_ports.RemoveHead();
	}
	
    while(nlefttoread > 0)
    {
//		if(pWfpDlg->m_stop)
//			break;
		while((connect_list.GetCount() > 0) && (nconn < options.max_connections))
		{
			lpsock = connect_list.GetHead();
			if((lpsock->f_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
			{
				ErrorHandler("socket", WSAGetLastError());
				continue;
			}

			sin.sin_port = htons (lpsock->portnum);
			setsockopt(lpsock->f_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeo , sizeof(timeo));
			setsockopt(lpsock->f_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeo , sizeof(timeo));
            setsockopt(lpsock->f_fd, SOL_SOCKET, SO_LINGER,   (const char *)&l_data, sizeof(l_data));
			setsockopt(lpsock->f_fd, SOL_SOCKET, SO_REUSEADDR,(const char *)&sopts1, sizeof(sopts1));
			
			// Set non-blocking
			if((ioctlsocket(lpsock->f_fd,FIONBIO,&icmd)) == SOCKET_ERROR )
			{
				ErrorHandler("ioctlsocket", WSAGetLastError());
				if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
					ErrorHandler("closesocket", WSAGetLastError());
				delete lpsock;
				continue;
			}
			
			if(connect(lpsock->f_fd,(struct sockaddr *)&sin,sizeof(sin)) == SOCKET_ERROR)
			{
				// It is normal for WSAEWOULDBLOCK to be reported as the result from calling
				// connect() on a nonblocking SOCK_STREAM socket, since some time
				// must elapse for the connection to be established.
				if(WSAGetLastError()!=WSAEWOULDBLOCK)
				{
					ErrorHandler("connect", WSAGetLastError());
					if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
						ErrorHandler("closesocket", WSAGetLastError());
					if(nlefttoread > 0)
						nlefttoread--;        // Subtract 1 from nlefttoread
					connect_list.RemoveHead();
					delete lpsock;
					continue;
				}
			}    
		    // if connect() returned 0 instead of SOCKET_ERROR, the socket was 
			// connected immediately
			
			Sleep(1); // Sleep 1 ms Drastically improves accuracy
			lpsock->f_flags &= ~(F_READY);
			lpsock->f_flags |= F_CONNECTING; 
			
			// Increase connection count
			if(nconn < options.max_connections)
				nconn++;
			
			FD_SET(lpsock->f_fd, &writefds);
			FD_SET(lpsock->f_fd, &readfds);
			FD_SET(lpsock->f_fd, &exceptfds);
			
			read_list.AddTail(lpsock);
			connect_list.RemoveHead();
		} // end of while((connect_list.GetCount() > 0) && (nconn < node->m_maxconn))

		if((n = select(NULL, &readfds, &writefds, &exceptfds, &tv))== 0) // timeout
		{
			lpsock = read_list.GetHead(); 
			lpsock->status++; // and increase its status by 1
		}
	
		// Run through connections looking for ready sockets
		pos = read_list.GetHeadPosition();
		while(pos != NULL)
		{
			pos2 = pos; // Always maintain a valid POSITION
			lpsock = read_list.GetNext(pos);
			if((lpsock->f_flags & F_CONNECTING) && \
				((FD_ISSET(lpsock->f_fd, &readfds)) || \
				(FD_ISSET(lpsock->f_fd, &writefds)) || \
				(FD_ISSET(lpsock->f_fd, &exceptfds))))
			{
				lpsock->f_flags &= ~(F_CONNECTING);
				
				FD_CLR(lpsock->f_fd, &readfds);		
				FD_CLR(lpsock->f_fd, &writefds);
				FD_CLR(lpsock->f_fd, &exceptfds);
				
				n = sizeof(error);
				if(getsockopt(lpsock->f_fd, SOL_SOCKET, SO_ERROR, (char*)&error, &n) == SOCKET_ERROR)
				{
					ErrorHandler("getsockopt SOCKET_ERROR", WSAGetLastError());
					continue;
				}
				if(error != 0)
				{
					// Confirmed closed
					tmp.Format("%s:%d ", node.ipaddress, lpsock->portnum);
					ErrorHandler(tmp.GetBuffer(), WSAGetLastError());
					shutdown(lpsock->f_fd,SD_BOTH);
					closesocket(lpsock->f_fd);
					read_list.RemoveAt(pos2);
					delete lpsock;
					lpsock = NULL;
					if(nlefttoread > 0)
						nlefttoread--;
					nconn--;
				}
				else // Port is open
				{
					switch(lpsock->portnum)
					{
						case 445:
						case 139:
							if(nbt == false)
								nbt = true;
							if(verbose)
							{
								se = getservbyport(htons(lpsock->portnum),"tcp");
								tmp.Format(_T("\t%s %s:%d/tcp connect() %s\n"),node.ipaddress,
									node.DNS.IsEmpty() ? "" : node.DNS,
									lpsock->portnum, se==NULL ? "" : se->s_name);
								ScanResults.Add(tmp);
							}
							break;
						case 21:  // FTP
						case 22:  // SSH
						case 23:  // Telnet
						case 25:  // SMTP
						case 110: // POP3
						case 119: // NEWS
						case 143: // IMAP
							lpsock->f_flags |= F_READING;    // flag for recv()
							FD_SET(lpsock->f_fd, &readfds);
							Sleep(1000);
							break;
						case 80:  // HTTP
						case 443: // HTTPS
							lpsock->f_flags |= F_READING;    // flag for recv()
							FD_SET(lpsock->f_fd, &readfds);
							if((send(lpsock->f_fd,"HEAD / HTTP/1.0\r\n\r\n",19,0)) == SOCKET_ERROR)
								ErrorHandler("send", WSAGetLastError());
							Sleep(1000); //Without this Sleep() HTTP banner grab is rarely successful
							break;
						default:
							FD_CLR(lpsock->f_fd, &readfds);
							se = getservbyport(htons(lpsock->portnum),"tcp");
							tmp.Format(_T("\t%s %s:%d/tcp %s\n"),node.ipaddress,
								node.DNS.IsEmpty() ? "" : node.DNS,
								lpsock->portnum, se==NULL ? "" : se->s_name);
							ScanResults.Add(tmp);   
							if(shutdown(lpsock->f_fd,SD_BOTH) == SOCKET_ERROR)
								ErrorHandler("shutdown", WSAGetLastError());
							if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
								ErrorHandler("closesocket", WSAGetLastError());
							read_list.RemoveAt(pos2);
							delete lpsock;
							lpsock = NULL;
							if(nlefttoread > 0)
								nlefttoread--;         // Subtract 1 from nlefttoread
							nconn--;
							break;
					} // End of switch()		
				} // End of if getsockopt == 0  
			} // End of FD_ISSET writefds 
			
			if(lpsock != NULL)
			{
				if((lpsock->f_flags & F_READING) && (FD_ISSET(lpsock->f_fd, &readfds)))
				{
					memset(recvbuff,0,sizeof(recvbuff));				
					while((n = recv(lpsock->f_fd,recvbuff,sizeof(recvbuff),0)) > 0 && (n != SOCKET_ERROR))
					{
						lpsock->f_flags &= ~(F_READING);
						FD_CLR(lpsock->f_fd, &readfds);
						line = strtok_s(recvbuff,"\r\n", &next_token);
						while(line !=NULL)
						{
							if(strstr(line,"Server:") || \
							strstr(line,"Servlet-Engine") || \
							strstr(line,"Cisco Live! Meet-Me") || \
							strstr(line,"Telnet Server Build") || \
							strstr(line,"SSH")   || \
							strstr(line,"SMTP")  || \
							strstr(line,"FTP")   || \
							strstr(line,"POP")   || \
							strstr(line,"IMAP")  || \
							strstr(line,"NNTP") || \
							strstr(line,"Internet News Service") || \
							strstr(line,"WinGate") || \
							strstr(line,"Via:"))
							break;
								line = strtok_s(NULL,"\r\n", &next_token);
						}

						se = getservbyport(htons(lpsock->portnum),"tcp");
						tmp.Format(_T("\t%s %s:%d/tcp %s %s\n"),node.ipaddress,
							node.DNS.IsEmpty() ? "" : node.DNS,
							lpsock->portnum, se==NULL ? "" : se->s_name,
							line == NULL ? "Open, No Banner" : line);
						ScanResults.Add(tmp);
						if(line != NULL)
							memset(line,0,sizeof(line));
						if(shutdown(lpsock->f_fd,SD_BOTH) == SOCKET_ERROR)
							ErrorHandler("shutdown", WSAGetLastError());
						if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
							ErrorHandler("closesocket", WSAGetLastError());
						read_list.RemoveAt(pos2);
						delete lpsock;
						lpsock = NULL;
						if(nlefttoread > 0)       // Safety check
							nlefttoread--;        // Subtract 1 from nlefttoread
						nconn--;
						break;
					} // End of while(recv())
				}
			} // End of if lpsock != NULL
			
			if(lpsock != NULL)
			{
				if(lpsock->status >= options.retries)
				{
					FD_CLR(lpsock->f_fd, &writefds);
					FD_CLR(lpsock->f_fd, &readfds);
					if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
						ErrorHandler("closesocket", WSAGetLastError());
					read_list.RemoveAt(pos2);
					delete lpsock;
					if(nlefttoread > 0)
						nlefttoread--;
					nconn--;
				}
				else
					lpsock->status++;
			}
		} // End of for loop
	} // End of nlefttoread > 0
	return true;
}

bool CWfpEngine::Trace(addrinfo *res)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	HANDLE hIP;
	CString tmp;
	traceroute_reply trr;
    IN_ADDR stDestAddr;
	struct hostent *host = NULL;
	stDestAddr.s_addr = *(u_long*)node.ipaddress;

	// Prevent ICMP from being called if it wont work
	if(!have_icmp)
		return false;

	tmp.Format("Tracing route to %s\n",node.ipaddress);   
	ScanResults.Add(tmp); 

	BOOL bReachedHost = FALSE;
	// 30 is hop count
	for(UCHAR nTTL=1; nTTL<= 30 && !bReachedHost; nTTL++)
	{
		TRACE_MULTI_REPLY htrr;
		htrr.dwError = 0;
		htrr.minRTT = ULONG_MAX;
		htrr.avgRTT = 0;
		htrr.maxRTT = 0;

		//Iterate through all the pings for each host
		DWORD totalRTT = 0;
		TRACE_SINGLE_REPLY htsr;
		htsr.Address.S_un.S_addr = 0;
		htsr.dwError = 0;
		BOOL bPingError = FALSE;
		unsigned long myres = 0;
		
		for(int j=0; j < 3 && !bPingError; j++)
		{
			// IcmpCreateFile() - Open the ping service
			if((hIP = pIcmpCreateFile()) == INVALID_HANDLE_VALUE)
			{
				ErrorHandler("IcmpCreateFile", GetLastError());
				return false;
			}
			
			//Set up the option info structure
			IP_OPTION_INFORMATION OptionInfo;
			ZeroMemory(&OptionInfo, sizeof(IP_OPTION_INFORMATION));
			OptionInfo.Ttl = nTTL;

			//Set up the data which will be sent
			unsigned char* pBuf = new unsigned char[32];
			memset(pBuf, 'E', 32);

			//Do the actual Ping
			int nReplySize = sizeof(ICMP_ECHO_REPLY) + max(MIN_ICMP_PACKET_SIZE, 32);
			unsigned char* pReply = new unsigned char[nReplySize];
			ICMP_ECHO_REPLY* pEchoReply = (ICMP_ECHO_REPLY*) pReply;
			DWORD nRecvPackets = pIcmpSendEcho(hIP, node.res, pBuf, 32, &OptionInfo, pReply, nReplySize, 30000);

			//Check we got the packet back
			if (nRecvPackets != 1)
				htsr.dwError = GetLastError();
			else
			{
				//Ping was successful, copy over the pertinent info
				//into the return structure
				htsr.Address.S_un.S_addr = pEchoReply->Address;
				htsr.RTT = pEchoReply->RoundTripTime;
			}

			//Close the ICMP handle
			pIcmpCloseHandle(hIP);

			//Free up the memory we allocated
			delete [] pBuf;
			delete [] pReply;

			if (htsr.dwError == 0)
			{
				//Acumulate the total RTT
				totalRTT += htsr.RTT;

				//Store away the RTT's
				if (htsr.RTT < htrr.minRTT)
					htrr.minRTT = htsr.RTT;
				if (htsr.RTT > htrr.maxRTT)
					htrr.maxRTT = htsr.RTT;
			}
			else
			{
				htrr.dwError = htsr.dwError;
				bPingError = TRUE;
			}
		} // end of ping loop
		htrr.Address = htsr.Address;
		if (htrr.dwError == 0)
			htrr.avgRTT = totalRTT / 3;
		else
		{
			htrr.minRTT = 0;
			htrr.avgRTT = 0;
			htrr.maxRTT = 0;
		}

		if(htrr.dwError == 0)
		{
			tmp.Format(_T(" %d\t%d ms\t%d ms\t%d ms\t%d.%d.%d.%d "), nTTL, htrr.minRTT, htrr.avgRTT, htrr.maxRTT,
               htrr.Address.S_un.S_un_b.s_b1, htrr.Address.S_un.S_un_b.s_b2, htrr.Address.S_un.S_un_b.s_b3, 
		  		     htrr.Address.S_un.S_un_b.s_b4);
			ScanResults.Add(tmp);

			myres = htrr.Address.S_un.S_addr;
			host = gethostbyaddr ((char*) &myres, sizeof(myres), AF_INET);
			tmp.Format("%s\n", host!=NULL ? host->h_name : "");
			ScanResults.Add(tmp); 
		}
		else
		{
			tmp.Format(_T("  %d\t*\t*\t*\tError:%d\n"), nTTL, htrr.dwError);
			ScanResults.Add(tmp);
			
		}
		//Add to the list of hosts
		trr.Add(htrr);
		//Have we reached the final host ?
		if(node.res == htrr.Address.S_un.S_addr)
		{
			bReachedHost = TRUE;
		}
	}
    return true;
}

bool CWfpEngine::UDP_Sockets(unsigned short UDPStartPort, unsigned short UDPEndPort, int type) // Non-blocking UDP Portscan
{
	struct sockaddr_in sin, zero;
	struct servent *se;
	struct timeval tv;
	CList<PSOCK,PSOCK> connect_list, read_list;
	PSOCK lpsock;
	POSITION pos, pos2;
	fd_set readfds;
	int                s           = 0, // connect() and select() return value;
					   ret		   = 0,
					   timeo       = options.timeout * 1000, // setsockopt() timeout
					   total       = 0,
					   i           = 0,
					   j           = 0,
					   index       = 0,
					   counter     = 0;
	unsigned short int nchecks     = 0, // Total number of ports to checks
	                   nlefttoread = 0, // Number of ports left to read
	                   nlefttoconn = 0, // Number of ports left to connect()
	                   nconn       = 0; // Number of current connections
	                 
	unsigned long      icmd        = 1; // ioctlsocket()
    char data[1], recvbuff[256], temp[CNLEN+1];
	char nbtstat[]= "\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01";
	char sqlping[]= "\x02";
	char *ptr;
	unsigned int nb_num, nb_type;
	CString tmp;
	
    // Determine the total number of ports to check.
    // If the total number of ports to check is less than FD_SETSIZE
    // set the maximum number of connections to the number of ports
    // if the total number of ports is greater than FD_SETSIZE limit
    // the maximum connections to FD_SETSIZE
   
	// For a connectionless socket(SOCK_DGRAM),
	// the operation performed by connect is merely to establish a
	// default destination address that can be used on subsequent
	// send() and recv() calls. Any datagrams received from an
	// address other than the destination address specified will be discarded.
	// If the address member of the structure specified by name is all zeroes,
	// the socket will be disconnected.
	// Winfingerprint's UDPSockets() will use 'zero' for this purpose.

	memset(&zero,0,sizeof(zero));

	nchecks = (UDPEndPort - UDPStartPort) + 1; 
   
	if(nchecks < options.max_connections)
		options.max_connections = nchecks;
      
    nlefttoread = nlefttoconn = nchecks;
    
	memset(&sin,0,sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = node.res;
    
    FD_ZERO(&readfds);
	tv.tv_sec =  options.timeout; //seconds
    tv.tv_usec = 0;                  //microseconds
	
	// Initialize all ports to be scanned for this host to F_READY status
    // it does not matter if we exceed FD_SETSIZE for initialation as the 
    // ports are not added to the FD_SET until later

  	for (i = 0; i < nchecks; i++)
    {
		lpsock = new SOCK;
		lpsock->f_flags  = 0;
		lpsock->f_flags |= F_READY;
		lpsock->portnum  = UDPStartPort + (unsigned short)i;
		lpsock->status   = 0;
		connect_list.AddTail(lpsock);
	}

    while (nlefttoread > 0)
    {
//		if(pWfpDlg->m_stop)
//			break;
		while(connect_list.GetCount() > 0)
		{
			lpsock = connect_list.GetHead();
           
			if((lpsock->f_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
			{
				ErrorHandler("socket", WSAGetLastError());
				continue;
			}

			sin.sin_port = htons (lpsock->portnum);
			setsockopt(lpsock->f_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeo , sizeof(timeo));
			setsockopt(lpsock->f_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeo , sizeof(timeo));
			
			if((ioctlsocket(lpsock->f_fd,FIONBIO,&icmd)) == SOCKET_ERROR )
			{
				ErrorHandler("ioctlsocket", WSAGetLastError());
				connect(lpsock->f_fd,(struct sockaddr *)&zero,sizeof(zero));
				if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
					ErrorHandler("closesocket", WSAGetLastError());
				delete lpsock;
				continue;
			}
			
			if((s = connect(lpsock->f_fd,(struct sockaddr *)&sin,sizeof(sin))) == SOCKET_ERROR)
				ErrorHandler("connect", WSAGetLastError());
			else
			{
				nconn++;       // Add 1 to number of connections 
				if(nlefttoconn > 0)
					nlefttoconn--; // Subtract 1 from number left to connect
				// With a "connected" UDP socket, we must use 
				// send() instead of sendto()
				if(lpsock->portnum == 137 && (type == 1))
				{
					ret = send(lpsock->f_fd,nbtstat,sizeof(nbtstat)-1,0);
				}
				else if((lpsock->portnum == 1434) && (type == 2))
					ret = send(lpsock->f_fd,sqlping,sizeof(sqlping),0);
				else
					ret = send(lpsock->f_fd,data,0,0);
					
				if(ret == SOCKET_ERROR)
				{
					connect(lpsock->f_fd,(struct sockaddr *)&zero,sizeof(zero));
					if(shutdown(lpsock->f_fd,SD_BOTH) == SOCKET_ERROR)
						ErrorHandler("shutdown", WSAGetLastError());
					if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
						ErrorHandler("closesocket", WSAGetLastError());
					connect_list.RemoveHead();
					delete lpsock;
						if(nconn > 0)
						nconn--;              // Subtract 1 from number of connections
					if(nlefttoread > 0)
						nlefttoread--;        // Subtract 1 from nlefttoread
				}
				else
				{
					lpsock->f_flags &= ~(F_READY);
					lpsock->f_flags |= F_READING;
					FD_SET(lpsock->f_fd, &readfds);
					read_list.AddTail(lpsock);
					connect_list.RemoveHead();
				}
			}
		} // nconn < maxnconn && nlefttoconn > 0 
		
		if((s = select(NULL, &readfds,NULL, NULL, &tv))== 0) // timeout
		{
			lpsock = read_list.GetHead(); 
			lpsock->status++; // and increase its status by 1
		}
	
		// Run through connections looking for ready sockets
		pos = read_list.GetHeadPosition();
		while(pos != NULL)
		{
			pos2 = pos; // Always maintain a valid POSITION
			lpsock = read_list.GetNext(pos);

			if((lpsock->f_flags & F_READING) && (FD_ISSET(lpsock->f_fd, &readfds)))
			{
				FD_CLR(lpsock->f_fd, &readfds);   // Remove fd from read set
				// "connected" UDP sockets must use recv() rather than recvfrom()
				
				if(type == 0) // Regular portscan
				{
					if((ret = recv(lpsock->f_fd,data,sizeof(data),0)) == SOCKET_ERROR)
					{
						if(WSAGetLastError() == WSAECONNRESET) //ICMP Port Unreachable
						{
							connect(lpsock->f_fd,(struct sockaddr *)&zero,sizeof(zero));
							if(shutdown(lpsock->f_fd,SD_BOTH) == SOCKET_ERROR)
								ErrorHandler("shutdown", WSAGetLastError());
							if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
								ErrorHandler("closesocket", WSAGetLastError());
							read_list.RemoveAt(pos2);
							delete lpsock;
							if(nconn > 0)
								nconn--;              // Subtract 1 from number of connections
							if(nlefttoread > 0)
								nlefttoread--;        // Subtract 1 from nlefttoread
						}
					}
				} // end of type 0
				else if((lpsock->portnum == 137) && (type == 1))
				{
					memset(recvbuff, 0, sizeof(recvbuff));
					ret = recv(lpsock->f_fd,recvbuff,sizeof(recvbuff),0);
					ptr=recvbuff+57;
 					total=*(ptr - 1); // max names 
					while(ptr < recvbuff + sizeof(recvbuff))
					{
						memset(temp,0, sizeof(temp));
						strncpy_s(temp, _countof(temp), ptr, _TRUNCATE); 	// copies the name into temp
						ptr+=15;
						nb_num  = *ptr; 
						nb_type = *(ptr + 1);
						ptr+=3;
						if(j == total)
						{
							ptr-=19;
							// FIXME
							//if(options.optionmacaddress)
							//	if(node->MAC_Address.GetSize() == 0) 
							//	{
							//		tmp.Format("%02x%02x%02x%02x%02x%02x",
							//			*(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4),*(ptr+5),*(ptr+6));
							//		tmp.Replace("ffffff",""); //Junk cleanup
							//		node->MAC_Address.Add(tmp);
							//	}
							break;
						}

						if(nb_num == 0x00)
						{
							if (nb_type > 0x80) // Domain
							{
								if(temp)
								{
									if(node.Domain.IsEmpty())
									{
										tmp.Format("%s",temp);
										tmp.TrimRight(" ");
										node.Domain.operator +=(tmp);
									}									
								}
							}
						}
					
						if(nb_num ==0x20) // Computername	
						{
							if(temp)
							{
								if(node.NetBIOS.IsEmpty())
								{
									tmp.Format("%s", temp);
									tmp.TrimRight(" ");
									node.NetBIOS.operator +=(tmp);
								}
							}
						}
						j++;
					}

					connect(lpsock->f_fd,(struct sockaddr *)&zero,sizeof(zero));
					if(shutdown(lpsock->f_fd,SD_BOTH) == SOCKET_ERROR)
						ErrorHandler("shutdown", WSAGetLastError());
					if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
						ErrorHandler("closesocket", WSAGetLastError());
					read_list.RemoveAt(pos2);
				
					delete lpsock;	
					if(nconn > 0)
						nconn--;              // Subtract 1 from number of connections
					if(nlefttoread > 0)
						nlefttoread--;        // Subtract 1 from nlefttoread
				}
				else if((lpsock->portnum == 1434) && (type == 2))
				{
					memset(recvbuff, 0, sizeof(recvbuff));
					ret = recv(lpsock->f_fd,recvbuff,sizeof(recvbuff),0);
					for (index = 3; index < ret; index++)
					{
						if ((recvbuff[index] == ';') && (recvbuff[index+1] != ';')) 
						{  
							//Look for a semi-colon and check for end of record (;;)
							if ((counter % 2) == 0) 
							{ 
//FIXME								pWfpDlg->InsertString(":");
								counter++; 
							}
							else
							{
//FIXME								pWfpDlg->InsertString("\n");
								counter++; 
							}
						}
						else 
						{
							if (recvbuff[index] != ';') 
							{  
								// If an end of record (;;), then double-space for next instance
								tmp.Format("%c",recvbuff[index]);
//FIXME								pWfpDlg->InsertString(tmp);
							}
							else
							{
//FIXME								pWfpDlg->InsertString("\n");
							}
						}
					}

//FIXME					pWfpDlg->InsertString("\n");
					connect(lpsock->f_fd,(struct sockaddr *)&zero,sizeof(zero));
					if(shutdown(lpsock->f_fd,SD_BOTH) == SOCKET_ERROR)
						ErrorHandler("shutdown", WSAGetLastError());
					if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
						ErrorHandler("closesocket", WSAGetLastError());
					read_list.RemoveAt(pos2);
					delete lpsock;
					if(nconn > 0)
						nconn--;              // Subtract 1 from number of connections
					if(nlefttoread > 0)
						nlefttoread--;        // Subtract 1 from nlefttoread
				} // end of sqlping
			} // end of FD_ISSET			
			else if(lpsock->status < options.retries)
			{
				lpsock->status++;
			//	FD_SET(file[i].f_fd, &readfds);
			//	lpsock->f_flags = 0;
			//	lpsock->f_flags |= F_READING;
				// send() multiple times.
				if(lpsock->portnum == 137 && (type == 1))
					ret = send(lpsock->f_fd,nbtstat,sizeof(nbtstat)-1,0);
				else if((lpsock->portnum == 1434) && (type == 2))
					ret = send(lpsock->f_fd,sqlping,sizeof(sqlping),0);
				else
					ret = send(lpsock->f_fd,data,0,0);
				// Sleep an increasing amount of time per resend
				Sleep(lpsock->status * 10);
					
				if(ret == SOCKET_ERROR)
				{
					if(lpsock->f_flags & F_READING)
						FD_CLR(lpsock->f_fd, &readfds);

					connect(lpsock->f_fd,(struct sockaddr *)&zero,sizeof(zero));
					if(shutdown(lpsock->f_fd,SD_BOTH) == SOCKET_ERROR)
						ErrorHandler("shutdown", WSAGetLastError());
					if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
						ErrorHandler("closesocket", WSAGetLastError());
					read_list.RemoveAt(pos2);
					delete lpsock;
					if(nconn > 0)
						nconn--;              // Subtract 1 from number of connections
					if(nlefttoread > 0)
						nlefttoread--;        // Subtract 1 from nlefttoread
				}
			}
			else
			{
				//FIXME pWfpDlg->InsertString("No response from nbtstat packet\n");
		
				FD_CLR(lpsock->f_fd, &readfds);		
				se = getservbyport(htons(lpsock->portnum),"udp");
				tmp.Format(_T("\t%s %s %d udp %s\n"),node.ipaddress,
					node.DNS.IsEmpty() ? "" : node.DNS,
					lpsock->portnum, se==NULL ? "" : se->s_name);
				ScanResults.Add(tmp);
				connect(lpsock->f_fd,(struct sockaddr *)&zero,sizeof(zero));
				if(shutdown(lpsock->f_fd,SD_BOTH) == SOCKET_ERROR)
					ErrorHandler("shutdown", WSAGetLastError());
				if(closesocket(lpsock->f_fd) == SOCKET_ERROR)
					ErrorHandler("closesocket", WSAGetLastError());
				read_list.RemoveAt(pos2);
				delete lpsock;
				if(nconn > 0)
					nconn--;              // Subtract 1 from number of connections
				if(nlefttoread > 0)
					nlefttoread--;        // Subtract 1 from nlefttoread
			}
		} // End of q <= nchecks 
	} // End of nlefttoread > 0
	return true;
}

unsigned short CWfpEngine::in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	//  Our algorithm is simple, using a 32 bit accumulator (sum),
	//  we add sequential 16 bit words to it, and at the end, fold
	//  back all the carry bits from the top 16 bits into the lower
	//  16 bits.
	
	while(nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	// mop up an odd byte, if necessary 
	if(nleft == 1)
	{
		u_short	u = 0;
		*(u_char *)(&u) = *(u_char *)w ;
		sum += u;
	}

	// add back carry outs from top 16 bits to low 16 bits
	
	sum = (sum >> 16) + (sum & 0xffff);	// add hi 16 to low 16 
	sum += (sum >> 16);			// add carry 
	answer = (u_short) ~sum;	// truncate to 16 bits 
	return (answer);
}

bool CWfpEngine::DatabaseConnect() // Check for sa passwords
{
	return true;
	/*if (mysql_library_init(0, NULL, NULL)) {
		fprintf(stderr, "could not initialize MySQL library\n");
		return false;
	}*/
	mysql = mysql_init(NULL);
	//mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, "libmysqld_client");
	//mysql_options(mysql, MYSQL_OPT_USE_EMBEDDED_CONNECTION, NULL);
	//mysql_real_connect(mysql, NULL,NULL,NULL, "winfingerprint", 0,NULL,0);

	return true;
}

bool CWfpEngine::DatabaseDisconnect()
{
	//mysql_close(mysql);
	//mysql_library_end();
	return true;
}

bool CWfpEngine::EnumNeighborhood(LPNETRESOURCE lpnr, CString *result)
{
	DWORD nStatus = 0, nStatusEnum = 0, i = 0;
	HANDLE hEnum;
	DWORD cbBuffer = 37268;      // 32K is a good size
	DWORD cEntries = (DWORD) -1; // enumerate all possible entries
	LPNETRESOURCE lpnrLocal;     // pointer to enumerated structures
	CString tmp;
	DWORD dwWNetResult = 0; 
    CHAR szDescription[256]; 
    CHAR szProvider[256];
//	PNODE pNode;
	
	nStatus = WNetOpenEnum(RESOURCE_GLOBALNET, // all network resources
		RESOURCETYPE_ANY,   // all resources
		0,        // enumerate all resources
		lpnr,     // NULL first time the function is called
		&hEnum);  // handle to the resource

	if(nStatus != NO_ERROR)
	{
		if(nStatus == ERROR_EXTENDED_ERROR)
		{
			dwWNetResult = WNetGetLastError(&nStatus, // error code
            (LPSTR) szDescription,  // buffer for error description 
            sizeof(szDescription),  // size of error buffer
            (LPSTR) szProvider,     // buffer for provider name 
            sizeof(szProvider));    // size of name buffer
 
			if(dwWNetResult != NO_ERROR)
			{
//				if(pWfpDlg->opt_showerror)
//				{
				tmp.Format("WNetGetLastError failed; error %ld\n", dwWNetResult);
				Errors.Add(tmp);
//				}
				return (0); 
			} 
//			if(pWfpDlg->opt_showerror)
//			{
			tmp.Format("%s failed with code %ld;\n%s\n", 
					(LPSTR) szProvider, nStatus, (LPSTR) szDescription); 
				Errors.Add(tmp);
//			}
			return(0); 
		}
		else if(nStatus == ERROR_NOT_CONTAINER)
			Errors.Add("ERROR_NOT_CONTAINER");
		else if(nStatus == ERROR_INVALID_PARAMETER)
			Errors.Add("ERROR_INVALID_PARAMETER");
		else if(nStatus == ERROR_NO_NETWORK)
			Errors.Add("ERROR_NO_NETWORK");
		else if (nStatus == ERROR_INVALID_ADDRESS)
			Errors.Add("ERROR_INVALID_ADDRESS");
		else
		{
			tmp.Format("error %d\n", nStatus);
			Errors.Add(tmp);
		}
		ErrorHandler("WNetOpenEnum", nStatus);
		return(0);
	}
	
	if((lpnrLocal = (LPNETRESOURCE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer)) == NULL)
	{
		Errors.Add("HeapAlloc Error\n");
		return(0);
	}
	
	do
	{  
		nStatusEnum = WNetEnumResource(hEnum,       // resource handle
			&cEntries,  // defined locally as -1
			lpnrLocal,  // LPNETRESOURCE
			&cbBuffer); // buffer size

		if(nStatusEnum == NO_ERROR)
		{
			for(i = 0; i < cEntries; i++)
			{
//				if(pWfpDlg->m_stop)
//					break;

				if(lpnrLocal[i].dwDisplayType == RESOURCEDISPLAYTYPE_SERVER)
				{
					ScanHost(lpnrLocal[i].lpRemoteName+2);
				} 
			
//				if(pWfpDlg->opt_shares)
//				{
//					if(lpnrLocal[i].dwDisplayType == RESOURCEDISPLAYTYPE_SHARE)   
//					{   
//						tmp.Format("NetBIOS Share: %s\n",lpnrLocal[i].lpRemoteName);   
//						pWfpDlg->InsertString(tmp);
//					}
//				}
				// If the NETRESOURCE structure represents a container resource, 
				//  call the Neighborhood function recursively.
				if(RESOURCEUSAGE_CONTAINER == (lpnrLocal[i].dwUsage & RESOURCEUSAGE_CONTAINER))
					EnumNeighborhood(&lpnrLocal[i], result);			
			} 
		}
		else if (nStatusEnum != ERROR_NO_MORE_ITEMS)
		{
			ErrorHandler("WNetCloseEnum", nStatusEnum);
			break;
		}
	}while(nStatusEnum != ERROR_NO_MORE_ITEMS);
  
	if(lpnrLocal != NULL)
		HeapFree(GetProcessHeap(), 0, lpnrLocal);
  
	nStatus = WNetCloseEnum(hEnum);
	
	if(nStatus != NO_ERROR)
	{
		ErrorHandler("WNetCloseEnum", nStatus);
		return false;
	}
	return true;
}

CString CWfpEngine::Output(CStringArray *Array)
{
	CString results;
	if(Array->GetSize() > 0) 
	{
		for(int i = 0; i <= Array->GetUpperBound(); i++)
		{
			results.operator +=(Array->GetAt(i));
			results.operator +=("\n");
		//	MessageBox(NULL, results, "Results", MB_OK);
		}	
	}
	//else
	//	MessageBox(NULL, "Array empty", "Error", MB_OK);
	return results;
}

bool CWfpEngine::NetBIOSShares_get(void)
{
	MessageBox(NULL, "not good", "Error", MB_OK);
	return false;
}

bool CWfpEngine::Sessions_get(void)
{
	MessageBox(NULL, "not good", "Error", MB_OK);
	return false;
}

bool CWfpEngine::ScanFiles(CString directory, CString filemask)
{
	CString tmp;
	RETCODE retcode;
	hstmt = SQL_NULL_HSTMT;
	using_database = true;
	
	//DatabaseConnect();

	if(using_database)
	{
		retcode = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);
		if((retcode != SQL_SUCCESS_WITH_INFO) && (retcode != SQL_SUCCESS))
		{
			ErrorHandler("SQLAllocHandle", retcode);
			return false;
		}
	}
	
	if(!SetCurrentDirectory(directory))
	{
		ErrorHandler("SetCurrentDirectory", GetLastError());
		return false;
	}
	else
	{	
		DirectoryListContents(directory, filemask);
		
	//	if(using_database)
	//		DatabaseDisconnect();
	}
	return true;
}

bool CWfpEngine::DirectoryListContents(CString directory, CString filemask) {

	char curDir[_MAX_PATH];
	char printDir[_MAX_PATH];
	char temp[_MAX_PATH];
	CString tmp;
	HANDLE fileHandle;
	WIN32_FIND_DATA findData;
	// save current dir so it can restore it
	if(!GetCurrentDirectory(_MAX_PATH, curDir)) 
		return false;

	// if the directory name is neither . or .. then
	// change to it, otherwise ignore it

	if(strcmp(directory, ".") && strcmp(directory, ".." ))
	{
		if(!SetCurrentDirectory(directory)) 
			return false;
		if(!GetCurrentDirectory(_MAX_PATH, printDir)) 
			return false;
	}
	else 
		return true;

	// Loop through all files looking for 
	// the file name of interest.

	fileHandle = FindFirstFile(filemask, &findData);
	while(fileHandle != INVALID_HANDLE_VALUE)
	{
		Win32FindData_get(&findData, printDir, 0);
  		// loop thru remaining entries in the dir
		if(!FindNextFile(fileHandle, &findData))
			break;
 	}
	FindClose(fileHandle);

	// Loop through all files in the directory
	// looking for other directories

	fileHandle = FindFirstFile("*.*", &findData);
	while(fileHandle != INVALID_HANDLE_VALUE)
	{
			// If the name is a directory,
			// recursively walk it.
		if(!options.optionnodirectoryrecurse)
			{
				if(findData.dwFileAttributes &	FILE_ATTRIBUTE_DIRECTORY)
				{
					_snprintf_s(temp, _countof(temp), _TRUNCATE, "%s", findData.cFileName);
					ScanFiles(findData.cFileName, filemask);
				}
			}
  		// loop thru remaining entries in the dir

		if(!FindNextFile(fileHandle, &findData))
			break;
 	}

	// clean up and restore directory
	FindClose( fileHandle );
	SetCurrentDirectory( curDir );
	return(0);
}

int CWfpEngine::Win32FindData_get(WIN32_FIND_DATA *findData, char *directory, DWORD pid)
{
	FILETIME ft;
	SYSTEMTIME st;
	DWORD dwSerialNumber = 0, dwMaxComponentLen = 0, dwFileSysFlags = 0;
	BOOL bRetCode;
	char filename[_MAX_PATH];
	char *driveletter = NULL, *filepart = NULL;
	int iActualItem = 0;
	TCHAR szApp[MAX_PATH];
	char volumename[MAX_PATH], volumeserial[MAX_PATH], szFileSysName[80];
	char szHash[HASHLEN], rootpathname[4], temp[MAX_PATH];
	char *next_token;
    LPTSTR pszPath;
	CString tmp, attributes;
	SQLINTEGER NativeError, sizeInt;
	RETCODE retcode;
	SQLCHAR SqlState[6], Msg[SQL_MAX_MESSAGE_LENGTH];
	SQLSMALLINT i, MsgLen;
	SQLRETURN rc2;
	LPSTR lpBuffer;
	DWORD dwVerInfoSize = 0, dwVerHnd = 0;
	UINT *dwBytes = new UINT;
	LPTSTR lpstrVffInfo;
	VS_FIXEDFILEINFO *pinfo;	
	HANDLE hMem;
	bool foundpath = false;
	char fileversion[255], productversion[255], companyname[255], filedescription[255], productname[255];
  
	// Get the full path of the filename
	// Do not call when enumerating processes
	if(options.scan_type != SCAN_PROCESSES)
		if((GetFullPathName(findData->cFileName, _MAX_PATH, filename, &filepart)) != 0)
			foundpath = true;

	if(!foundpath)
	{
		if(SearchPath(NULL, findData->cFileName, NULL, _MAX_PATH, szApp, &pszPath))
		{
			_snprintf_s(filename, _countof(filename), _TRUNCATE, "%s", szApp);
			foundpath = true;
		}
		else // SearchPath failed, use findData->cFileName
		{
			_snprintf_s(filename, _countof(filename), _TRUNCATE, "%s", findData->cFileName);
		}
	}

	// Process Hash Digest before we slice up filename with strtok
	memset(szHash, 0, sizeof(szHash));
	_snprintf_s(szHash, _countof(szHash), _TRUNCATE, "%s", HashDigest_get(filename));

	retcode = SQLPrepare(hstmt,
		(SQLCHAR *)"INSERT INTO FILEDATA (filename, volumename, volumeserial, scantime, filesize, creation, accessed, modified, attributes, filedescription, fileversion, companyname, productname, productversion, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		SQL_NTS);
	
	if((retcode != SQL_SUCCESS_WITH_INFO) && (retcode != SQL_SUCCESS))
	{
		i = 1;
		while ((rc2 = SQLGetDiagRec(SQL_HANDLE_STMT, hstmt, i, SqlState, &NativeError,
			Msg, sizeof(Msg), &MsgLen)) != SQL_NO_DATA) {
				tmp.Format("%s %d %s %d ",
					SqlState,NativeError,Msg,MsgLen);
				MessageBox(NULL, tmp, "SQLGetDiagRec Info (SQLPrepare)",MB_OK);
			i++;
		}
		return(-1);
	}
		
	sizeInt = SQL_NTS;

	WfpSQLBindParameter(SQL_VARCHAR,1,(void *)filename);
	
	_snprintf_s(temp, _countof(temp), _TRUNCATE, "%s", filename);
	driveletter = strtok_s(temp,"\\", &next_token);
	memset(rootpathname, 0, sizeof(rootpathname));
	memset(&volumename, 0, sizeof(volumename));
	memset(&volumeserial, 0,sizeof(volumeserial));
	_snprintf_s(rootpathname, _countof(rootpathname), _TRUNCATE, "%s\\", driveletter);
		
	bRetCode = GetVolumeInformation(rootpathname, // volume of current dirctory
		volumename, MAX_PATH,&dwSerialNumber, &dwMaxComponentLen,
		&dwFileSysFlags, szFileSysName, 80);

	if(!bRetCode)
		_snprintf_s(volumename, _countof(volumename), _TRUNCATE, "%s", "");
	
	WfpSQLBindParameter(SQL_VARCHAR,2,(void *)volumename);
	
	_snprintf_s(volumeserial, _countof(volumeserial), _TRUNCATE, "%#lx", dwSerialNumber);
	
	WfpSQLBindParameter(SQL_VARCHAR,3,(void *)volumeserial);
	
	WfpSQLBindParameter(SQL_INTEGER,5,(void *)&findData->nFileSizeLow);
	
	// Creation Time
	FileTimeToLocalFileTime(&findData->ftCreationTime, &ft);
	FileTimeToSystemTime(&ft, &st);

	_snprintf_s(temp, _countof(temp), _TRUNCATE, "%d-%.2d-%.2d %.2d:%.2d:%.2d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	WfpSQLBindParameter(SQL_C_TIMESTAMP,6,(void *)&st);
	
	
	// Last Accessed Time
	FileTimeToLocalFileTime(&findData->ftLastAccessTime , &ft); // ftLastAccessTime
	FileTimeToSystemTime(&ft, &st);

	_snprintf_s(temp, _countof(temp), _TRUNCATE, "%d-%.2d-%.2d %.2d:%.2d:%.2d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	
	WfpSQLBindParameter(SQL_C_TIMESTAMP,7,(void *)&st);
	

	if(findData->dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)
		attributes.operator +=("ARCHIVE ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED)
		attributes.operator +=("COMPRESSED ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		attributes.operator +=("DIRECTORY ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED)
		attributes.operator +=("ENCRYPTED ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
		attributes.operator +=("HIDDEN ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_NORMAL)
		attributes.operator +=("NORMAL ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_OFFLINE)
		attributes.operator +=("OFFLINE ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_READONLY)
		attributes.operator +=("READONLY ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		attributes.operator +=("REPARSE_POINT ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE)
		attributes.operator +=("SPARSE_FILE ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
		attributes.operator +=("SYSTEM ");
	if(findData->dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY)
		attributes.operator +=("TEMPORARY ");

	FileTimeToLocalFileTime(&findData->ftLastWriteTime, &ft);	  // ftLastWriteTime 
	FileTimeToSystemTime(&ft, &st);

	_snprintf_s(temp, _countof(temp), _TRUNCATE, "%d-%.2d-%.2d %.2d:%.2d:%.2d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	WfpSQLBindParameter(SQL_C_TIMESTAMP,8,(void *)&st);

	WfpSQLBindParameter(SQL_VARCHAR,9,(void *)attributes.GetBuffer());

	memset(&filedescription, 0, sizeof(filedescription));
	memset(&fileversion,0,sizeof(fileversion));
	memset(&companyname, 0, sizeof(companyname));
	memset(&productname, 0, sizeof(productname));
	memset(&productversion, 0, sizeof(productversion));
	
	if((dwVerInfoSize = GetFileVersionInfoSize(filename, &dwVerHnd)) != 0)
	{
		hMem = GlobalAlloc(GMEM_MOVEABLE, dwVerInfoSize);
		lpstrVffInfo  = (char *)GlobalLock(hMem);

		GetFileVersionInfo(filename, dwVerHnd, dwVerInfoSize, lpstrVffInfo);
		
		// "\\" Specifies root block
		if((bRetCode = VerQueryValue((LPVOID)lpstrVffInfo,"\\",(void**)&pinfo, dwBytes)) != 0)
		{
			_snprintf_s(fileversion, _countof(fileversion), _TRUNCATE, "%u.%u.%u.%u",
				HIWORD(pinfo->dwFileVersionMS),
				LOWORD(pinfo->dwFileVersionMS),
				HIWORD(pinfo->dwFileVersionLS),
				LOWORD(pinfo->dwFileVersionLS));
	   
			_snprintf_s(productversion, _countof(productversion), _TRUNCATE, "%u.%u.%u.%u",
				HIWORD(pinfo->dwProductVersionMS),
				LOWORD(pinfo->dwProductVersionMS),
				HIWORD(pinfo->dwProductVersionLS),
				LOWORD(pinfo->dwProductVersionLS));
			
		}

		if(pinfo->dwFileType & VFT_APP)
		{	
			// Here is a simple routine for those who read the source
//			if(pWininterrogateDlg->buffersize > 0)
//			{
				//if((pWininterrogateDlg->buffersize > (32766 - strlen(fullName))))
				//	pWininterrogateDlg->buffersize = (32766 - strlen(fullName));
				// Be unique and fill buffer with 0x41
				
//				Debugger(filename);
//			}
		}

		char * predefResStrings[] = {	"FileDescription",
										"CompanyName",
										//"InternalName",
										//"LegalCopyright",
										//"OriginalFilename",
										"ProductName",
										//	"Comments",
										//	"LegalTrademarks",
										//	"PrivateBuild",
										//	"SpecialBuild",
										0
									};
		DWORD *dwLang;
		char lpLang[9];
		memset(&lpLang, 0, sizeof(lpLang));

		if(VerQueryValue((LPVOID)lpstrVffInfo,
			TEXT("\\VarFileInfo\\Translation"),
			(LPVOID *)&dwLang,
			dwBytes))
		{
			_snprintf_s(lpLang, _countof(lpLang), "%04x%04x", LOWORD(*dwLang), HIWORD(*dwLang));
		}

		for(unsigned i = 0; predefResStrings[i]; i++)
		{
			char szQueryStr[0x100];
		
			_snprintf_s(szQueryStr, _countof(szQueryStr), _TRUNCATE, "\\StringFileInfo\\%s\\%s", lpLang, predefResStrings[i]);
		
			bRetCode = VerQueryValue((LPVOID)lpstrVffInfo, szQueryStr,(LPVOID *)&lpBuffer,dwBytes);
				
			if(bRetCode)
			{
				if(strcmp(predefResStrings[i], "FileDescription") == 0)
					_snprintf_s(filedescription, _countof(filedescription), _TRUNCATE, "%s", lpBuffer);
				if(strcmp(predefResStrings[i], "CompanyName") == 0)
					_snprintf_s(companyname, _countof(companyname), _TRUNCATE, "%s", lpBuffer);
				if(strcmp(predefResStrings[i], "ProductName") == 0)
					_snprintf_s(productname, _countof(productname), _TRUNCATE, "%s", lpBuffer);
			}
		}
		GlobalFree(hMem);
	} // end of if GetFileVersionInfoSize

	delete[] dwBytes;

	if(using_database)
	{
		
		WfpSQLBindParameter(SQL_VARCHAR,10,(void *)filedescription);
		WfpSQLBindParameter(SQL_VARCHAR,11,(void *)fileversion);
		WfpSQLBindParameter(SQL_VARCHAR,12,(void *)companyname);
		WfpSQLBindParameter(SQL_VARCHAR,13,(void *)productname);
		WfpSQLBindParameter(SQL_VARCHAR,14,(void *)productversion);
		WfpSQLBindParameter(SQL_VARCHAR,15,(void *)szHash); // column size 40
	}

	if(options.scan_type == SCAN_PROCESSES)
	{
		if(pid != 0)
		{
			if(options.optionbindings)
				ProcessBindings_get(pid);
		}
	}

	if(using_database)
	{
		retcode = SQLExecute(hstmt);
		if((retcode == SQL_ERROR) || (retcode == SQL_SUCCESS_WITH_INFO))
		{
			i = 1;
			while ((rc2 = SQLGetDiagRec(SQL_HANDLE_STMT, hstmt, i, SqlState, &NativeError,
				Msg, sizeof(Msg), &MsgLen)) != SQL_NO_DATA) {
					tmp.Format("%s %d %s %d ",
						SqlState,NativeError,Msg,MsgLen);
					MessageBox(NULL, tmp, "SQLGetDiagRec Info (SQLExecute)",MB_OK);
				i++;
			}
			return(-1);
		}
	}
	return(1);
}

char *CWfpEngine::HashDigest_get(char *name)
{
	DWORD dwStatus = 0, cbRead = 0, cbHash = HASHLEN;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = 0;
	BYTE rgbFile [BUFFSIZE], rgbHash [HASHLEN];
	CHAR rgbDigits[] = "0123456789abcdef";
	char tmp[HASHLEN];
	memset(tmp, 0, sizeof(tmp));
	memset(hash, 0, sizeof(hash));

	hFile = CreateFile(name,                     // File name
				       GENERIC_READ,             // Access mode
					   FILE_SHARE_READ,          // Share mode
				       NULL,                     // Not inheritable
				       OPEN_EXISTING,            // Create flags
				       FILE_FLAG_SEQUENTIAL_SCAN,// Attributes
				       NULL);                    // Template handle
  
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return("");
  	}
		
	if(!CryptAcquireContext(&hProv,
                            NULL,
                            NULL,
                            PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT))
	{
		ErrorHandler("CryptAcquireContext", GetLastError());
		return("");
  	}
			
	// Create a MD5 hash.
	if(options.optionMD5)
	{
		if(!CryptCreateHash(hProv, CALG_MD5,0 , 0, &hHash))
		{
			ErrorHandler("CryptCreateHash", GetLastError());
			return("");
  		}
	}
	else
	{	
		// Create a SHA-1 hash.
		if(!CryptCreateHash(hProv, CALG_SHA ,0 , 0, &hHash))
		{
			ErrorHandler("CryptCreateHash", GetLastError());
			return("");
  		}
	}

	// Read the file and hash the data.
	while(ReadFile(hFile, rgbFile, BUFFSIZE, &cbRead, NULL))
	{
		if(0 == cbRead)
			break;
	
		if(!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			ErrorHandler("CryptHashData", GetLastError());
			return("");
  		}
	}
	
	// Get the hash.
	cbHash = HASHLEN;
			
	if(!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		ErrorHandler("CryptGetHashParam", GetLastError());
		return("");
  	}

	for(int i = 0;i < (int)cbHash;++i)
	{
		_snprintf_s(tmp, _countof(tmp), _TRUNCATE, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
		strncat_s(hash, _countof(hash), tmp, sizeof(hash));
    }

    // Clean up.
    if(hFile)
        CloseHandle (hFile);

    if(hHash)
    {
        if(!CryptDestroyHash(hHash))
        {
			ErrorHandler("CryptDestroyHash", GetLastError());
			return("");
        }
    }
    if(hProv)
    {
        if(!CryptReleaseContext(hProv, 0))
        {
   			ErrorHandler("CryptReleaseContext", GetLastError());
			return("");
        }
    }	
	return(hash);
}

int CWfpEngine::ProcessBindings_get(DWORD processID)
{
	HANDLE  hProcessSnap;
	DWORD i = 0;
	struct servent *se;
	PMIB_TCPEXTABLE TCPExTable;
	PMIB_UDPEXTABLE UDPExTable;
	DWORD nRetCode = 0;
    char szProcessName[_MAX_PATH];
	UINT nipaddr;
	CString tmp;

	nRetCode = pAllocateAndGetTcpExTableFromStack(&TCPExTable, TRUE, GetProcessHeap(), 2, 2);
	if(nRetCode) 
	{
		ErrorHandler("AllocateAndGetTcpExTableFromStack", nRetCode);
		return (-1);
	}
 
	nRetCode = pAllocateAndGetUdpExTableFromStack(&UDPExTable, TRUE, GetProcessHeap(), 2, 2 );
	if(nRetCode) 
	{
		ErrorHandler("AllocateAndGetUdpExTableFromStack", nRetCode);
		return (-1);
	}
 
	hProcessSnap = pCreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if(hProcessSnap == INVALID_HANDLE_VALUE) 
	{
		ErrorHandler("CreateToolhelp32Snapshot", GetLastError());
		return (-1);
	}

	for(i = 0; i < TCPExTable->dwNumEntries; i++) 
	{
		// Check if processID is bound to TCP port

		if(TCPExTable->table[i].dwProcessId == processID)
		{
			ProcessPidToName(hProcessSnap, TCPExTable->table[i].dwProcessId, szProcessName);
			se = getservbyport(htons((u_short)TCPExTable->table[i].dwLocalPort),"tcp");
			nipaddr = htonl(TCPExTable->table[i].dwLocalAddr);
/*			if(!using_database)
				fprintf(stream,"\"%d.%d.%d.%d:%d/tcp\"",
					(nipaddr >> 24) & 0xFF,
					(nipaddr >> 16) & 0xFF,
					(nipaddr >> 8) & 0xFF,
					(nipaddr) & 0xFF,
					htons((u_short)TCPExTable->table[i].dwLocalPort));
*/
				}
	}

	for(i = 0; i < UDPExTable->dwNumEntries; i++) 
	{
        // Check if processID is bound to UDP port
		if(UDPExTable->table[i].dwProcessId == processID)
		{
			ProcessPidToName(hProcessSnap, UDPExTable->table[i].dwProcessId, szProcessName);
			se = getservbyport(htons((u_short)UDPExTable->table[i].dwLocalPort),"udp");
			nipaddr = htonl(UDPExTable->table[i].dwLocalAddr);
/*			if(!using_database)
				fprintf(stream,"\"%d.%d.%d.%d:%d/udp\"",
					(nipaddr >> 24) & 0xFF,
					(nipaddr >> 16) & 0xFF,
					(nipaddr >> 8) & 0xFF,
					(nipaddr) & 0xFF,
					htons((u_short)UDPExTable->table[i].dwLocalPort));
*/
			}	
	}
	return (0);
}

PCHAR CWfpEngine::ProcessPidToName(HANDLE hProcessSnap, DWORD ProcessId, PCHAR ProcessName)
{
	PROCESSENTRY32 processEntry;

	memset(ProcessName,0,_MAX_PATH);
	
	if(!pProcess32First(hProcessSnap, &processEntry))
		return ProcessName;
 
	do
	{
		if(processEntry.th32ProcessID == ProcessId) 
		{
			_snprintf_s(ProcessName, _MAX_PATH, _TRUNCATE, "%s", processEntry.szExeFile );
			return ProcessName;
		}
	}while(pProcess32Next(hProcessSnap, &processEntry));

 return ProcessName;

}

int CWfpEngine::ProcessNameAndID_get(DWORD processID)
{
	HANDLE hFile = 0;
	char ProcessName[_MAX_PATH] = "unknown";
	char FullPath[_MAX_PATH];
	TCHAR szApp[MAX_PATH];
    LPTSTR pszPath;
	int iActualItem = 0;
	WIN32_FIND_DATA findData;
	HANDLE fileHandle;
	CString tmp;
    
	// Get a handle to the process.
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_READ,
                                   FALSE, processID);
    // Get the process name.
    if(hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if(EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
		{
			if((GetModuleBaseName(hProcess, hMod, ProcessName, sizeof(ProcessName))) != 0)
			{
				// Attempt to get the full path of the process
				if((GetModuleFileNameEx(hProcess, hMod, FullPath, sizeof(FullPath))) != 0)
				{
					// Test if FullPath can be opened.
					if((hFile = CreateFile(FullPath, // File name
						GENERIC_READ,                // Access mode
						FILE_SHARE_READ,             // Share mode
						NULL,                        // Not inheritable
						OPEN_EXISTING,               // Create flags
						FILE_FLAG_SEQUENTIAL_SCAN,   // Attributes
						NULL)) == INVALID_HANDLE_VALUE)
					{
						// Could not open FullPath, SearchPath ProcessName
						if(SearchPath(NULL, ProcessName, NULL, _MAX_PATH, szApp, &pszPath))
						{
							// Found complete path (szApp)
							if((fileHandle = FindFirstFile(szApp, &findData)) != INVALID_HANDLE_VALUE)
							{
								Win32FindData_get(&findData, "", processID);
								FindClose(fileHandle);
 							}
						}
					}
					else
					{
						CloseHandle(hFile); // File opened successfully, close it.
						if((fileHandle = FindFirstFile(FullPath, &findData)) != INVALID_HANDLE_VALUE)
						{
							Win32FindData_get(&findData, "", processID);
							FindClose(fileHandle);
 						}
					}
				}
				
				
			} // GetModuleBaseName
		} // EnumProcessModules()
	} // if(hProcess)

    CloseHandle(hProcess);
	return(1);
}

int CWfpEngine::ProcessModules_get(DWORD processID)
{
	HMODULE hMods[1024];
	MODULEINFO ModInfo;
    HANDLE hProcess;
    DWORD cbNeeded = 0;
    unsigned int j = 0;
	DWORD dwVerHnd = 0;
	WIN32_FIND_DATA findData;
	HANDLE fileHandle;

    // Get a list of all the modules in this process.

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                    PROCESS_VM_READ,
                                    FALSE, processID );

    if(EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for(j = 0; j < (cbNeeded / sizeof(HMODULE)); j++)
        {
            char szModName[MAX_PATH];

            // Get the full path to the module's file.
			if(GetModuleFileNameEx(hProcess, hMods[j], szModName, sizeof(szModName)))
            {
				if((fileHandle = FindFirstFile(szModName, &findData)) != INVALID_HANDLE_VALUE)
				{
					Win32FindData_get(&findData, "", 0);
					FindClose(fileHandle);
				}
				
				// FIXME This code is not hooked up to Database or interface.
				if(GetModuleInformation(hProcess, hMods[j], &ModInfo, sizeof(ModInfo))) 	                                 if((fileHandle = FindFirstFile(szModName, &findData)) != INVALID_HANDLE_VALUE)
                { 
					CString EntryPoint, BaseOfDll, SizeofImage;
					EntryPoint.Format("0x%p", ModInfo.EntryPoint); 	 
					BaseOfDll.Format("0x%p", ModInfo.lpBaseOfDll); 	 
					SizeofImage.Format("%08X", ModInfo.SizeOfImage); 	 
                } 	 
			}
		}
    }
    CloseHandle(hProcess);
	return(1);
}


bool CWfpEngine::ScanProcesses(void)
{
	DWORD lpidProcess[2048], cbNeeded = 0, cProcesses = 0;
	RETCODE retcode;
	hstmt = SQL_NULL_HSTMT;
	using_database = false;
	
	// Initialize Undocumented XP and newer Specific APIs
	options.optionbindings = CheckXP();

	DatabaseConnect();

	if(hdbc != SQL_NULL_HDBC) // We connected
	{
		retcode = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);
		if((retcode != SQL_SUCCESS_WITH_INFO) && (retcode != SQL_SUCCESS))
		{
			ErrorHandler("SQLAllocHandle", retcode);
			return false;
		}
		using_database = true;
	}
	
	// Get the list of process identifiers.
    if(!EnumProcesses(lpidProcess, sizeof(lpidProcess), &cbNeeded))
        return false;

    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.
	//if(pWininterrogateDlg->just_pid)
	//{
	//	ProcessGetNameAndID(pWininterrogateDlg->pid);
	//	ProcessGetModules(pWininterrogateDlg->pid);
	//}
	//else
	//{
		for(DWORD count = 0; count < cProcesses; count++)
		{
			ProcessNameAndID_get(lpidProcess[count]);
			//if(!pWininterrogateDlg->just_ps)
				ProcessModules_get(lpidProcess[count]);
		}
	//}

	if(using_database)
		DatabaseDisconnect();

	return(0);
}

bool CWfpEngine::CheckXP(void)
{

	pAllocateAndGetTcpExTableFromStack =
		(PALLOCATE_AND_GET_TCPEXTABLE_FROM_STACK) 
		GetProcAddress(LoadLibrary("iphlpapi.dll"), 
		"AllocateAndGetTcpExTableFromStack");
	if(!pAllocateAndGetTcpExTableFromStack ) 
		return false;
 
	pAllocateAndGetUdpExTableFromStack =
		(PALLOCATE_AND_GET_UDPEXTABLE_FROM_STACK)
		GetProcAddress(LoadLibrary("iphlpapi.dll"), 
		"AllocateAndGetUdpExTableFromStack");
	if(!pAllocateAndGetUdpExTableFromStack) 
		return false;
 
	pCreateToolhelp32Snapshot =
		(PCREATE_TOOL_HELP32_SNAPSHOT)
		GetProcAddress(GetModuleHandle("kernel32.dll"),
		"CreateToolhelp32Snapshot");
	if(!pCreateToolhelp32Snapshot) 
		return false;
 
	pProcess32First =
		(PPROCESS32_FIRST)
		GetProcAddress(GetModuleHandle("kernel32.dll"),
		"Process32First");
	if(!pProcess32First) 
		return false;
 
	pProcess32Next =
		(PPROCESS32_NEXT)
		GetProcAddress(GetModuleHandle("kernel32.dll"),
		"Process32Next");
	if(!pProcess32Next)
		return false;
 
	return true;
}

bool CWfpEngine::Registry_get(void)
{
	CString tmp;
	LONG result;
	HKEY hKey, phkResult;
	DWORD lpType = 0;
	TCHAR loutput[1024];
	TCHAR lpName[1024];
	DWORD lpcbName = 1024;
	FILETIME time;
	DWORD index =0;
	DWORD lpcbData = 1024;
	
	// The RegConnectRegistry function establishes a connection to a predefined
	// registry handle on another computer. 

	if((result = RegConnectRegistry(node.szComputerM,HKEY_LOCAL_MACHINE,&hKey)) == ERROR_SUCCESS)
	{
		if((result = RegOpenKeyEx(hKey,_T("Software\\Microsoft\\Windows NT\\CurrentVersion"),0,KEY_READ,&phkResult)) == ERROR_SUCCESS)
		{
			if((result = RegQueryValueEx(phkResult,_T("CSDVersion"),NULL,&lpType,(unsigned char *)loutput,&lpcbData)) == ERROR_SUCCESS)
			{
				tmp.Format(_T("%s"),loutput);
				PatchLevel.Add(tmp);
			}
			RegCloseKey(phkResult);
		}
		else
		{
			//if(pWfpDlg->opt_showerror)
			//{
				LPVOID lpMsgBuf;
				FormatMessage( 
					FORMAT_MESSAGE_ALLOCATE_BUFFER | 
					FORMAT_MESSAGE_FROM_SYSTEM | 
					FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL,
					result,
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
					(LPTSTR) &lpMsgBuf,0,NULL);
				tmp.Format(_T("RegOpenKeyEx Error %d: Retrieving Service Pack: %s"),result,lpMsgBuf);
				Errors.Add(tmp);
				LocalFree(lpMsgBuf);
			//}
		}
					
		if((result = RegOpenKeyEx(hKey,_T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix"),0,KEY_READ,&phkResult)) == ERROR_SUCCESS)
		{
			index = 0;
			lpcbName = sizeof(lpName);
			result = RegEnumKeyEx(phkResult, // handle to key to enumerate
				index,			// index of subkey to enumerate
				lpName,			// address of buffer for subkey name
				&lpcbName,		// address for size of subkey buffer
				NULL,			// reserved
				NULL,			// address of buffer for class string
				NULL,			// address for size of class buffer
				&time);
			
			for(index = 0; result != ERROR_NO_MORE_ITEMS; index++)
			{
				lpcbName = sizeof(lpName);
				result = RegEnumKeyEx(phkResult,          // handle to key to enumerate
					index,		// index of subkey to enumerate
					lpName,		// address of buffer for subkey name
					&lpcbName,  // address for size of subkey buffer
					NULL,       // reserved
					NULL,       // address of buffer for class string
					NULL,       // address for size of class buffer
					&time);

				if(result == ERROR_NO_MORE_ITEMS)
				{
					RegCloseKey(phkResult); // Done enumerating phkResult	
					break;
				}
				else
				{
					HKEY hkey_q;
					DWORD lpcbData=8192;
				
					result = RegOpenKeyEx(phkResult,lpName,0,KEY_READ,&hkey_q);
					if((result = RegQueryValueEx(hkey_q,TEXT("Comments"),NULL,&lpType,(unsigned char *)loutput,&lpcbData)) == ERROR_SUCCESS)
					{
						tmp.Format(_T("%s http://support.microsoft.com/kb/%s %s"),lpName, lpName+2, loutput);
						PatchLevel.Add(tmp);
					}
					RegCloseKey(hkey_q);	
				}
			} // end of for loop
			RegCloseKey(hKey);	
		}
		else
		{
			//if(pWfpDlg->opt_showerror)
			//{
				LPVOID lpMsgBuf;
				FormatMessage( 
					FORMAT_MESSAGE_ALLOCATE_BUFFER | 
					FORMAT_MESSAGE_FROM_SYSTEM | 
					FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL,
					result,
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
					(LPTSTR) &lpMsgBuf,0,NULL);
				tmp.Format(_T("%s Error enumerating Hot Fixes\n"),lpMsgBuf);
				Errors.Add(tmp);
				LocalFree(lpMsgBuf);
			//}
			RegCloseKey(hKey);	// Successfully connected with RegConnectRegistry, but some other failure.
		}
	}
	else
	{
//		if(pWfpDlg->opt_showerror)
//		{
			LPVOID lpMsgBuf;
			FormatMessage( 
				FORMAT_MESSAGE_ALLOCATE_BUFFER | 
				FORMAT_MESSAGE_FROM_SYSTEM | 
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				result, 
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
				(LPTSTR) &lpMsgBuf,0,NULL);
			tmp.Format(_T("RegConnectRegistry Error %d: %s\n"),result,lpMsgBuf);
			Errors.Add(tmp);
			LocalFree(lpMsgBuf);
//		}
		return false;
	}
	return true;
}

void CWfpEngine::StartThread()
{
	//CWinThread *pThreads = NULL;
	//pThreads = AfxBeginThread(ThreadFunc, this);
	switch(options.scan_type) {
		case SCAN_LIST:
		ScanList(List, false, false);
		break;
		case SCAN_RANGE:
		ScanRange(StartIPAddress, EndIPAddress, false, false);
		break;	
		case SCAN_NEIGHBORHOOD:
		ScanNeighborhood(StartIPAddress);
		break;
		case SCAN_FILES:
		// reuse StartIPAddress for Directory
		// reuse EndIPAddress for FileMask
		ScanFiles(StartIPAddress, EndIPAddress);
		break;
		case SCAN_PROCESSES: 
		ScanProcesses();
		break;
		case SCAN_HOST:
		default:
		ScanHost(StartIPAddress);
		break;	
	}
	
}

UINT CWfpEngine::ThreadFunc(LPVOID pParam)
{
	CWfpEngine *self = (CWfpEngine *)pParam;
	
	switch(self->options.scan_type) {
		case SCAN_LIST:
		self->ScanList(self->List, false, false);
		break;
		case SCAN_RANGE:
		self->ScanRange(self->StartIPAddress, self->EndIPAddress, false, false);
		break;	
		case SCAN_NEIGHBORHOOD:
		self->ScanNeighborhood(self->StartIPAddress);
		break;
		case SCAN_FILES:
		// reuse StartIPAddress for Directory
		// reuse EndIPAddress for FileMask
		self->ScanFiles(self->StartIPAddress, self->EndIPAddress);
		break;
		case SCAN_PROCESSES: 
		self->ScanProcesses();
		break;
		case SCAN_HOST:
		default:
		self->ScanHost(self->StartIPAddress);
		break;	
	}
	return(1);
}