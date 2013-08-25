#include "StdAfx.h"
#include ".\wfpnet.h"

CWfpNET::CWfpNET(void)
{
}

CWfpNET::~CWfpNET(void)
{
}

bool CWfpNET::Groups_get(void) {
	if(!NET_Machines_Users_Groups(ENUM_GROUPS))
		return false;
	else
		return true;
}

bool CWfpNET::OperatingSystem_get(void)
{
	LPSERVER_INFO_101 pBuf	= NULL;
	LPWKSTA_INFO_102 pwBuf  = NULL;
	NET_API_STATUS nStatus  = NULL;
	unsigned long res = 0;
	CString tmp;
	
	// The NetServerGetInfo function retrieves current configuration information
	// for the specified server.
	// No special group membership is required for level 100 or level 101 calls.

	if((nStatus  = NetServerGetInfo(node.szComputerW, 101,(LPBYTE *)&pBuf)) == NERR_Success)   
	{
		tmp.Format(_T("Operating System: %d.%d"), pBuf->sv101_version_major, pBuf->sv101_version_minor);
		OperatingSystem.Add(tmp);
		
		if(pBuf->sv101_type & SV_TYPE_SQLSERVER)
		{
			OperatingSystem.Add(_T("Role: SQL Server"));
			SQLPassword_test();
//			UDP_Sockets(node,1434,1434,2); // sqlping
		}
		
		if(pBuf->sv101_type & SV_TYPE_DOMAIN_CTRL)
			OperatingSystem.Add(_T("Role: Primary Domain Controller"));

		if(pBuf->sv101_type & SV_TYPE_DOMAIN_BAKCTRL)
			OperatingSystem.Add(_T("Role: Backup Domain Controller"));

		if(pBuf->sv101_type & SV_TYPE_SERVER_NT)
			OperatingSystem.Add(_T("Role: NT Member Server"));
			
		if(pBuf->sv101_type & SV_TYPE_NT)
			OperatingSystem.Add(_T("Role: NT Workstation"));

		if(pBuf->sv101_type & SV_TYPE_WORKSTATION)
			OperatingSystem.Add(_T("Role: LAN Manager Workstation"));

		if(pBuf->sv101_type & SV_TYPE_SERVER)
			OperatingSystem.Add(_T("Role: LAN Manager Server"));

		if(pBuf->sv101_type & SV_TYPE_TIME_SOURCE)
			OperatingSystem.Add(_T("Role: Time Source"));

		if(pBuf->sv101_type & SV_TYPE_AFP)
			OperatingSystem.Add(_T("Role: Apple File Protocol Server"));

		if(pBuf->sv101_type & SV_TYPE_DOMAIN_MEMBER)
			OperatingSystem.Add(_T("Role: LAN Manager 2.x domain member"));
	
		if(pBuf->sv101_type & SV_TYPE_LOCAL_LIST_ONLY)
			OperatingSystem.Add(_T("Role: Servers maintained by the browser"));
	
		if(pBuf->sv101_type & SV_TYPE_PRINTQ_SERVER)
			OperatingSystem.Add(_T("Role: Server sharing print queue"));
	
		if(pBuf->sv101_type & SV_TYPE_DIALIN_SERVER)
			OperatingSystem.Add(_T("Role: Dial-in Server"));
			
		if(pBuf->sv101_type & SV_TYPE_XENIX_SERVER)
			OperatingSystem.Add(_T("Role: Xenix"));
			
		if(pBuf->sv101_type & SV_TYPE_POTENTIAL_BROWSER)
			OperatingSystem.Add(_T("Role: Potential Browser"));
			
		if(pBuf->sv101_type & SV_TYPE_MASTER_BROWSER)
			OperatingSystem.Add(_T("Role: Master Browser"));
			
		if(pBuf->sv101_type & SV_TYPE_BACKUP_BROWSER)
			OperatingSystem.Add(_T("Role: Backup Browser"));

		if(pBuf->sv101_type & SV_TYPE_DOMAIN_MASTER)
			OperatingSystem.Add(_T("Role: Domain Master Browser"));

#if _WIN32_WINNT > 0x0500
		if(pBuf->sv101_type & SV_TYPE_TERMINALSERVER)
			OperatingSystem.Add(_T("Role: Terminal Server"));
#endif

		if(pBuf->sv101_type & SV_TYPE_CLUSTER_NT)
			OperatingSystem.Add(_T("Role: Cluster"));

		if(pBuf->sv101_type &  SV_TYPE_NOVELL)
			OperatingSystem.Add(_T("Role: Novell Netware Server"));
			
		if(pBuf->sv101_type &  SV_TYPE_WINDOWS )
			OperatingSystem.Add(_T("Role: Windows 9x or Me Workstation"));
			
		if(pBuf->sv101_type & SV_TYPE_WFW )
			OperatingSystem.Add(_T("Role: Windows for Workgroups Workstation"));
		
		if(pBuf->sv101_comment != NULL) {
			tmp.Format(_T("Comment: %S"),pBuf->sv101_comment);
			OperatingSystem.Add(tmp);
		}
		
		if(pBuf != NULL)
			NetApiBufferFree(pBuf);
	}
	else 
	{
		if(pBuf != NULL)
			NetApiBufferFree(pBuf);
		
		ErrorHandler("NetServerGetInfo", nStatus);
	}
	return true; 
}

bool CWfpNET::NetBIOSShares_get(void)
{
	DWORD i = 0, entriesread = 0, resume_handle = 0, totalentries = 0;
	PSHARE_INFO_1 pBuf = NULL, pTmpBuf = NULL;
	NET_API_STATUS nStatus  = NULL;
	NETRESOURCE nr;
	CString tmp, tmp2;
	bool accessible = false;
	
	// The NetShareEnum function retrieves information about each shared
	// resource on a server.
	// No special group membership is required for level 0 or level 1 calls.

	do{
		nStatus = NetShareEnum(node.szComputerW, 1, (LPBYTE *) &pBuf,
			0xFFFFFFFF, &entriesread, &totalentries, &resume_handle);

		if(nStatus == ERROR_SUCCESS || nStatus == ERROR_MORE_DATA)
		{
			if((pTmpBuf = pBuf) != NULL)
			{
				for(i = 0; i < entriesread; i++)
				{
					if(node.NetBIOS.IsEmpty()) {
						tmp.Format(_T("\\\\%s\\%S"),
							node.ipaddress, pTmpBuf->shi1_netname);
					}
					else {
						tmp.Format(_T("\\\\%s\\%S"),
							node.NetBIOS, pTmpBuf->shi1_netname);
					}

					if((pTmpBuf->shi1_type == STYPE_DISKTREE) && 
						(options.optionopensharetest))
					{
						accessible = false;
						//WNetCancelConnection2(_T("X:") ,CONNECT_UPDATE_PROFILE, TRUE);
						nr.dwType = RESOURCETYPE_ANY;
						//nr.lpLocalName = _T("X:");
						nr.lpLocalName = NULL;
						nr.lpRemoteName = tmp.GetBuffer();
						nr.lpProvider = NULL;
						if(WNetAddConnection2(&nr, NULL, NULL, FALSE) == NO_ERROR)
						{
							accessible = true;
							//WNetCancelConnection2(_T("X:") ,CONNECT_UPDATE_PROFILE, TRUE);
							WNetCancelConnection2(tmp.GetBuffer() ,CONNECT_UPDATE_PROFILE, TRUE);
						}
					}
					tmp2.Format("%s %S %s", tmp, pTmpBuf->shi1_remark,
						(accessible) ? "accessible with current credentials" : "");
					NetBIOSShares.Add(tmp2);
					pTmpBuf++;
				}
			}
			if(pBuf != NULL)
			{
				NetApiBufferFree(pBuf);
				pBuf = NULL;
			}
		}
		else
		{
			// Silence Errors
			// NetErrorHandler("NetShareEnum", nStatus);
			return false;
		}
	}while (nStatus==ERROR_MORE_DATA);
	return true;
}

bool CWfpNET::PasswordPolicy_get(void)
{
	USER_MODALS_INFO_0 *pBuf0 = NULL;
	USER_MODALS_INFO_3 *pBuf3 = NULL;
	NET_API_STATUS nStatus = NULL;
	CString tmp;

	if((nStatus = NetUserModalsGet(node.szComputerW, 0,(LPBYTE *)&pBuf0)) != NERR_Success)
		ErrorHandler("NetUserModalsGet", nStatus);
	else
	{
		//m_output.operator +=(_T("Password Policy:\n"));
		if (pBuf0 != NULL)
		{
			tmp.Format("\tMinimum password length:  %d\n", pBuf0->usrmod0_min_passwd_len);
			Users.Add(tmp);
			if(pBuf0->usrmod0_max_passwd_age == TIMEQ_FOREVER)
				tmp.Format("\tMaximum password age: Forever\n");
			else
				tmp.Format("\tMaximum password age : %d days\n", pBuf0->usrmod0_max_passwd_age/86400);
			Users.Add(tmp);
			tmp.Format("\tMinimum password age : %d days\n", pBuf0->usrmod0_min_passwd_age/86400);
			Users.Add(tmp);
			if(pBuf0->usrmod0_force_logoff == TIMEQ_FOREVER)
				tmp.Format("\tForced log off time : Never\n");
			else
				tmp.Format("\tForced log off time :  %d seconds\n", pBuf0->usrmod0_force_logoff);
			Users.Add(tmp);
			tmp.Format("\tPassword history length:  %d\n", pBuf0->usrmod0_password_hist_len);
			Users.Add(tmp);
      }
	}
 
	if (pBuf0 != NULL)
		NetApiBufferFree(pBuf0);
	if((nStatus = NetUserModalsGet(node.szComputerW, 3,(LPBYTE *)&pBuf3)) != NERR_Success)
		ErrorHandler("NetUserModalsGet", nStatus);
	else
	{
		if(pBuf3 != NULL)
		{
			tmp.Format("\tAttempts before Lockout: %d\n",pBuf3->usrmod3_lockout_threshold);
			Users.Add(tmp);
			tmp.Format("\tTime between two failed login attempts: %d seconds\n",pBuf3->usrmod3_lockout_duration);
			Users.Add(tmp);
			tmp.Format("\tLockout Duration: %d minutes\n",pBuf3->usrmod3_lockout_duration/60);
			Users.Add(tmp);
		}
	}

	if (pBuf3 != NULL)
		NetApiBufferFree(pBuf3);

	return true;
}

bool CWfpNET::Services_get(void)
{
	SC_HANDLE scm;
	LPENUM_SERVICE_STATUS service_status	= NULL;
	DWORD numServices						= 0,
		sizeNeeded							= 0,
		resume								= 0;
	DWORD i									= 0;
	CString tmp;
	// Open a connection to the SCM
	scm = OpenSCManager(node.szComputerM, 0, SC_MANAGER_ALL_ACCESS);
	if(scm)
	{
		EnumServicesStatus(scm,	SERVICE_WIN32, SERVICE_STATE_ALL, // use SERVICE_STATE_ALL to see both
		0, 0, &sizeNeeded, &numServices, &resume);
		if(GetLastError() != ERROR_MORE_DATA)
			return false;

		if((service_status = (LPENUM_SERVICE_STATUS) HeapAlloc(GetProcessHeap(), 0, sizeNeeded)) == NULL)
			return false;
			
		// Get the status records. Making an assumption
		// here that no new services get added during
		// the allocation (could lock the database to
		// guarantee that...)
		resume = 0;
		// EnumServicesStatusEx supersedes EnumServicesStatus and also returns PID
		// but is for Win2k or XP only
		if(!EnumServicesStatus(scm, SERVICE_WIN32, SERVICE_STATE_ALL,
			service_status, sizeNeeded, &sizeNeeded, &numServices, &resume))
		{
			CloseServiceHandle(scm);
			if(service_status != NULL)
				HeapFree(GetProcessHeap(), 0, service_status);
			return false;
		}
			
		for(i=0; i < numServices; i++)
		{
			if(((_tcscmp(service_status[i].lpServiceName,_T("WARSVR"))==0) || \
				(_tcscmp(service_status[i].lpServiceName,_T("MSFTPSVC"))==0)) && \
				(service_status[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING))
				tmp.Format(_T("%s Browse: ftp://%s"), service_status[i].lpDisplayName,node.szComputerM+2);
			else if(((_tcscmp(service_status[i].lpServiceName,_T("W3SVC"))==0) || \
				(_tcscmp(service_status[i].lpServiceName,_T("Apache"))==0) || \
				(_tcscmp(service_status[i].lpServiceName,_T("Apache2"))==0)) && \
				(service_status[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING))
				tmp.Format(_T("%s Browse: http://%s"), service_status[i].lpDisplayName,node.szComputerM+2);
			else if(((strncmp(service_status[i].lpServiceName,"TlntSvr",7)) == 0) && \
				(service_status[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING))
				tmp.Format(_T("%s Connect: telnet://%s"), service_status[i].lpDisplayName, node.szComputerM+2);
			else {
				tmp.Format(_T("%s "),service_status[i].lpDisplayName);
				switch(service_status[i].ServiceStatus.dwCurrentState)
				{
				case SERVICE_CONTINUE_PENDING:
					tmp.operator +=("continue pending.");
					break;
				case SERVICE_PAUSE_PENDING:
					tmp.operator +=("pause pending.");
					break;
				case SERVICE_PAUSED:
					tmp.operator +=("paused.");
					break;
				case SERVICE_RUNNING:
					tmp.operator +=("running.");
					break;
				case SERVICE_START_PENDING:
					tmp.operator +=("start pending.");
					break;
				case SERVICE_STOP_PENDING:
					tmp.operator +=("stop pending.");
					break;
				case SERVICE_STOPPED:
					tmp.operator +=("stopped.");
					break;
				}
			}
			Services.Add(tmp);
		}
			
		if(service_status != NULL)
			HeapFree(GetProcessHeap(), 0, service_status);
		CloseServiceHandle(scm);
		return true;
	}
	return false;
}


bool CWfpNET::Sessions_get(void)  {
		LPSESSION_INFO_10 pBuf = NULL, pTmpBuf = NULL;
	DWORD dwLevel = 10,	dwPrefMaxLen = MAX_PREFERRED_LENGTH,
		dwEntriesRead = 0, dwTotalEntries = 0, dwResumeHandle = 0,
		i = 0;
	LPWSTR pszClientName = NULL, pszUserName = NULL;
	NET_API_STATUS nStatus = NULL;
	CString tmp, session;

	// The NetSessionEnum function provides information about sessions
	// established on a server.
	// No special group membership is required for level 0 or level 10 calls.

	do // begin do
	{
		nStatus = NetSessionEnum(node.szComputerW, pszClientName, pszUserName,
			dwLevel, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries,
			&dwResumeHandle);
		if((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{		  
			if((pTmpBuf = pBuf) != NULL)
			{
				for(i = 0; i < dwEntriesRead; i++)
				{
					assert(pTmpBuf != NULL);

					if(pTmpBuf == NULL)
						break;
					    
					tmp.Format(_T("Client: %S "),pTmpBuf->sesi10_cname);
					session.operator +=(tmp);
					   
					tmp.Format(_T("User: %S "),pTmpBuf->sesi10_username);
					session.operator +=(tmp);

					tmp.Format(_T("Seconds Connected: %d "),pTmpBuf->sesi10_time);
					session.operator +=(tmp);
				
					tmp.Format(_T("Seconds Idle: %d"),pTmpBuf->sesi10_idle_time);
					session.operator +=(tmp);
					Sessions.Add(session);
					pTmpBuf++;
				}
			}
			
			if(pBuf != NULL)
			{
				NetApiBufferFree(pBuf);
				pBuf = NULL;
			}
		}
		else
		{
			ErrorHandler("NetSessionEnum", nStatus);
			return false;
		}
	    
		if(pBuf != NULL)
		{
			NetApiBufferFree(pBuf);
				pBuf = NULL;
		}
	}while (nStatus == ERROR_MORE_DATA); // end do

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
	  
	return true;
}

bool CWfpNET::Users_get(void) {
	if(!NET_Machines_Users_Groups(ENUM_USERS))
		return false;
	else
		return true;
}

bool CWfpNET::NET_Machines_Users_Groups(DWORD level)
{
	NET_DISPLAY_USER *ndu		= NULL;
	NET_DISPLAY_MACHINE *ndm	= NULL;
	NET_DISPLAY_GROUP *ndg		= NULL;
	NET_API_STATUS nStatus		= NULL;
	DWORD read = 0, Index = 0, i = 0;
	void *pBuf;
	CString tmp;

	do
	{
		pBuf = NULL;
		nStatus = NetQueryDisplayInformation(node.szComputerW, level, Index, 100,
			MAX_PREFERRED_LENGTH, &read, &pBuf);
		if (nStatus != ERROR_MORE_DATA && nStatus != ERROR_SUCCESS)
		{
			ErrorHandler("NetQueryDisplayInformation", nStatus);				
			return false;
		}

		switch (level)
		{
			case ENUM_USERS: // users
			{
				for(i = 0, ndu = (NET_DISPLAY_USER *)pBuf; i < read; ++ i, ++ ndu )
				{
					tmp.Format(_T("%S [%u] \"%S\" - %S"), ndu->usri1_name,
						ndu->usri1_user_id ,ndu->usri1_full_name,
						ndu->usri1_comment);
					Users.Add(tmp);
					
					if(options.optionsid)
						Users.Add(SID_get(ndu->usri1_name));

					if(ndu->usri1_flags & UF_SCRIPT)
						Users.Add("- The logon script executed. This value must be set for LAN Manager 2.0 or Windows NT.");

					if (ndu->usri1_flags & UF_ACCOUNTDISABLE)
						Users.Add("- The user's account is disabled.");
					
					if (ndu->usri1_flags & UF_HOMEDIR_REQUIRED)
						Users.Add("- The home directory is required. Windows NT/2000 ignores this value.");
					
					if (ndu->usri1_flags & UF_PASSWD_NOTREQD)
						Users.Add("- No password is required.");
					
					if (ndu->usri1_flags & UF_PASSWD_CANT_CHANGE )
						Users.Add("- The user cannot change the password.");
					
					if (ndu->usri1_flags & UF_LOCKOUT)
						Users.Add("- The Account is currently locked out.");
					
					if (ndu->usri1_flags & UF_DONT_EXPIRE_PASSWD)
						Users.Add("\t- Password does not expire.");
						
					#if _WIN32_WINNT > 0x0500
					if (ndu->usri1_flags & UF_TRUSTED_FOR_DELEGATION)
						Users.Add("- The account is enabled for delegation.");
					
					if (ndu->usri1_flags & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)
						Users.Add("- The user's password is stored under reversible encryption in the Active Directory.");
					
					if (ndu->usri1_flags & UF_NOT_DELEGATED)
						Users.Add("- Marks the account as \"sensitive\"; other users cannot act as delegates of this user account.");
						
					if (ndu->usri1_flags & UF_SMARTCARD_REQUIRED)
						Users.Add("- Requires the user to log on to the user account with a smart card.");
						
					if (ndu->usri1_flags & UF_USE_DES_KEY_ONLY)
						Users.Add("- Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.");
						
					if (ndu->usri1_flags & UF_DONT_REQUIRE_PREAUTH)
						Users.Add("- This account does not require Kerberos preauthentication for logon.");
					
					if (ndu->usri1_flags & UF_PASSWORD_EXPIRED)
						Users.Add("- The user's password has expired.");
					#endif
				}
				tmp.Format("%d\n",read);
				// take the last element's next_index
				if (read > 0)
					Index = ((NET_DISPLAY_USER *)pBuf)[read - 1].usri1_next_index;
				break;
			}
			case ENUM_MACHINES: // machines
				for (i = 0, ndm = (NET_DISPLAY_MACHINE *) pBuf; i < read; ++ i, ++ ndm )
				{
//					m_output.Format(_T("\t%S %S\n"),ndm->usri2_name, ndm->usri2_flags );
				}
				// take the last element's next_index
				if (read > 0)
					Index = ((NET_DISPLAY_MACHINE *)pBuf)[read - 1].usri2_next_index;
				break;
			case ENUM_GROUPS: // groups
			{
				//m_output.operator +=(_T("Global Groups:\n"));
				for (i = 0, ndg = (NET_DISPLAY_GROUP *) pBuf; i < read; ++ i, ++ ndg )
				{
					tmp.Format(_T("\t%S \"%S\" [%u]\n"),ndg->grpi3_name,ndg->grpi3_comment,ndg->grpi3_group_id);
					Groups.Add(tmp);
					if(options.optionsid)
						Groups.Add(SID_get(ndg->grpi3_name));
					GroupMembers_get(ndg->grpi3_name);
				}
				// take the last element's next_index
				if (read > 0)
					Index = ((NET_DISPLAY_GROUP *)pBuf)[read - 1].grpi3_next_index;
				break;
			}
		}
		if (pBuf != NULL)
			NetApiBufferFree(pBuf);

	} while (nStatus == ERROR_MORE_DATA);
	return true;
}

bool CWfpNET::Disks_get(void) //Enumerate Disks
{
	const int ENTRY_SIZE   = 3; // Drive letter, colon, NULL
	LPWSTR pBuf            = NULL;
	DWORD dwLevel          = 0; // level must be zero
	DWORD dwPrefMaxLen     = (DWORD)-1;
	DWORD dwEntriesRead    = 0;
	DWORD dwTotalEntries   = 0;
	NET_API_STATUS nStatus = NULL;
	CString tmp;

	// The NetServerDiskEnum function retrieves a list of disk drives on a server.
	// Only members of the Administrators or Account Operators local group can
	// successfully execute the NetServerDiskEnum function on a remote computer.
	nStatus = NetServerDiskEnum(node.szComputerW, dwLevel, (LPBYTE *) &pBuf,
        dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, NULL);
   
	if(nStatus == NERR_Success)
	{
		LPWSTR pTmpBuf;

		if((pTmpBuf = pBuf) != NULL)
		{
			DWORD i;
			DWORD dwTotalCount = 0;
        
			// Loop through the entries.
        
			for(i = 0; i < dwEntriesRead; i++)
			{
				assert(pTmpBuf != NULL);

				if(pTmpBuf == NULL)
				break;
            
				// Print drive letter, colon, NULL for each drive;
				// the number of entries actually enumerated; and
				// the total number of entries available.
            
				tmp.Format(_T("\tDisk: %S\n"), pTmpBuf);
				Disks.Add(tmp);

				pTmpBuf += ENTRY_SIZE;
				dwTotalCount++;
			}
			//tmp.Format(_T("\tEntries enumerated: %d\n"), dwTotalCount);
			//m_output.operator +=(tmp);
			NetApiBufferFree(pBuf);
		}
	}
	else
	{
		ErrorHandler("NetServerDiskEnum", nStatus);
		return false;
	}
	return true;
}

bool CWfpNET::EventLog_get(void)
{
	HANDLE h;
    EVENTLOGRECORD *pevlr; 
    BYTE bBuffer[8192]; 
    DWORD dwRead, dwNeeded, dwThisRecord = 0;
	CString tmp, event;
	char *cp;
	char *pSourceName;
	char *pComputerName;

    if((h = OpenEventLog(node.szComputerM, _T("Security"))) == NULL)
	{
		ErrorHandler("OpenEventLog", GetLastError());
		return false;
	}
    
    pevlr = (EVENTLOGRECORD *)&bBuffer; 
 
    // Opening the event log positions the file pointer for this 
    // handle at the beginning of the log. Read the records 
    // sequentially until there are no more. 
 
    while(ReadEventLog(h,                // event log handle 
		EVENTLOG_FORWARDS_READ |  // reads forward 
        EVENTLOG_SEQUENTIAL_READ, // sequential read 
        0,			  // ignored for sequential reads 
        pevlr,        // pointer to buffer 
        8192,		  // size of buffer 
        &dwRead,      // number of bytes read 
        &dwNeeded))   // bytes in next record 
    {
        while(dwRead > 0) 
        { 
            // Print the event identifier, type, and source name. 
            // The source name is just past the end of the 
            // formal structure. 
 
            tmp.Format(_T("\t%02d  Event ID: 0x%08X "), 
                dwThisRecord++, pevlr->EventID);
			event.operator +=(tmp);
			char buf[26];
			ctime_s(buf, 26, (const time_t *)&pevlr->TimeGenerated);
			tmp.Format("Time Generated: %s", buf);
			event.operator +=(tmp);
			ctime_s(buf, 26, (const time_t *)&pevlr->TimeWritten);
			tmp.Format("Time Written: %s", buf);
			event.operator +=(tmp);
			switch(pevlr->EventType)
			{
				case EVENTLOG_ERROR_TYPE: event.operator +=("Error Event\n"); break;
				case EVENTLOG_WARNING_TYPE: event.operator +=("Warning Event\n"); break;
				case EVENTLOG_INFORMATION_TYPE: event.operator +=("Information Event\n"); break;
				case EVENTLOG_AUDIT_SUCCESS: event.operator +=("Success Audit Event\n"); break;
				case EVENTLOG_AUDIT_FAILURE: event.operator +=("Failure Audit Event\n"); break;
				default: event.operator +=("Unknown\n"); break;
			}

			cp = (char *)pevlr;
			cp += sizeof(EVENTLOGRECORD);

			pSourceName = cp;
			cp += strlen(cp)+1;

			pComputerName = cp;
			cp += strlen(cp)+1;

			tmp.Format("SourceName: %s\n", pSourceName);
			event.operator +=(tmp);
			tmp.Format("ComputerName: %s\n", pComputerName);
			event.operator +=(tmp);
			EventLog.Add(event);
            dwRead -= pevlr->Length; 
            pevlr = (EVENTLOGRECORD *)((LPBYTE) pevlr + pevlr->Length); 
        } 
        pevlr = (EVENTLOGRECORD *) &bBuffer; 
	}
	return(1);
}

bool CWfpNET::GroupMembers_get(LPWSTR Group) // Enumerate Group Memberships
{
	NET_API_STATUS nStatus       = NULL;
	LPGROUP_USERS_INFO_0 pBuf    = NULL,
		pTmpBuf                  = NULL;
	DWORD i                      = 0,
		entriesread              = 0,
		totalentries			 = 0;
	CString tmp;
	
	do
	{
		nStatus = NetGroupGetUsers(node.szComputerW,Group,0,(LPBYTE *) &pBuf,
			MAX_PREFERRED_LENGTH, &entriesread, &totalentries, NULL);
	
		if(nStatus == NERR_Success || nStatus == ERROR_MORE_DATA)
		{
			if((pTmpBuf = pBuf) != NULL)
			{
				for(i = 0; i < entriesread; i++)
				{
					assert(pTmpBuf != NULL);

					if (pTmpBuf == NULL)
						break;

					tmp.Format(_T("Member: %S"),pTmpBuf->grui0_name);
					Groups.Add(tmp);
					pTmpBuf++;
				}
			}
			if(pBuf != NULL)
			{
				NetApiBufferFree(pBuf);
				pBuf = NULL;
			}
		}
		else
		{
			// Disable for now
			// NetErrorHandler("NetGroupGetUsers", nStatus);
			return false;
		}
	} while (nStatus==ERROR_MORE_DATA);
	
	return true;
}

bool CWfpNET::IPC_Session_Connect(void) // Establish NULL IPC$ Sessions
{
	NETRESOURCE nr;
	DWORD nStatus = 0;
	TCHAR RemoteResource[23]; // UNC Name length (17) + \\IPC$\0 (6) = 23 
	
	_snprintf_s(RemoteResource, _countof(RemoteResource), _TRUNCATE, _T("%s\\IPC$"),node.szComputerM);
	
	nr.dwType				= RESOURCETYPE_ANY;
	nr.lpLocalName			= NULL;
	nr.lpProvider			= NULL;
	nr.lpRemoteName			= RemoteResource;

	// First attempt: Use currently logged in user
	nStatus = WNetAddConnection3(NULL,
			&nr,
			NULL, // password
			NULL, // username
			0);

	if(nStatus == NO_ERROR)
		return(true);
	else
	{
		nStatus = WNetAddConnection3(NULL,
			&nr,
			(LPTSTR) _T(""),
			(LPTSTR) _T(""),
			0);
	
		if(nStatus != NO_ERROR)
		{
			ErrorHandler("WNetAddConnection3",nStatus);
			return (false);
		}
	}
	return (true);
}

bool CWfpNET::IPC_Session_Disconnect(void) // Disconnect NULL IPC$ Sessions
{
	DWORD nStatus = 0;
	nStatus = WNetCancelConnection2(node.szComputerM,0,1);

	if(nStatus == NO_ERROR)
		return true;
	else
		return false;
}

bool CWfpNET::LocalGroups_get(void) // Enumerate Groups
{
	NET_API_STATUS nStatus	    = NULL;
	LPLOCALGROUP_INFO_1 pBuf    = NULL,
		pTmpBuf					= NULL;
	DWORD i						= 0,
		entriesread             = 0,
		totalentries			= 0;
	CString tmp;
	
	// The NetQueryDisplayInformation function returns user account information
	// No special group membership is required to successfully execute the 
	// NetQueryDisplayInformation function.
	// 1 indicates User account information
	do
	{
		nStatus = NetLocalGroupEnum(node.szComputerW,1,(LPBYTE *)&pBuf,MAX_PREFERRED_LENGTH,
			&entriesread, &totalentries, NULL);
	
		if(nStatus == NERR_Success || nStatus == ERROR_MORE_DATA)
		{
			if((pTmpBuf = pBuf) != NULL)
			{
				for(i = 0; i < entriesread; i++)
				{
					assert(pTmpBuf != NULL);

					if (pTmpBuf == NULL)
						break;

					tmp.Format(_T("%S \"%S\""), pTmpBuf->lgrpi1_name, pTmpBuf->lgrpi1_comment);
					Groups.Add(tmp);
					GroupMembers_get(pTmpBuf->lgrpi1_name);
					pTmpBuf++;
				}
			}
			
			if(pBuf != NULL)
			{
				NetApiBufferFree(pBuf);
				pBuf = NULL;
			}
		}
		else
		{
			ErrorHandler("NetLocalGroupEnum",nStatus);
			return false;
		}
	} while(nStatus==ERROR_MORE_DATA);

	return(1);
}

bool CWfpNET::Time_get(void) // Obtain Date and Time
{
	LPTIME_OF_DAY_INFO pTOD = NULL;
	NET_API_STATUS nStatus = NULL;
	DWORD mindiff = 0, hourdiff = 0;
	CString tmp;
	
	// The NetRemoteTOD function returns the time of day information from
	// a specified server.
	// No special group membership is required to successfully execute the
	// NetRemoteTOD function.

	nStatus = NetRemoteTOD(node.szComputerW, (LPBYTE *)&pTOD);
	
	if(nStatus == NERR_Success)
	{
		if(pTOD != NULL)
		{
			tmp.Format(_T("Date and Time:\n\t[%d/%d/%d] "),pTOD->tod_month, pTOD->tod_day, pTOD->tod_year);
			Time.Add(tmp);
			tmp.Format(_T(" -- %02lu:%02lu:%02lu.%02lu\n"), pTOD->tod_hours - (pTOD->tod_timezone / 60), pTOD->tod_mins, pTOD->tod_secs, pTOD->tod_hunds); 
			Time.Add(tmp);		
		}
	}
	else
	{
		ErrorHandler("NetRemoteTOD", nStatus);
	    return false;
	}
	if(pTOD != NULL)
      NetApiBufferFree(pTOD);

	return true;
}

bool CWfpNET::Transports_get(void)
{
	NET_API_STATUS nStatus			  = NULL;
	LPSERVER_TRANSPORT_INFO_1 pBuf	  = NULL,
		pTmpBuf						  = NULL;
	DWORD dwEntriesRead				  = 0;
	DWORD dwTotalEntries			  = 0;
	DWORD dwResumeHandle			  = 0;
	DWORD i	= 0;
	int j = 0;
	CString tmp;	

	// The NetServerTransportEnum function supplies information about
	// transport protocols that are managed by the server.
	// No special group membership is required to successfully execute
	// the NetServerTransportEnum function.
		
	do 
	{
		nStatus = NetServerTransportEnum(node.szComputerW, 1, (LPBYTE *)&pBuf,
			MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
		// If the call succeeds,
		if((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if((pTmpBuf = pBuf) != NULL)
			{
				// Loop through the entries;
				//  process access errors.
	          		
				for(i = 0; i < dwEntriesRead; i++)
				{
					assert(pTmpBuf != NULL);
					if(pTmpBuf == NULL)
						return false;
					
					if(node.NetBIOS.IsEmpty())
						node.NetBIOS.Format("%s", pTmpBuf->svti1_transportaddress);
	
					if(node.Domain.IsEmpty())
						node.Domain.Format("%S", pTmpBuf->svti1_domain);
					
					tmp.Format("%S", pTmpBuf->svti1_networkaddress);
					
					if(options.optionmacaddress)
						if(wcscmp(pTmpBuf->svti1_transportname,L"\\Device\\NetbiosSmb") != 0)  
						{
							tmp.Format("%S", pTmpBuf->svti1_networkaddress);
							if(MACAddress.GetSize() > 0) 
							{
								bool exists = false;
								for(j = 0; j <= MACAddress.GetUpperBound(); j++)
								{	
									if(strcmp(tmp, MACAddress[j]) == 0)
										exists = true;
								}
								if(!exists)
									MACAddress.Add(tmp);
							}	
							else
								MACAddress.Add(tmp);
						}
					pTmpBuf++;
				}
			
				if(pBuf != NULL)
				{
					NetApiBufferFree(pBuf);
					pBuf = NULL;
				}
			}
		}
		else
		{
			ErrorHandler("NetServerTransportEnum", nStatus);
			// If NetServerTransportEnum fails, attempt via UDP
			//UDP_Sockets(node,137,137,1); // nbtstat -a equivalent
			return false;
		}
	}while(nStatus == ERROR_MORE_DATA);
	return true;
}
