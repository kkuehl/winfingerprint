#include "StdAfx.h"
#include ".\wfpwmi.h"

#pragma comment (lib,"wbemuuid") // From WMI SDK

CWfpWMI::CWfpWMI(void)
{
}

CWfpWMI::~CWfpWMI(void)
{
}

bool CWfpWMI::OperatingSystem_get(void)
{
	HRESULT hres				= WBEM_S_NO_ERROR;
	IEnumWbemClassObject *pEnum = NULL;
	IWbemServices *pSvc         = NULL;
	IWbemLocator *pLoc		    = NULL;
	IWbemClassObject *pObj      = NULL;
	ULONG uTotal		        = 0,
	  uReturned					= 0;
	VARIANT v;
	BSTR strClassProp			= NULL;
	CString tmp;

	// Creates a single uninitialized object of the class 
	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *)&pLoc);

	if(FAILED(hres)) 
	{
		Errors.Add("Failed to create IWbemLocator object.\n");
		return false; 
	}
	
	LPWSTR ConnectString = new WCHAR[29]; 
	_snwprintf_s(ConnectString, 28, _TRUNCATE, L"\\\\%S\\ROOT\\cimv2",node.ipaddress);
	hres = pLoc->ConnectServer(_bstr_t(ConnectString), NULL, NULL, 0, NULL, 0,
		0, &pSvc);
	delete [] ConnectString;
	
	if(FAILED(hres)) 
	{
		Errors.Add("Could not connect to WMI for Win32_OperatingSystem query.\n");
		pLoc->Release();     
		return false;
	}
	
	// Sets the authentication information that will be used to make calls on the specified proxy
	hres = CoSetProxyBlanket(pSvc,
		RPC_C_AUTHN_WINNT, // NTLMSSP (Windows NT LAN Manager Security Support Provider). 
		RPC_C_AUTHZ_NONE,  // Server performs no authorization
		NULL,
		RPC_C_AUTHN_LEVEL_CALL, // Authenticates only at the beginning of each remote procedure call when the server receives the request.
		RPC_C_IMP_LEVEL_IMPERSONATE, // The server process can impersonate the client's security context while acting on behalf of the client. 
		NULL,
		EOAC_NONE);

	if(FAILED(hres)) 
	{
		Errors.Add("Could not set proxy blanket.\n");      
		pLoc->Release();     
		return false;
	}
	
	// Allocates a new string and copies the passed string into it
	BSTR Language = SysAllocString(L"WQL");
	BSTR Query    = SysAllocString(L"SELECT * FROM Win32_OperatingSystem");
	
	hres = pSvc->ExecQuery(Language,Query,WBEM_FLAG_FORWARD_ONLY,0,&pEnum);

	if(FAILED(hres)) 
	{
		Errors.Add("ExecQuery Win32_OperatingSystem Error\n");
		pLoc->Release();     
		return false;
	}
	
	while((hres = pEnum->Next(1000,	// time in milliseconds that the call blocks
					1,				// number of requested objects
					&pObj,			// IWbemClassObject 
					&uReturned))	// number of objects returned
					== WBEM_S_NO_ERROR)
	{
		strClassProp = SysAllocString(L"Caption");
		hres = pObj->Get(strClassProp, 0, &v,0, 0);
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format(_T("Operating System: %S"), V_BSTR(&v));
			OperatingSystem.Add(tmp);
			VariantClear(&v);
		}
		
		SysReAllocString(&strClassProp,L"CSDVersion");
		hres = pObj->Get(strClassProp, 0, &v, NULL, NULL);
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format("%S", V_BSTR(&v));
			OperatingSystem.Add(tmp);
			VariantClear(&v);
		}
		
		pObj->Release();            
	}

	SysReAllocString(&Language,L"WQL");
	SysReAllocString(&Query,L"SELECT * FROM Win32_ComputerSystem");

	hres = pSvc->ExecQuery(Language,Query,WBEM_FLAG_FORWARD_ONLY,0,&pEnum);
	
	if(FAILED(hres))
	{
		Errors.Add("ExecQuery Win32_ComputerSystem Error\n");
		pLoc->Release();     
		return false;
	}

	while((hres = pEnum->Next(1000,	// time in milliseconds that the call blocks
				  1,				// number of requested objects
				  &pObj,			// IWbemClassObject 
				  &uReturned))		// number of objects returned
				  == WBEM_S_NO_ERROR)
	{
		strClassProp = SysAllocString(L"Domain");
		hres = pObj->Get(strClassProp, 0, &v,0, 0);
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			node.DNS.Format("%S", V_BSTR(&v));
			VariantClear(&v);
		}
	
		SysReAllocString(&strClassProp,L"Name");
		hres = pObj->Get(strClassProp, 0, &v, NULL, NULL);
		if (SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{	
			node.NetBIOS.Format("%S", V_BSTR(&v));
			VariantClear(&v);
		}
		pObj->Release();    
	}

	if(pEnum)
		pEnum->Release();
	if(pLoc)
		pLoc->Release();
	if(pSvc)
		pSvc->Release();
	SysFreeString(strClassProp);
	SysFreeString(Language);
	SysFreeString(Query);
 	return true;
}

bool CWfpWMI::Groups_get(void)
{
	return false;
}

bool CWfpWMI::NetBIOSShares_get(void)
{
	CString tmp;
	NETRESOURCE nr;
	VARIANT v;
	HRESULT hres				= WBEM_S_NO_ERROR;
	IEnumWbemClassObject *pEnum = NULL;
	IWbemServices *pSvc			= NULL;
	IWbemLocator *pLoc		    = NULL;
	IWbemClassObject *pObj      = NULL;
	ULONG uTotal		        = 0,
	  uReturned					= 0;
	int i						= 0;
	
	// Creates a single uninitialized object of the class 
	hres = CoCreateInstance(CLSID_WbemLocator, 0,CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
 	if (FAILED(hres)) 
	{
		Errors.Add("Failed to create IWbemLocator object.\n");
		return false; 
	}
		
	LPWSTR  ConnectString = NULL;
	ConnectString = new WCHAR[29];
	_snwprintf_s(ConnectString, 28, _TRUNCATE, L"\\\\%S\\ROOT\\cimv2", node.ipaddress);
	hres = pLoc->ConnectServer(_bstr_t(ConnectString),NULL,NULL,0,NULL,0,0,&pSvc);
	delete [] ConnectString;
	
	if(FAILED(hres)) 
	{
		Errors.Add("Could not connect to WMI for Win32_Share query.\n");
		pLoc->Release();     
		return false;
	}
		
	// Sets the authentication information that will be used to make calls on the specified proxy
	hres = CoSetProxyBlanket(pSvc,
		RPC_C_AUTHN_WINNT, // NTLMSSP (Windows NT LAN Manager Security Support Provider). 
		RPC_C_AUTHZ_NONE,  // Server performs no authorization
		NULL,
		RPC_C_AUTHN_LEVEL_CALL, // Authenticates only at the beginning of each remote procedure call when the server receives the request.
		RPC_C_IMP_LEVEL_IMPERSONATE, // The server process can impersonate the client's security context while acting on behalf of the client. 
		NULL,
		EOAC_NONE);

	if(FAILED(hres)) 
	{
		Errors.Add("Could not set proxy blanket. Error code = 0x\n");      
		pLoc->Release();     
		return false;
	}
	BSTR strClassProp	= SysAllocString(L"Name");
	BSTR strClassProp2	= SysAllocString(L"Description");

	BSTR Language		= SysAllocString(L"WQL");
	BSTR Query			= SysAllocString(L"SELECT * FROM Win32_Share");
	hres = pSvc->ExecQuery(Language,Query,WBEM_FLAG_FORWARD_ONLY,0,&pEnum);
	
	if(FAILED(hres))
	{
		Errors.Add("ExecQuery Win32_Share Error\n");
		pLoc->Release();     
		return false;
	}

	while((hres = pEnum->Next(1000,	// time in milliseconds that the call blocks
					1,		        // number of requested objects
					&pObj,		    // IWbemClassObject 
					&uReturned))    // number of objects returned
					== WBEM_S_NO_ERROR)
	{
		hres = pObj->Get(strClassProp, 0, &v,0, 0);
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format("\\\\%s\\%S", node.NetBIOS, V_BSTR(&v));
			VariantClear(&v);
		}
		
		if(tmp.Find("IPC$")== -1) // Skip IPC$ Share
		{
			WNetCancelConnection2(_T("X:") ,CONNECT_UPDATE_PROFILE, TRUE);
			nr.dwType = RESOURCETYPE_ANY;
			nr.lpLocalName = _T("X:");
			nr.lpRemoteName = tmp.GetBuffer();
			nr.lpProvider = NULL;
			if(WNetAddConnection2(&nr, NULL, NULL, FALSE) == NO_ERROR)
			{
				CString tmp2;
				tmp2.Format("%s Accessible with current credentials.", tmp);
				NetBIOSShares.Add(tmp2);
				WNetCancelConnection2(_T("X:") ,CONNECT_UPDATE_PROFILE, TRUE);
			}
			else
				NetBIOSShares.Add(tmp);
		}
		else
			NetBIOSShares.Add(tmp);
		
		hres = pObj->Get(strClassProp2, 0, &v, NULL, NULL);
		if (SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format("%S", V_BSTR(&v));
			NetBIOSShares.Add(tmp);
			VariantClear(&v);
		}
		
		SysFreeString(strClassProp);
		SysFreeString(strClassProp2);
		pObj->Release();            
	}
	if(pEnum)
		pEnum->Release();
	if(pLoc)
		pLoc->Release();
	if(pSvc)
		pSvc->Release();
	SysFreeString(Language);
	SysFreeString(Query);
	return true;
}

bool CWfpWMI::Services_get(void) {
	CString tmp, tmp2;
	HRESULT hres				= WBEM_S_NO_ERROR;
	IEnumWbemClassObject *pEnum = NULL;
	IWbemServices *pSvc			= NULL;
	IWbemLocator *pLoc		    = NULL;
	IWbemClassObject *pObj      = NULL;
	ULONG uTotal		        = 0,
	  uReturned					= 0;
	VARIANT v;
	LPWSTR ConnectString = new WCHAR[29];
	
	// Creates a single uninitialized object of the class 
	hres = CoCreateInstance(CLSID_WbemLocator, 0,CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
 
	if (FAILED(hres)) 
	{
		Errors.Add("Failed to create IWbemLocator object.\n");
		return false; 
	}
		
	_snwprintf_s(ConnectString, 28, _TRUNCATE, L"\\\\%S\\ROOT\\cimv2", node.ipaddress);
	hres = pLoc->ConnectServer(_bstr_t(ConnectString),NULL,NULL,0,NULL,0,0,&pSvc);
	delete [] ConnectString;
		
	if(FAILED(hres)) 
	{
		Errors.Add("Could not connect to WMI for Win32_Service query.\n");
		pLoc->Release();     
		return false;
	}
		
	// Sets the authentication information that will be used to make calls on the specified proxy
	hres = CoSetProxyBlanket(pSvc,
		RPC_C_AUTHN_WINNT, // NTLMSSP (Windows NT LAN Manager Security Support Provider). 
		RPC_C_AUTHZ_NONE,  // Server performs no authorization
		NULL,
		RPC_C_AUTHN_LEVEL_CALL, // Authenticates only at the beginning of each remote procedure call when the server receives the request.
		RPC_C_IMP_LEVEL_IMPERSONATE, // The server process can impersonate the client's security context while acting on behalf of the client. 
		NULL,
		EOAC_NONE);

	if(FAILED(hres)) 
	{
		Errors.Add("Could not set proxy blanket. Error code = 0x\n");      
		pLoc->Release();     
		return false;
	}

	BSTR strClassProp	= SysAllocString(L"Name");
	BSTR strClassProp2	= SysAllocString(L"Description");
	BSTR Language		= SysAllocString(L"WQL");
	BSTR Query			= SysAllocString(L"SELECT * FROM Win32_Service");
	
	hres = pSvc->ExecQuery(Language,Query,WBEM_FLAG_FORWARD_ONLY,0,&pEnum);
	if(FAILED(hres))
  	{
		Errors.Add("ExecQuery Win32_Service Error\n");
		pLoc->Release();     
        return false;
	}

	while((hres = pEnum->Next(1000,	// time in milliseconds that the call blocks
					  1,			// number of requested objects
					  &pObj,		// IWbemClassObject 
					  &uReturned))  // number of objects returned
					  == WBEM_S_NO_ERROR)
	{
		hres = pObj->Get(strClassProp, 0, &v,0, 0);
		tmp2.Empty();
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format("%S ", V_BSTR(&v));
			if(tmp.Find("Apache")!= -1)
			{
				CString http;
				http.Format("%S http://%s ", V_BSTR(&v), node.ipaddress); 
				tmp2.operator +=(http);
			}
			else 
				tmp2.operator +=(tmp);
			VariantClear(&v);
		}
		
		hres = pObj->Get(strClassProp2, 0, &v, NULL, NULL);
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format("%S", V_BSTR(&v));
			tmp2.operator +=(tmp);
			VariantClear(&v);
		}
		Services.Add(tmp2);
		pObj->Release();            
	}
	
	if(pEnum)
		pEnum->Release();
	if(pLoc)
		pLoc->Release();
	if(pSvc)
		pSvc->Release();
	SysFreeString(strClassProp);
	SysFreeString(strClassProp2);
	SysFreeString(Language);
	SysFreeString(Query);
	return true;
}

bool CWfpWMI::Sessions_get(void) {
	// Not Implemented
	return false;
}

bool CWfpWMI::Transports_get(void)
{
	CString tmp;
	HRESULT hres				= WBEM_S_NO_ERROR;
	IEnumWbemClassObject *pEnum = NULL;
	IWbemServices *pSvc			= NULL;
	IWbemLocator *pLoc		    = NULL;
	IWbemClassObject *pObj      = NULL;
	ULONG uTotal		        = 0,
	  uReturned					= 0;
	VARIANT v;
	int i = 0;
	
	// Creates a single uninitialized object of the class 
	hres = CoCreateInstance(CLSID_WbemLocator, 0,CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
 	if (FAILED(hres)) 
	{
		Errors.Add("Failed to create IWbemLocator object.\n");
		return false; 
	}
		
	LPWSTR  ConnectString = NULL;
	ConnectString = new WCHAR[29];
	_snwprintf_s(ConnectString, 28, _TRUNCATE, L"\\\\%S\\ROOT\\cimv2", node.ipaddress);
	hres = pLoc->ConnectServer(_bstr_t(ConnectString),NULL,NULL,0,NULL,0,0,&pSvc);
	delete [] ConnectString;
	
	if(FAILED(hres)) 
	{
		Errors.Add("Could not connect to WMI for Win32_NetworkAdapter query.\n");
		pLoc->Release();     
		return false;
	}
		
	// Sets the authentication information that will be used to make calls on the specified proxy
	hres = CoSetProxyBlanket(pSvc,
		RPC_C_AUTHN_WINNT, // NTLMSSP (Windows NT LAN Manager Security Support Provider). 
		RPC_C_AUTHZ_NONE,  // Server performs no authorization
		NULL,
		RPC_C_AUTHN_LEVEL_CALL, // Authenticates only at the beginning of each remote procedure call when the server receives the request.
		RPC_C_IMP_LEVEL_IMPERSONATE, // The server process can impersonate the client's security context while acting on behalf of the client. 
		NULL,
		EOAC_NONE);

	if(FAILED(hres)) 
	{
		Errors.Add("Could not set proxy blanket. Error code = 0x\n");      
		pLoc->Release();     
		return false;
	}
	BSTR strClassProp	= SysAllocString(L"Name");
	BSTR Language		= SysAllocString(L"WQL");
	BSTR Query			= SysAllocString(L"SELECT * FROM Win32_NetworkAdapter");
	hres = pSvc->ExecQuery(Language,Query,WBEM_FLAG_FORWARD_ONLY,0,&pEnum);
	
	if(FAILED(hres))
	{
		Errors.Add("ExecQuery Win32_NetworkAdapter Error\n");
		pLoc->Release();     
		return false;
	}

	while((hres = pEnum->Next(1000,	// time in milliseconds that the call blocks
					1,		        // number of requested objects
					&pObj,		    // IWbemClassObject 
					&uReturned))    // number of objects returned
					== WBEM_S_NO_ERROR)
	{
		strClassProp = SysAllocString(L"MACAddress");
		hres = pObj->Get(strClassProp, 0, &v,0, 0);
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format("%S", V_BSTR(&v));
			// Don't insert duplicates into array
			if(MACAddress.GetSize() > 0) 
			{
				bool exists = false;
				for(i = 0; i <= MACAddress.GetUpperBound(); i++)
				{	
					if(strcmp(tmp, MACAddress[i]) == 0)
						exists = true;
				}
				if(!exists)
					MACAddress.Add(tmp);
			}	
			else
				MACAddress.Add(tmp);

			VariantClear(&v);
		}
		SysFreeString(strClassProp);
		pObj->Release();            
	}
	if(pEnum)
		pEnum->Release();
	if(pLoc)
		pLoc->Release();
	if(pSvc)
		pSvc->Release();
	SysFreeString(Language);
	SysFreeString(Query);
	return true;
}

bool CWfpWMI::PatchLevel_get(void)
{
	CString tmp;
	HRESULT hres				= WBEM_S_NO_ERROR;
	IEnumWbemClassObject *pEnum = NULL;
	IWbemServices *pSvc			= NULL;
	IWbemLocator *pLoc		    = NULL;
	IWbemClassObject *pObj      = NULL;
	ULONG uTotal		        = 0,
	  uReturned					= 0;
	VARIANT v;
	int i = 0;
	
	// Creates a single uninitialized object of the class 
	hres = CoCreateInstance(CLSID_WbemLocator, 0,CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
 	if (FAILED(hres)) 
	{
		Errors.Add("Failed to create IWbemLocator object.\n");
		return false; 
	}
		
	LPWSTR  ConnectString = NULL;
	ConnectString = new WCHAR[29];
	_snwprintf_s(ConnectString, 28, _TRUNCATE, L"\\\\%S\\ROOT\\cimv2", node.ipaddress);
	hres = pLoc->ConnectServer(_bstr_t(ConnectString),NULL,NULL,0,NULL,0,0,&pSvc);
	delete [] ConnectString;
	
	if(FAILED(hres)) 
	{
		Errors.Add("Could not connect to WMI for Win32_QuickFixEngineering query.\n");
		pLoc->Release();     
		return false;
	}
		
	// Sets the authentication information that will be used to make calls on the specified proxy
	hres = CoSetProxyBlanket(pSvc,
		RPC_C_AUTHN_WINNT, // NTLMSSP (Windows NT LAN Manager Security Support Provider). 
		RPC_C_AUTHZ_NONE,  // Server performs no authorization
		NULL,
		RPC_C_AUTHN_LEVEL_CALL, // Authenticates only at the beginning of each remote procedure call when the server receives the request.
		RPC_C_IMP_LEVEL_IMPERSONATE, // The server process can impersonate the client's security context while acting on behalf of the client. 
		NULL,
		EOAC_NONE);

	if(FAILED(hres)) 
	{
		Errors.Add("Could not set proxy blanket. Error code = 0x\n");      
		pLoc->Release();     
		return false;
	}
	BSTR strClassProp	= SysAllocString(L"Name");
	BSTR Language		= SysAllocString(L"WQL");
	BSTR Query			= SysAllocString(L"SELECT * FROM Win32_QuickFixEngineering");
	hres = pSvc->ExecQuery(Language,Query,WBEM_FLAG_FORWARD_ONLY,0,&pEnum);
	
	if(FAILED(hres))
	{
		Errors.Add("ExecQuery Win32_QuickFixEngineering Error\n");
		pLoc->Release();     
		return false;
	}

	while((hres = pEnum->Next(1000,	// time in milliseconds that the call blocks
					1,		        // number of requested objects
					&pObj,		    // IWbemClassObject 
					&uReturned))    // number of objects returned
					== WBEM_S_NO_ERROR)
	{
		strClassProp = SysAllocString(L"HotFixID");
		hres = pObj->Get(strClassProp, 0, &v,0, 0);
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			CString tmp2;
			tmp.Format("HotFix: %S", V_BSTR(&v));
			if(strcmp(tmp, "HotFix: File 1") != 0)
				tmp2.operator +=(tmp);
			VariantClear(&v);
		
			if(!tmp2.IsEmpty())
			{
				SysReAllocString(&strClassProp,L"Description");
				hres = pObj->Get(strClassProp, 0, &v, NULL, NULL);
				if (SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
				{
					tmp.Format(" %S", V_BSTR(&v));
					tmp2.operator +=(tmp);
					VariantClear(&v);
				}
				PatchLevel.Add(tmp2);
			}
		}

		SysFreeString(strClassProp);
		pObj->Release();            
	}
	if(pEnum)
		pEnum->Release();
	if(pLoc)
		pLoc->Release();
	if(pSvc)
		pSvc->Release();
	SysFreeString(Language);
	SysFreeString(Query);
	return true;
}

bool CWfpWMI::Users_get(void)
{
	CString tmp, user;
	HRESULT hres				= WBEM_S_NO_ERROR;
	IEnumWbemClassObject *pEnum = NULL;
	IWbemServices *pSvc			= NULL;
	IWbemLocator *pLoc		    = NULL;
	IWbemClassObject *pObj      = NULL;
	ULONG uTotal		        = 0,
	  uReturned					= 0;
	VARIANT v;
	LPWSTR ConnectString = new WCHAR[29];
	
	// Creates a single uninitialized object of the class 
	hres = CoCreateInstance(CLSID_WbemLocator, 0,CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
 
	if(FAILED(hres)) 
	{
		Errors.Add("Failed to create IWbemLocator object.\n");
		return false; 
	}
		
	_snwprintf_s(ConnectString, 28, _TRUNCATE, L"\\\\%S\\ROOT\\cimv2", node.ipaddress);
	hres = pLoc->ConnectServer(_bstr_t(ConnectString),NULL,NULL,0,NULL,0,0,&pSvc);
	delete [] ConnectString;
		
	if(FAILED(hres)) 
	{
		Errors.Add("Could not connect to WMI for Win32_UserAccount query.\n");
		pLoc->Release();     
		return false;
	}
		
	// Sets the authentication information that will be used to make calls on the specified proxy
	hres = CoSetProxyBlanket(pSvc,
		RPC_C_AUTHN_WINNT, // NTLMSSP (Windows NT LAN Manager Security Support Provider). 
		RPC_C_AUTHZ_NONE,  // Server performs no authorization
		NULL,
		RPC_C_AUTHN_LEVEL_CALL, // Authenticates only at the beginning of each remote procedure call when the server receives the request.
		RPC_C_IMP_LEVEL_IMPERSONATE, // The server process can impersonate the client's security context while acting on behalf of the client. 
		NULL,
		EOAC_NONE);

	if(FAILED(hres)) 
	{
		Errors.Add("Could not set proxy blanket. Error code = 0x\n");      
		pLoc->Release();     
		return false;
	}
	
	BSTR strClassProp	= SysAllocString(L"Name");
	BSTR strClassProp2  = SysAllocString(L"Description");
	BSTR strClassProp3  = SysAllocString(L"SID");
	BSTR Language		= SysAllocString(L"WQL");
	BSTR Query			= SysAllocString(L"SELECT * FROM Win32_UserAccount");
	
	hres = pSvc->ExecQuery(Language,Query,WBEM_FLAG_FORWARD_ONLY,0,&pEnum);
	if(FAILED(hres))
  	{
		Errors.Add("ExecQuery Win32_UserAccount Error\n");
		pLoc->Release();     
        return false;
	}

	while((hres = pEnum->Next(1000,	// time in milliseconds that the call blocks
					  1,			// number of requested objects
					  &pObj,		// IWbemClassObject 
					  &uReturned))  // number of objects returned
					  == WBEM_S_NO_ERROR)
	{
		user.Empty();
		hres = pObj->Get(strClassProp, 0, &v,0, 0);
		// Name
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format("%S ", V_BSTR(&v));
			user.operator +=(tmp);
			VariantClear(&v);
		}
		
		hres = pObj->Get(strClassProp2, 0, &v, NULL, NULL);
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format("%S ", V_BSTR(&v));
			user.operator +=(tmp);
			VariantClear(&v);
		}
		
		hres = pObj->Get(strClassProp3, 0, &v, NULL, NULL);
		if(SUCCEEDED(hres) && (V_VT(&v) == VT_BSTR))
		{
			tmp.Format("SID %S", V_BSTR(&v));
			user.operator +=(tmp);
			VariantClear(&v);
		}
		Users.Add(user);
		pObj->Release();            
	}
	
	if(pEnum)
		pEnum->Release();
	if(pLoc)
		pLoc->Release();
	if(pSvc)
		pSvc->Release();
	SysFreeString(strClassProp);
	SysFreeString(strClassProp2);
	SysFreeString(strClassProp3);
	SysFreeString(Language);
	SysFreeString(Query);
	return true;
}