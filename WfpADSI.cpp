#include "StdAfx.h"
#include ".\wfpadsi.h"

using namespace std;

CWfpADSI::CWfpADSI(void)
{
}

CWfpADSI::~CWfpADSI(void)
{
}

bool CWfpADSI::NetBIOSShares_get(void)
{
	// FIXME: Currently ADSI_Shares only returns 1 share.
	IADsFileShare *pShares = NULL;	
	HRESULT hr = WBEM_S_NO_ERROR;
	LPWSTR  adsPath = new WCHAR[37]; 
	IADsContainer *pCont = NULL;
	IADsCollection *pColl = NULL;
	IUnknown *pUnk = NULL;
	IEnumVARIANT *pEnum = NULL;
	ULONG lFetch = 0;
	IDispatch *pDisp = NULL;
	CString tmp, session;
	BSTR bstr;
	VARIANT var;
	
	_snwprintf_s(adsPath, 36, 26, L"WinNT://%S/LanmanServer", node.ipaddress);
	hr = ADsGetObject(adsPath, IID_IADsContainer, (void**)&pCont);
	if(FAILED(hr))
	{
		delete [] adsPath;
		ErrorHandler("ADsGetObject", GetLastError());
		return false;
	}

	hr = pCont->get__NewEnum(&pUnk);
	if (FAILED(hr))
	{
		delete [] adsPath;
		return false;
	}

	hr = pUnk->QueryInterface(IID_IEnumVARIANT,(void**)&pEnum);
	if (FAILED(hr))
	{
		delete [] adsPath;
		return false;
	}

	// Now Enumerate

	VariantInit(&var);
	pEnum->Reset();
	hr = pEnum->Next(1, &var, &lFetch);
	//tmp.Format("Number of items %lu\n", lFetch);
	//pWfpDlg->InsertString(tmp);
	while(SUCCEEDED(hr) && lFetch > 0)
	{
		if (lFetch == 1)    
		{
			pDisp = V_DISPATCH(&var);
			pDisp->QueryInterface(IID_IADsFileShare , (void**)&pShares);
			pShares->get_HostComputer(&bstr);
			tmp.Format(_T("%S\\"),bstr);
			NetBIOSShares.Add(tmp);   
			SysFreeString(bstr);

			pShares->get_Name(&bstr);
			tmp.Format(_T("%S\n"),bstr);
			NetBIOSShares.Add(tmp);   
			SysFreeString(bstr);

			pShares->get_Description(&bstr);
			tmp.Format(_T("%S\n"),bstr);
			NetBIOSShares.Add(tmp);   
			SysFreeString(bstr);

			pShares->Release();
		}
		VariantClear(&var);
		pDisp=NULL;
		hr = pEnum->Next(1, &var, &lFetch);
	};
	
	delete [] adsPath;
	
	if(pDisp)
		pDisp->Release();
	if(pEnum)
		pEnum->Release();
	if(pUnk)
		pUnk->Release();
	if(pColl)
		pColl->Release();
	return true;
}

bool CWfpADSI::Groups_get(void)
{
	if(!Services_Users_Groups(ENUM_GROUPS))
		return false;
	else
		return true;
}

bool CWfpADSI::OperatingSystem_get(void)
{
	CString tmp;
	IADsComputer *pComp = NULL;
	LPWSTR  pwszBindingString = new WCHAR[33]; 
	HRESULT hr = WBEM_S_NO_ERROR;
	BSTR bstr, bstr2;
	
	_snwprintf_s(pwszBindingString, 32, 32, L"WinNT://%S,computer", node.ipaddress);
   	
	hr = ADsGetObject(pwszBindingString,IID_IADsComputer,(void**)&pComp);
	if(FAILED(hr))
	{
		ErrorHandler("ADsGetObject", GetLastError());
		delete[] pwszBindingString;
		return false;
	}
			
	pComp->get_OperatingSystem(&bstr);
	pComp->get_OperatingSystemVersion(&bstr2);

	tmp.Format(_T("Operating System: %S %S"),bstr,bstr2);
	OperatingSystem.Add(tmp);
	SysFreeString(bstr);
	SysFreeString(bstr2);

	pComp->get_Division(&bstr);
	tmp.Format(_T("Organization: %S"),bstr);
	OperatingSystem.Add(tmp);
	SysFreeString(bstr);
			
	pComp->get_Processor(&bstr);
	tmp.Format(_T("Processor : %S"),bstr);
	OperatingSystem.Add(tmp);
	SysFreeString(bstr);

	pComp->get_ProcessorCount(&bstr);
	tmp.Format(_T("Processor Count : %S"),bstr);
	OperatingSystem.Add(tmp);
	SysFreeString(bstr);

	pComp->get_GUID(&bstr);
	tmp.Format("GUID: %S",bstr);
	OperatingSystem.Add(tmp);
	SysFreeString(bstr);
			
	pComp->get_Owner(&bstr);
	tmp.Format(_T("Computer owner: %S"),bstr);
	OperatingSystem.Add(tmp);
	SysFreeString(bstr);

	pComp->Release();
	delete[] pwszBindingString;
	return true;
}

bool CWfpADSI::Services_get(void)
{
	if(!Services_Users_Groups(ENUM_GROUPS))
		return false;
	else
		return true;
}

bool CWfpADSI::Sessions_get(void) {
	IADsFileServiceOperations *pFso = NULL;	
	IADsSession *pSes				= NULL;
	LONG seconds					= 0;
	HRESULT hr						= WBEM_S_NO_ERROR;
	LPWSTR  adsPath = new WCHAR[37]; 
	LPWKSTA_INFO_102 pwBuf			= NULL;
	IADsCollection *pColl			= NULL;
	IUnknown *pUnk					= NULL;
	IEnumVARIANT *pEnum				= NULL;
	ULONG lFetch					= 0;
	IDispatch *pDisp				= NULL;
	BSTR bstr;
	VARIANT var;
	CString tmp, session;
		
	_snwprintf_s(adsPath, 36, 36, L"WinNT://%S/LanmanServer", node.ipaddress);
	hr = ADsGetObject(adsPath, IID_IADsFileServiceOperations, (void**)&pFso);
	if(FAILED(hr))
	{
		delete [] adsPath;
		ErrorHandler("ADsGetObject", GetLastError());
		return false;
	}
	
	hr = pFso->Sessions(&pColl);
	pFso->Release();

	// Now to enumerate sessions. 
	hr = pColl->get__NewEnum(&pUnk);
	if (FAILED(hr))
	{
		delete [] adsPath;
		return false;
	}
			
	pColl->Release();

	hr = pUnk->QueryInterface(IID_IEnumVARIANT,(void**)&pEnum);
	if (FAILED(hr))
	{
		delete [] adsPath;
		return false;
	}
	pUnk->Release();

	// Now Enumerate

	VariantInit(&var);
	hr = pEnum->Next(1, &var, &lFetch);
	while(hr == S_OK)
	{
		if (lFetch == 1)    
		{
			pDisp = V_DISPATCH(&var);
			pDisp->QueryInterface(IID_IADsSession, (void**)&pSes);
			pSes->get_Computer(&bstr);
			tmp.Format(_T("Client: %S "),bstr);
			session.operator +=(tmp);
			   
			SysFreeString(bstr);
			pSes->get_User(&bstr);
			tmp.Format(_T("User: %S "),bstr);
			session.operator +=(tmp);
			
			SysFreeString(bstr);

			pSes->get_ConnectTime(&seconds);
			tmp.Format(_T("Seconds Connected: %d "),seconds);
			session.operator +=(tmp);
			pSes->get_IdleTime(&seconds);
			tmp.Format(_T("Seconds Idle: %d"),seconds);
			session.operator +=(tmp);
			Sessions.Add(session);
			pSes->Release();
		}
		VariantClear(&var);
		pDisp=NULL;
		hr = pEnum->Next(1, &var, &lFetch);
	};
	
	delete [] adsPath;
	hr = pEnum->Release();
	return true;
}

bool CWfpADSI::Users_get(void)
{
	if(!Services_Users_Groups(ENUM_USERS))
		return false;
	else
		return true;
}

bool CWfpADSI::Services_Users_Groups(int enumtype)
{
	IADsContainer * pIADsCont = NULL;
	LPWSTR  pwszBindingString = new WCHAR[33];
	LPWSTR pwszFilter = NULL;
	IDispatch *pDispatch = NULL;
	IADs *pIADs	= NULL;
	VARIANT vFilter, Variant;
	HRESULT hr = WBEM_S_NO_ERROR;
	IEnumVARIANT *pEnumVariant = NULL; // Ptr to the IEnumVariant Interface
	ULONG ulElementsFetched = 0;    // Number of elements fetched
	BSTR bsResult, bsResult2, bsResult3;
	CString tmp, tmp2, type;

	_snwprintf_s(pwszBindingString, 32, 32, L"WinNT://%S,computer", node.ipaddress);
	hr = ADsGetObject(pwszBindingString, IID_IADsContainer,(void **)&pIADsCont);

	if(SUCCEEDED(hr))
	{
		VariantInit(&vFilter);
		// Build a Variant of array type, using the filter passed
		hr = ADsBuildVarArrayStr(&pwszFilter, 1, &vFilter);		
		if (SUCCEEDED(hr))
		{
			// Set the filter for the results of the Enum
			hr = pIADsCont->put_Filter(vFilter);
			if (SUCCEEDED(hr))
			{
				// Builds an enumerator interface- this will be used 
				// to enumerate the objects contained in the IADsContainer 
				hr = ADsBuildEnumerator(pIADsCont,&pEnumVariant);
				// While no errors- Loop through and print the data
				while (SUCCEEDED(hr) && hr != S_FALSE) 
				{
					// Object comes back as a VARIANT holding an IDispatch *
					hr = ADsEnumerateNext(pEnumVariant,1,&Variant,&ulElementsFetched);
					if(hr != S_FALSE) 
					{ 
						pDispatch = Variant.pdispVal;
						// QI the Variant's IDispatch * for the IADs interface
						hr = pDispatch->QueryInterface(IID_IADs,(VOID **) &pIADs) ;
 						if (SUCCEEDED(hr))
						{
							// Print some information about the object
							tmp2.Empty();
							pIADs->get_Class(&bsResult);
							pIADs->get_Name(&bsResult2);
						
							pIADs->get_GUID(&bsResult3);
							type.Format("%S", (LPOLESTR) bsResult);
							tmp.Format(_T("%S"),(LPOLESTR) bsResult2);
							tmp2.operator +=(tmp);
							tmp.Format(_T(" GUID: %S"),(LPOLESTR) bsResult3);
							tmp2.operator +=(tmp);
							if(type.Find("Service") != -1)
								if(options.optionservices)
									Services.Add(tmp2);
							if(type.Find("Group") != -1)
								if(options.optiongroups)
									Groups.Add(tmp2);
							if(type.Find("User") != -1)
								if(options.optionusers)
									Users.Add(tmp2);
							SysFreeString(bsResult);
							SysFreeString(bsResult2);
							SysFreeString(bsResult3);
							pIADs->Release();
							pIADs = NULL;
						}
					}
				}
 
				// Since the hr from iteration was lost, free 
				// the interface if the ptr is != NULL
				if(pEnumVariant)
				{
					pEnumVariant->Release();
					pEnumVariant = NULL;
				}
				VariantClear(&Variant);
			}
		}
		VariantClear(&vFilter);
	}

	delete[] pwszBindingString;
	return true;
}