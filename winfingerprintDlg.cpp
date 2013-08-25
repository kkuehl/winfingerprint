/*  
    $Id: winfingerprintDlg.cpp,v 1.156 2008/12/17 02:47:15 vacuum Exp $
    winfingerprintDlg.cpp : implementation file
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

#include "stdafx.h"
#include "winfingerprint.h"
#include "winfingerprintDlg.h"
#include "WfpEngine.h" // Access to the CWfpEngine
#include "WfpADSI.h"
#include "WfpNET.h"
#include "WfpWMI.h"
#include <dos.h>
#include <direct.h>
#include ".\winfingerprintdlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

u_short	in_cksum(u_short *addr, int len);
typedef const char * (*MYPCAP_PCAP_LIB_VERSION)(VOID);

/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	virtual BOOL OnInitDialog();
	//{{AFX_MSG(CAboutDlg)
	afx_msg void OnWww();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
	HMODULE hwpcap;
	MYPCAP_PCAP_LIB_VERSION ppcap_lib_version;
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
	ON_BN_CLICKED(IDC_WWW, OnWww)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CWinfingerprintDlg dialog

CWinfingerprintDlg::CWinfingerprintDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CWinfingerprintDlg::IDD, pParent)
	, timeout(5)
	, retries(3)
	, m_stop(0)
	, opt_macaddress(TRUE)
	, opt_netmask(FALSE)
	, opt_showerror(FALSE)
	, m_communitystring(_T("public"))
	, max_connections(1024)
{
	//{{AFX_DATA_INIT(CWinfingerprintDlg)	
	m_output = _T("");
	tcpendport = 1024;
	tcpstartport = 1;
	udpstartport = 1;
	udpendport = 1024;
	
	scan_type = SCANRANGE;
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

}

void CWinfingerprintDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CWinfingerprintDlg)
	DDX_Check(pDX, IDC_UDPPORTS, opt_udpportscan);
	DDX_Check(pDX, IDC_SNMP, opt_snmp);
	DDX_Text(pDX, IDC_OUTPUT, m_output);
	DDX_Text(pDX, IDC_TCPENDPORT, tcpendport);
	DDV_MinMaxInt(pDX, tcpendport, 1, 65535);
	DDX_Text(pDX, IDC_TCPSTARTPORT, tcpstartport);
	DDV_MinMaxInt(pDX, tcpstartport, 1, 65535);
	DDX_Text(pDX, IDC_HOST, m_outputfile);
	DDX_Text(pDX, IDC_UDPSTARTPORT, udpstartport);
	DDV_MinMaxInt(pDX, udpstartport, 1, 65535);
	DDX_Text(pDX, IDC_UDPENDPORT, udpendport);
	DDV_MinMaxInt(pDX, udpendport, 1, 65535);
	//}}AFX_DATA_MAP
	DDX_Text(pDX, IDC_TIMEOUT, timeout);
	DDV_MinMaxInt(pDX, timeout, 1, 60);
	DDX_Text(pDX, IDC_COMMUNITY, m_communitystring);
	DDX_Text(pDX, IDC_MAXCONN, max_connections);
	DDV_MinMaxInt(pDX, max_connections, 1, 65535);
	DDX_Text(pDX, IDC_RETRIES, retries);
	DDV_MinMaxInt(pDX, retries, 1, 10);
	DDX_Check(pDX, IDC_TCPPORTS, opt_tcpportscan);
}

BEGIN_MESSAGE_MAP(CWinfingerprintDlg, CDialog)
	//{{AFX_MSG_MAP(CWinfingerprintDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BROWSE, OnBrowse)
	ON_NOTIFY(EN_LINK, IDC_OUTPUT, OnRichEditExLink )
	//}}AFX_MSG_MAP
	ON_COMMAND(ID_SMBSCANOPTIONS_ADSI, &CWinfingerprintDlg::OnSmbscanoptionsAdsi)
	ON_COMMAND(ID_SMBSCANOPTIONS_NET, &CWinfingerprintDlg::OnSmbscanoptionsNet)
	ON_COMMAND(ID_SMBSCANOPTIONS_WMI, &CWinfingerprintDlg::OnSmbscanoptionsWmi)
	ON_COMMAND(ID_FILE_HELP, &CWinfingerprintDlg::OnFileHelp)
	ON_COMMAND(ID_FILE_ABOUT, &CWinfingerprintDlg::OnFileAbout)
	ON_COMMAND(ID_FILE_SAVERESULTS, &CWinfingerprintDlg::OnFileSaveresults)
	ON_COMMAND(ID_SCANTYPE_SCANFILES, &CWinfingerprintDlg::OnScantypeScanfiles)
	ON_COMMAND(ID_SCANTYPE_SCANHOST, &CWinfingerprintDlg::OnScantypeScanhost)
	ON_COMMAND(ID_SCANTYPE_SCANLIST, &CWinfingerprintDlg::OnScantypeScanlist)
	ON_COMMAND(ID_SCANRANGE_BEGINNINGANDENDINGIPADDRESS, &CWinfingerprintDlg::OnScanrangeBeginningandendingipaddress)
	ON_COMMAND(ID_SCANRANGE_IPADDRESSANDNETMASK, &CWinfingerprintDlg::OnScanrangeIpaddressandnetmask)
	ON_COMMAND(ID_SCANTYPE_SCANNEIGHBORHOOD, &CWinfingerprintDlg::OnScantypeScanneighborhood)
	ON_COMMAND(ID_SMBSCANOPTIONS_OSVERSION, &CWinfingerprintDlg::OnSmbscanoptionsOsversion)
	ON_COMMAND(ID_FILE_EXIT, &CWinfingerprintDlg::OnFileExit)
	ON_COMMAND(ID_SMBSCANOPTIONS_RPCBINDINGS, &CWinfingerprintDlg::OnSmbscanoptionsRpcbindings)
	ON_COMMAND(ID_SMBSCANOPTIONS_SESSIONS, &CWinfingerprintDlg::OnSmbscanoptionsSessions)
	ON_COMMAND(ID_SMBSCANOPTIONS_SERVICES, &CWinfingerprintDlg::OnSmbscanoptionsServices)
	ON_COMMAND(ID_SMBSCANOPTIONS_REGISTRY, &CWinfingerprintDlg::OnSmbscanoptionsRegistry)
	ON_COMMAND(ID_NETBIOSSHARES_ENUMERATESHARES, &CWinfingerprintDlg::OnNetbiossharesEnumerateshares)
	ON_COMMAND(ID_FILE_CLEAR, &CWinfingerprintDlg::OnFileClear)
	ON_COMMAND(ID_TCP_PING, &CWinfingerprintDlg::OnTcpPing)
	ON_COMMAND(ID_TCP_TRACEROUTE, &CWinfingerprintDlg::OnTcpTraceroute)
	ON_COMMAND(ID_USERS_ENUMERATEUSERS, &CWinfingerprintDlg::OnUsersEnumerateusers)
	ON_COMMAND(ID_SMBSCANOPTIONS_GROUPS, &CWinfingerprintDlg::OnSmbscanoptionsGroups)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CWinfingerprintDlg message handlers

BOOL CWinfingerprintDlg::OnInitDialog()
{
	CString strAboutMenu, tmp;
	DWORD dwSize = 0;
	HMODULE hwpcap, hpacket;
	HINSTANCE hicmp = NULL;
	PIP_ADAPTER_INFO pAdapter = NULL;
	pInterfaces = (CComboBox *)GetDlgItem(IDC_INTERFACES);
	CDialog::OnInitDialog();
	pRichEditCtrl = (CRichEditCtrl *)GetDlgItem(IDC_OUTPUT);
	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if(pSysMenu != NULL)
	{
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if(!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	// Intitialize pAdaptersInfo pointer to NULL
	pAdaptersInfo = NULL;
	// Call GetAdaptersInfo with NULL to determine size of pAdaptersInfo
	GetAdaptersInfo(NULL, &dwSize);
	// Allocate required size
	pAdaptersInfo = (PIP_ADAPTER_INFO)GlobalAlloc(GPTR, dwSize);
	
	if((GetAdaptersInfo(pAdaptersInfo, &dwSize)) != ERROR_SUCCESS)
	{
		MessageBox("GetAdaptersInfo Error", "Winfingerprint Error",
			MB_ICONERROR | MB_OK);
        return false;
	}
	
	pAdapter = pAdaptersInfo;
	OurIPAddress.Empty();
	while(pAdapter)
	{
		pInterfaces->AddString(pAdapter->Description);
		if(OurIPAddress.IsEmpty())
			OurIPAddress.Format("%s", pAdapter->IpAddressList.IpAddress.String); 
		pAdapter = pAdapter->Next;
	}

	CMenu* mmenu = GetMenu();
	scan_type_menu = mmenu->GetSubMenu(1);
	smb_options_menu = mmenu->GetSubMenu(2);
	ip_options_menu = mmenu->GetSubMenu(3);

	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_OSVERSION, MF_CHECKED | MF_BYCOMMAND);

	switch(RegistrySetting_get("SMBType"))
	{
		case SMB_ADSI:
			OnSmbscanoptionsAdsi();		
			break;
		case SMB_NET:
			OnSmbscanoptionsNet();
			break;
		case SMB_WMI:
			OnSmbscanoptionsWmi();
			break;
	}

	if(opt_patchlevel = (BOOL) RegistrySetting_get("Registry"))
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_REGISTRY, MF_CHECKED | MF_BYCOMMAND);
	
	if(opt_sessions = (BOOL) RegistrySetting_get("Sessions"))
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_SESSIONS, MF_CHECKED | MF_BYCOMMAND);
	
	if(opt_rpcbindings = (BOOL) RegistrySetting_get("RPCBindings"))
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_RPCBINDINGS, MF_CHECKED | MF_BYCOMMAND);
	
	if(opt_services = (BOOL) RegistrySetting_get("Services"))
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_SERVICES, MF_CHECKED | MF_BYCOMMAND);
	
	if(opt_osversion = (BOOL) RegistrySetting_get("OSVersion"))
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_OSVERSION, MF_CHECKED | MF_BYCOMMAND);
	
	if(opt_shares = (BOOL) RegistrySetting_get("Shares"))
		smb_options_menu->CheckMenuItem(ID_NETBIOSSHARES_ENUMERATESHARES, MF_CHECKED | MF_BYCOMMAND);

	if(opt_pinghost = (BOOL) RegistrySetting_get("Ping"))
		ip_options_menu->CheckMenuItem(ID_TCP_PING, MF_CHECKED | MF_BYCOMMAND);

	if(opt_trace = (BOOL) RegistrySetting_get("Trace"))
		ip_options_menu->CheckMenuItem(ID_TCP_TRACEROUTE, MF_CHECKED | MF_BYCOMMAND);
	
	if(opt_groups = RegistrySetting_get("Groups"))
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_GROUPS, MF_UNCHECKED | MF_BYCOMMAND);

    if(opt_users = RegistrySetting_get("Users"))
		smb_options_menu->CheckMenuItem(ID_USERS_ENUMERATEUSERS, MF_UNCHECKED | MF_BYCOMMAND);
	
	pInterfaces->SetCurSel(0);

	// Only show interface selection if we have wpcap.dll and packet.dll
	// GetAdaptersInfo() is still needed to obtain OurIPAddress.
	hwpcap = LoadLibrary("wpcap");
	hpacket = LoadLibrary("packet");

	if((hwpcap == NULL) || (hpacket == NULL))
		GetDlgItem(IDC_INTERFACES)->ShowWindow(SW_HIDE);
	
	if(hwpcap != NULL)
		FreeLibrary(hwpcap);
	if(hpacket != NULL)
		FreeLibrary(hpacket);

	if((hicmp = LoadLibrary("icmp.dll")) != NULL)
		FreeLibrary(hicmp);

	if(!OurIPAddress.IsEmpty())
	{
		GetDlgItem(IDC_STARTIP)->SetWindowText(OurIPAddress);
		GetDlgItem(IDC_ENDIP)->SetWindowText(OurIPAddress);
	}
	else
	{
		GetDlgItem(IDC_STARTIP)->SetWindowText(_T("127.0.0.1"));
		GetDlgItem(IDC_ENDIP)->SetWindowText(_T("127.0.0.1"));
	}

	GetDlgItem(IDC_HOST)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_BROWSE)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_IPLIST)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_IP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_DOMAIN)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_NETMASKTEXT)->ShowWindow(SW_HIDE);
	pRichEditCtrl->SetEventMask(pRichEditCtrl->GetEventMask() | ENM_LINK);
	pRichEditCtrl->SendMessage(EM_AUTOURLDETECT,1,0);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CWinfingerprintDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CWinfingerprintDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CWinfingerprintDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CWinfingerprintDlg::OnOK() 
{
	CString tmp;
	CWfpEngine *p;
	CWfpADSI adsi;
	CWfpNET net;
	CWfpWMI wmi;

	// Don't Allow editing during scan.
	pRichEditCtrl->SetReadOnly(TRUE);

	m_startip.Empty();
	m_endip.Empty();
	m_stop = 0;   // Reset stop variable
	
	UpdateData(); // Get configuration
	
	switch(smb_access)
	{
	case SMB_ADSI:
		p = &adsi;
		break;
	case SMB_NET:
		p = &net;
		break;
	case SMB_WMI:
		p = &wmi;
	default:
		p = &net;
	}
	
	p->options.optiontrace = opt_trace;
	p->options.optionping = opt_pinghost;
	p->options.optionosversion = opt_osversion;
	p->options.optiongroups = opt_groups;
	p->options.optionservices = opt_services;
	p->options.optionbindings = opt_rpcbindings;
	p->options.optionmacaddress = opt_macaddress;
	p->options.optionusers = opt_users;
	p->options.optionshares = opt_shares;
	p->options.optionsessions = opt_sessions;
	p->options.optionregistry = opt_patchlevel;

	switch(scan_type)
	{
		case SCAN_RANGE:
			GetDlgItem(IDC_STARTIP)->GetWindowText(p->StartIPAddress);
			GetDlgItem(IDC_ENDIP)->GetWindowText(p->EndIPAddress);
			break;
		case SCAN_LIST:
			// Use startip variable as file name
			GetDlgItem(IDC_HOST)->GetWindowText(p->StartIPAddress);
			break;
		case SCAN_NEIGHBORHOOD:
			break;
		case SCAN_HOST:
			p->options.scan_type = SCAN_HOST;
			GetDlgItem(IDC_HOST)->GetWindowText(p->StartIPAddress);
			break;
	}

	//GetDlgItem(IDCANCEL)->ShowWindow(SW_HIDE);
	p->StartThread();

	if(p->Errors.GetSize() > 0) 
	{
		for(int i = 0; i <= p->Errors.GetUpperBound(); i++)
		{
			InsertString(p->Errors[i]);
		}	
	}
	else
	{
		InsertString(p->Output(&p->ScanResults));	
		InsertString(p->Output(&p->Disks));
		InsertString(p->Output(&p->EventLog));
		InsertString(p->Output(&p->Groups));
		InsertString(p->Output(&p->MACAddress));
		InsertString(p->Output(&p->NetBIOSShares));
		InsertString(p->Output(&p->OperatingSystem));
		InsertString(p->Output(&p->PatchLevel));
		InsertString(p->Output(&p->RPCBindings));
		InsertString(p->Output(&p->Services));
		InsertString(p->Output(&p->Sessions));
		InsertString(p->Output(&p->SNMP));
		InsertString(p->Output(&p->Time));
		InsertString(p->Output(&p->Users));
	}

	InsertString("Done\n");
	p->Uninit();
	return;
}

void CAboutDlg::OnWww() 
{
	ShellExecute(NULL,_T("open"),_T("http://www.winfingerprint.com"),
		NULL,NULL,SW_SHOWNORMAL); 
    return;
}

void CWinfingerprintDlg::OnHlp() 
{
	TCHAR path[_MAX_PATH];
	TCHAR string[_MAX_PATH];
    // Retrieve the current directory for the current process
    // in case someone doesn't accept default directory
    // during installation.
	GetCurrentDirectory(_MAX_PATH, path);
	_snprintf_s(string, _MAX_PATH -1, _T("%s\\winfingerprint.chm") ,path);
	ShellExecute(NULL, _T("open"), string, NULL, NULL, SW_SHOWNORMAL); 
    return;
}

void CWinfingerprintDlg::WSAErrorHandler(char *function)
{
	CString tmp;
	LPVOID lpMsgBuf;
	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		WSAGetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR) &lpMsgBuf,0,NULL);
	tmp.Format(_T("%s Error: %s\n"),function,lpMsgBuf);
	m_output.operator +=(tmp);
	LocalFree(lpMsgBuf);
	return;
}

void CWinfingerprintDlg::OnBrowse() 
{
	UpdateData(TRUE);
	CFileDialog dlg(TRUE, NULL, NULL, OFN_EXPLORER, "Text Files (*.txt)|*.txt||" );
	if(dlg.DoModal() == IDOK)
	{
		m_outputfile = dlg.GetPathName();
		UpdateData(FALSE);
	}			
}

BOOL CAboutDlg::OnInitDialog()
{
	CDialog::OnInitDialog();	// CG:  This was added by System Info Component.

	// CG: Following block was added by System Info Component.
	{
		CString strFreeDiskSpace;
		CString strFreeMemory;
		CString strFmt;
		CString strWinPCapVersion;
		CString strMySQLEmbeddedVersion;

		// Fill available memory
		MEMORYSTATUS MemStat;
		MemStat.dwLength = sizeof(MEMORYSTATUS);
		GlobalMemoryStatus(&MemStat);
		strFmt.LoadString(CG_IDS_PHYSICAL_MEM);
		strFreeMemory.Format(strFmt, MemStat.dwTotalPhys / 1024L);

		//TODO: Add a static control to your About Box to receive the memory
		//      information.  Initialize the control with code like this:
		SetDlgItemText(IDC_PHYSICAL_MEM, strFreeMemory);

		// Fill disk free information
		struct _diskfree_t diskfree;
		int nDrive = _getdrive(); // use current default drive
		if (_getdiskfree(nDrive, &diskfree) == 0)
		{
			strFmt.LoadString(CG_IDS_DISK_SPACE);
			strFreeDiskSpace.Format(strFmt,
				(DWORD)diskfree.avail_clusters *
				(DWORD)diskfree.sectors_per_cluster *
				(DWORD)diskfree.bytes_per_sector / (DWORD)1024L,
				nDrive-1 + _T('A'));
		}
		else
			strFreeDiskSpace.LoadString(CG_IDS_DISK_SPACE_UNAVAIL);

		//TODO: Add a static control to your About Box to receive the memory
		//      information.  Initialize the control with code like this:
		 SetDlgItemText(IDC_DISK_SPACE, strFreeDiskSpace);

		if((hwpcap = LoadLibrary("wpcap")) != NULL)
		{
			ppcap_lib_version = (MYPCAP_PCAP_LIB_VERSION)GetProcAddress(hwpcap, "pcap_lib_version");
			strWinPCapVersion.Format("%s", ppcap_lib_version());
			SetDlgItemText(IDC_WINPCAP_VER, strWinPCapVersion);
		}

		MYSQL mysql;
		if (mysql_library_init(0, NULL, NULL)) {
			fprintf(stderr, "[-] Could not initialize MySQL library\n");
			return TRUE;
		}
		mysql_init(&mysql);

		if(!mysql_real_connect(&mysql, NULL,"root", "winfingerprint", "winfingerprint", 0, NULL, 0)) {
			fprintf(stderr, "Failed to connect to database: Error: %s\n",
				mysql_error(&mysql));

		}
		strMySQLEmbeddedVersion.Format("%s",mysql_get_server_info(&mysql));
		SetDlgItemText(IDC_MYSQL_VER, strMySQLEmbeddedVersion);

		mysql_close(&mysql);
		mysql_library_end();
	}
	return TRUE;	// CG:  This was added by System Info Component.
}


void CWinfingerprintDlg::OnStop()
{
	if(!m_stop)
		m_stop = 1;
	else
		m_stop = 0;

	//GetDlgItem(IDCANCEL)->ShowWindow(SW_SHOW);
}


void CWinfingerprintDlg::OnRichEditExLink(NMHDR* in_pNotifyHeader, LRESULT* out_pResult)
{
	ENLINK* l_pENLink = ( ENLINK* )in_pNotifyHeader;

	*out_pResult = 0;

	switch(l_pENLink->msg)
	{
		default:
		{
		}
		break ;

		case WM_SETCURSOR:
		{
			// Because IDC_HAND is not available on all operating
			// systems, we will load the arrow cursor if IDC_HAND is not
			// present.
			HCURSOR hCursor = LoadCursor(NULL, MAKEINTRESOURCE
                                  (IDC_HAND));
			if (NULL == hCursor)
			{
				hCursor = LoadCursor(NULL, MAKEINTRESOURCE(IDC_ARROW));
			}
			SetCursor(hCursor);
			//return TRUE;
			//::SetCursor(AfxGetApp()->LoadStandardCursor(MAKEINTRESOURCE(IDC_HAND)));
			*out_pResult = 1 ;
		}
		break ;
		case WM_LBUTTONDOWN:
		{
			CString l_URL ;
			CHARRANGE l_CharRange ;

			pRichEditCtrl->GetSel( l_CharRange ) ;
			pRichEditCtrl->SetSel( l_pENLink->chrg ) ;
			l_URL = pRichEditCtrl->GetSelText() ;
			pRichEditCtrl->SetSel( l_CharRange ) ;
			CWaitCursor l_WaitCursor ;

			ShellExecute( this->GetSafeHwnd(), _T( "open" ), l_URL, NULL, NULL, SW_SHOWNORMAL ) ;

			*out_pResult = 1 ;
		}
		break ;

		case WM_LBUTTONUP:
		{
			*out_pResult = 1 ;
		}
		break ;
	}
}


DWORD CALLBACK CWinfingerprintDlg::MyEditStreamCallBackIn(DWORD  dwCookie, LPBYTE  pbBuff, LONG cb, LONG * pcb)
{
	CString *pstr = (CString *)dwCookie;
	if(pstr->GetLength() < cb )
	{
		*pcb = pstr->GetLength();
		memcpy(pbBuff, (LPCSTR)*pstr, *pcb );
		pstr->Empty();
	}
	else
	{
		*pcb = cb;
		memcpy(pbBuff, (LPCSTR)*pstr, *pcb );
		*pstr = pstr->Right( pstr->GetLength() - cb );
	}
	return 0;
}

bool CWinfingerprintDlg::InsertString(CString str)
{
	if(str.GetLength()==0)
		return FALSE;
    
	EDITSTREAM es = {(DWORD)&str, 0, MyEditStreamCallBackIn};
	pRichEditCtrl->SetSel(pRichEditCtrl->GetWindowTextLength(), pRichEditCtrl->GetWindowTextLength());
	pRichEditCtrl->StreamIn(SF_TEXT | SFF_SELECTION, es);
    return TRUE;
}

void CWinfingerprintDlg::OnSmbscanoptionsAdsi()
{
	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_ADSI, MF_CHECKED | MF_BYCOMMAND);
	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_NET, MF_UNCHECKED | MF_BYCOMMAND);
	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_WMI, MF_UNCHECKED | MF_BYCOMMAND);
	smb_access = SMB_ADSI;
	RegistrySetting_set("SMBType", SMB_ADSI);
}

void CWinfingerprintDlg::OnSmbscanoptionsNet()
{
	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_ADSI, MF_UNCHECKED | MF_BYCOMMAND);
	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_NET, MF_CHECKED | MF_BYCOMMAND);
	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_WMI, MF_UNCHECKED | MF_BYCOMMAND);
	smb_access = SMB_NET;
	RegistrySetting_set("SMBType", SMB_NET);
}

void CWinfingerprintDlg::OnSmbscanoptionsWmi()
{
	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_ADSI, MF_UNCHECKED | MF_BYCOMMAND);
	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_NET, MF_UNCHECKED | MF_BYCOMMAND);
	smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_WMI, MF_CHECKED | MF_BYCOMMAND);
	smb_access = SMB_WMI;
	RegistrySetting_set("SMBType", SMB_WMI);
}

DWORD CWinfingerprintDlg::RegistrySetting_get(LPCSTR setting)
{
	CString tmp;
	LONG result;
	HKEY hKey, phkResult;
	DWORD lpType = REG_DWORD;
	DWORD value = 0;
	DWORD lpcbName = 1024;
	DWORD index =0;
	DWORD lpcbData = sizeof(DWORD);
	SECURITY_ATTRIBUTES sa;
	DWORD disposition;

	sa.lpSecurityDescriptor = NULL;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = true;
	
	// The RegConnectRegistry function establishes a connection to a predefined
	// registry handle on another computer. 

	if((result = RegConnectRegistry(NULL,HKEY_LOCAL_MACHINE,&hKey)) == ERROR_SUCCESS)
	{
		//if((result = RegOpenKeyEx(hKey,_T("Software\\Winfingerprint"),0,KEY_READ,&phkResult)) == ERROR_SUCCESS)
		if((RegCreateKeyEx(hKey,_T("Software\\Winfingerprint"),0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_ALL_ACCESS, &sa, &phkResult, &disposition)) == ERROR_SUCCESS)
		{
			if((result = RegQueryValueEx(phkResult, setting, NULL, &lpType, (LPBYTE)&value, &lpcbData)) != ERROR_SUCCESS)
			{
				RegSetValueEx(phkResult, setting, NULL, REG_DWORD, (CONST BYTE*)0, sizeof(DWORD));
			}
			RegCloseKey(phkResult);
		} 
		RegCloseKey(hKey);	// Successfully connected with RegConnectRegistry, but some other failure.
	}
	return value;
}

bool CWinfingerprintDlg::RegistrySetting_set(LPCSTR setting, DWORD data)
{
	
	LONG result;
	HKEY hKey, phkResult;
	
	if((result = RegConnectRegistry(NULL,HKEY_LOCAL_MACHINE,&hKey)) == ERROR_SUCCESS)
	{
		if((result = RegOpenKeyEx(hKey,_T("Software\\Winfingerprint"),0, KEY_WRITE,&phkResult)) == ERROR_SUCCESS)
		{
			RegSetValueEx(phkResult, setting, NULL, REG_DWORD, (CONST BYTE*)&data, sizeof(data));
			RegCloseKey(phkResult);
		}
		RegCloseKey(hKey);	// Successfully connected with RegConnectRegistry, but some other failure.
	}
	return true;
}

void CWinfingerprintDlg::OnFileHelp()
{
	CHAR path[_MAX_PATH];
	TCHAR string[_MAX_PATH];
    // Retrieve the current directory for the current process
    // in case someone doesn't accept default directory
    // during installation.
	GetCurrentDirectory(_MAX_PATH, path);
	_snprintf_s(string, _MAX_PATH -1, _T("%s\\winfingerprint.chm") ,path);
	ShellExecute(NULL, _T("open"), string, NULL, NULL, SW_SHOWNORMAL); 
    return;
}

void CWinfingerprintDlg::OnFileAbout()
{
	CAboutDlg dlgAbout;
	dlgAbout.DoModal();
}

void CWinfingerprintDlg::OnFileSaveresults()
{
	HANDLE hFile;
	CString cstr, outputfile, tmp;
	DWORD dwBytesRead = 0, dwBytesWritten = 0;
  	
	CFileDialog dlg(FALSE, NULL, NULL, OFN_EXPLORER,
		            _T("Winfingerprint Output (*.rtf)|*.rtf||"));
	if(dlg.DoModal() == IDOK)
	{
		outputfile = dlg.GetPathName();
	}
	
	if(outputfile.IsEmpty())
		outputfile = "c:\\winfingerprint.rtf";
	else
	{
		int count = outputfile.ReverseFind('.');
		if(count == -1) //no dot found
			outputfile += ".rtf"; //append .rtf
		else //if there is a dot and the extension is not rtf remove it and put rtf there
		{
			CString temp = outputfile.Right(count);
			if(temp != ".rtf")
			{
				temp = outputfile.Left(count + 1);
				temp += "rtf";
				outputfile = temp;
			}
		}		
	}

	GetDlgItem(IDC_OUTPUT)->GetWindowText(cstr);
	dwBytesRead = GetDlgItem(IDC_OUTPUT)->GetWindowTextLength();

	hFile = CreateFile(outputfile,  // filename 
		GENERIC_WRITE,              // open for writing 
		0,                          // do not share 
		NULL,                       // no security 
		CREATE_ALWAYS,              // overwrite existing 
		FILE_ATTRIBUTE_NORMAL,     
		NULL);                      // no attr. template 

	if(hFile == INVALID_HANDLE_VALUE) 
	{ 
		LPVOID lpMsgBuf;
		FormatMessage( 
			FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM | 
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			(LPTSTR) &lpMsgBuf,0,NULL);
		tmp.Format(_T("CreateFile Error %d: %s\n"),GetLastError(),lpMsgBuf);
		m_output.operator +=(tmp);
		LocalFree(lpMsgBuf);
		return;
	}

	WriteFile(hFile, cstr, dwBytesRead, &dwBytesWritten, NULL);
	CloseHandle (hFile);
	return;
}

void CWinfingerprintDlg::OnScantypeScanfiles()
{
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANRANGE, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANLIST, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANHOST, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANNEIGHBORHOOD, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANFILES, MF_CHECKED | MF_BYCOMMAND);
    scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANPROCESSES, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type = SCAN_HOST;
}

void CWinfingerprintDlg::OnScantypeScanhost()
{
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANRANGE, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANLIST, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANHOST, MF_CHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANNEIGHBORHOOD, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANFILES, MF_UNCHECKED | MF_BYCOMMAND);
    scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANPROCESSES, MF_UNCHECKED | MF_BYCOMMAND);
	
	if(OurIPAddress)
		GetDlgItem(IDC_HOST)->SetWindowText(OurIPAddress);
	else
		GetDlgItem(IDC_HOST)->SetWindowText(_T("127.0.0.1"));
	
	GetDlgItem(IDC_HOST)->ShowWindow(SW_SHOW);
	GetDlgItem(IDS_IP)->ShowWindow(SW_SHOW);
	GetDlgItem(IDS_DOMAIN)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_STARTIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_ENDIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_STARTINGIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_ENDINGIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_BROWSE)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_IPLIST)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_NETMASKTEXT)->ShowWindow(SW_HIDE);
	scan_type = SCAN_HOST;
}

void CWinfingerprintDlg::OnScantypeScanlist()
{
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANRANGE, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANLIST, MF_CHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANHOST, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANNEIGHBORHOOD, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANPROCESSES, MF_UNCHECKED | MF_BYCOMMAND);
	scan_type_menu->CheckMenuItem(ID_SCANTYPE_SCANFILES, MF_UNCHECKED | MF_BYCOMMAND);
	GetDlgItem(IDC_HOST)->SetWindowText(_T(""));
	GetDlgItem(IDC_HOST)->ShowWindow(SW_SHOW);
	GetDlgItem(IDC_BROWSE)->ShowWindow(SW_SHOW);
	GetDlgItem(IDC_STARTIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_ENDIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_STARTINGIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_ENDINGIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_DOMAIN)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_IPLIST)->ShowWindow(SW_SHOW);
	GetDlgItem(IDS_IP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_NETMASKTEXT)->ShowWindow(SW_HIDE);
	scan_type = SCAN_LIST;
}

void CWinfingerprintDlg::OnScanrangeBeginningandendingipaddress()
{
	
	if(OurIPAddress)
	{
		GetDlgItem(IDC_STARTIP)->SetWindowText(OurIPAddress);
		GetDlgItem(IDC_ENDIP)->SetWindowText(OurIPAddress);
	}
	else
	{
		GetDlgItem(IDC_STARTIP)->SetWindowText(_T("127.0.0.1"));
		GetDlgItem(IDC_ENDIP)->SetWindowText(_T("127.0.0.1"));
	}
	
	GetDlgItem(IDC_STARTIP)->ShowWindow(SW_SHOW);
	GetDlgItem(IDC_ENDIP)->ShowWindow(SW_SHOW);
	GetDlgItem(IDS_STARTINGIP)->ShowWindow(SW_SHOW);
	GetDlgItem(IDC_HOST)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_BROWSE)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_IPLIST)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_IP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_DOMAIN)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_ENDINGIP)->ShowWindow(SW_SHOW);
	GetDlgItem(IDC_NETMASKTEXT)->ShowWindow(SW_HIDE);
	scan_type = SCANRANGE;
	opt_netmask = false;
}

void CWinfingerprintDlg::OnScanrangeIpaddressandnetmask()
{
	if(OurIPAddress)
	{
		GetDlgItem(IDC_STARTIP)->SetWindowText(OurIPAddress);
		GetDlgItem(IDC_ENDIP)->SetWindowText("255.255.255.0");
	}
	else
	{
		GetDlgItem(IDC_STARTIP)->SetWindowText(_T("127.0.0.1"));
		GetDlgItem(IDC_ENDIP)->SetWindowText(_T("127.0.0.1"));
	}
	
	GetDlgItem(IDC_STARTIP)->ShowWindow(SW_SHOW);
	GetDlgItem(IDC_ENDIP)->ShowWindow(SW_SHOW);
	GetDlgItem(IDS_STARTINGIP)->ShowWindow(SW_SHOW);
	GetDlgItem(IDC_HOST)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_BROWSE)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_IPLIST)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_IP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_DOMAIN)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_ENDINGIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_NETMASKTEXT)->ShowWindow(SW_SHOW);
	scan_type = SCANRANGE;
	opt_netmask = true;
}

void CWinfingerprintDlg::OnScantypeScanneighborhood()
{
	GetDlgItem(IDC_HOST)->SetWindowText(_T(""));
	GetDlgItem(IDC_HOST)->ShowWindow(SW_SHOW);
	GetDlgItem(IDS_DOMAIN)->ShowWindow(SW_SHOW);
	GetDlgItem(IDS_IP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_STARTIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_ENDIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_STARTINGIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_ENDINGIP)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_BROWSE)->ShowWindow(SW_HIDE);
	GetDlgItem(IDS_IPLIST)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_NETMASKTEXT)->ShowWindow(SW_HIDE);
	scan_type = SCANNEIGHBORHOOD;
}

void CWinfingerprintDlg::OnSmbscanoptionsOsversion()
{
	if(!opt_osversion) {
		opt_osversion = true;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_OSVERSION, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_osversion = false;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_OSVERSION, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("OSVersion", opt_osversion);
}
	

void CWinfingerprintDlg::OnFileExit()
{
	exit(1);
}


void CWinfingerprintDlg::OnSmbscanoptionsRpcbindings()
{
	if(!opt_rpcbindings) {
		opt_rpcbindings = true;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_RPCBINDINGS, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_rpcbindings = false;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_RPCBINDINGS, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("RPCBindings", opt_rpcbindings);
}

void CWinfingerprintDlg::OnSmbscanoptionsSessions()
{
	if(!opt_sessions) {
		opt_sessions = true;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_SESSIONS, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_sessions = false;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_SESSIONS, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("Sessions", opt_sessions);
}

void CWinfingerprintDlg::OnSmbscanoptionsServices()
{
	if(!opt_services) {
		opt_services = true;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_SERVICES, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_services = false;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_SERVICES, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("Services", opt_services);
}

void CWinfingerprintDlg::OnSmbscanoptionsRegistry()
{
	if(!opt_patchlevel) {
		opt_patchlevel = true;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_REGISTRY, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_patchlevel = false;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_REGISTRY, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("Registry", opt_patchlevel);
}

void CWinfingerprintDlg::OnNetbiossharesEnumerateshares()
{
	if(!opt_shares) {
		opt_shares = true;
		smb_options_menu->CheckMenuItem(ID_NETBIOSSHARES_ENUMERATESHARES, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_shares = false;
		smb_options_menu->CheckMenuItem(ID_NETBIOSSHARES_ENUMERATESHARES, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("Shares", opt_shares);
}

void CWinfingerprintDlg::OnFileClear()
{
	GetDlgItem(IDC_OUTPUT)->SetWindowText(_T(""));
	return;
}

void CWinfingerprintDlg::OnTcpPing()
{
	if(!opt_pinghost) {
		opt_pinghost = true;
		ip_options_menu->CheckMenuItem(ID_TCP_PING, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_pinghost = false;
		ip_options_menu->CheckMenuItem(ID_TCP_PING, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("Ping", opt_pinghost);
}

void CWinfingerprintDlg::OnTcpTraceroute()
{
	if(!opt_trace) {
		opt_trace = false; // FIXME!! should be true
		ip_options_menu->CheckMenuItem(ID_TCP_TRACEROUTE, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_trace = false;
		ip_options_menu->CheckMenuItem(ID_TCP_TRACEROUTE, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("Trace", opt_trace);
}

void CWinfingerprintDlg::OnUsersEnumerateusers()
{
	if(!opt_users) {
		opt_users = true;
		smb_options_menu->CheckMenuItem(ID_USERS_ENUMERATEUSERS, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_shares = false;
		smb_options_menu->CheckMenuItem(ID_USERS_ENUMERATEUSERS, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("Users", opt_users);
}

void CWinfingerprintDlg::OnSmbscanoptionsGroups()
{
	if(!opt_groups) {
		opt_groups = true;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_GROUPS, MF_CHECKED | MF_BYCOMMAND);
	} else {
		opt_groups = false;
		smb_options_menu->CheckMenuItem(ID_SMBSCANOPTIONS_GROUPS, MF_UNCHECKED | MF_BYCOMMAND);
	}
	RegistrySetting_set("Users", opt_groups);
}
