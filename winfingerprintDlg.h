/* 
   $Id: winfingerprintDlg.h,v 1.87 2008/12/16 19:25:11 vacuum Exp $
   winfingerprintDlg.h : header file
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

#if !defined(AFX_WINFINGERPRINTDLG_H__1EB9813A_4889_42A1_A42B_2C8A16A921E3__INCLUDED_)
#define AFX_WINFINGERPRINTDLG_H__1EB9813A_4889_42A1_A42B_2C8A16A921E3__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <pcap.h>
/////////////////////////////////////////////////////////////////////////////
// CWinfingerprintDlg dialog

class CWinfingerprintDlg : public CDialog
{
// Construction
public:
	CWinfingerprintDlg(CWnd* pParent = NULL);	// standard constructor
	CButton *pButton;
	CComboBox *pInterfaces;
	CMenu* scan_type_menu;
	CMenu* smb_options_menu;
	CMenu* ip_options_menu;
	CRichEditCtrl *pRichEditCtrl;
	CString	m_outputfile;
	CString m_startip;
	CString m_endip;
	CString OurIPAddress;
	PIP_ADAPTER_INFO pAdaptersInfo;
// Dialog Data
	//{{AFX_DATA(CWinfingerprintDlg)
	enum { IDD = IDD_WINFINGERPRINT_DIALOG };
	int     scan_type;
	BOOL	opt_disks;		  
	BOOL    opt_eventlog;     
	BOOL 	opt_groups;       
	BOOL    opt_macaddress;
	BOOL    opt_netmask;
	BOOL    opt_nullsession;  
	BOOL    opt_osversion;	  
	BOOL    opt_patchlevel;   
	BOOL    opt_pinghost;
	BOOL    opt_rpcbindings;
	BOOL    opt_services;
	BOOL    opt_sessions;     
	BOOL    opt_shares;       
	BOOL    opt_showerror;
	BOOL    opt_snmp;
	BOOL	opt_tcpportscan;
	BOOL    opt_time; 
	BOOL	opt_trace;
	BOOL    opt_udpportscan;  
	BOOL    opt_users;
	CString	m_output;       // CString for Rich Edit Control Output
	int		tcpendport;     
	int		tcpstartport;   
	int		udpstartport;   
	int		udpendport;     
	int     timeout;        // Timeout in seconds for ICMP/TCP/UDP/SO_SNDTIMEO/SO_RCVTIMEO
	int     max_connections;
	int     retries;
	int     m_stop;
		afx_msg void OnStop();
	CString m_communitystring;
	int smb_access;
	static DWORD CALLBACK MyEditStreamCallBackIn(DWORD  dwCookie, LPBYTE  pbBuff, LONG cb, LONG * pcb);
	bool InsertString(CString str);
	DWORD RegistrySetting_get(LPCSTR setting);
	bool RegistrySetting_set(LPCSTR setting, DWORD data);
	afx_msg void OnSmbscanoptionsAdsi();
	afx_msg void OnSmbscanoptionsNet();
	afx_msg void OnSmbscanoptionsWmi();
	afx_msg void OnFileHelp();
	afx_msg void OnFileAbout();
	afx_msg void OnFileSaveresults();
	afx_msg void OnScantypeScanfiles();
	afx_msg void OnScantypeScanhost();
	afx_msg void OnScantypeScanlist();
	afx_msg void OnScanrangeBeginningandendingipaddress();
	afx_msg void OnScanrangeIpaddressandnetmask();
	afx_msg void OnScantypeScanneighborhood();
	afx_msg void OnSmbscanoptionsOsversion();
	afx_msg void OnFileExit();
	afx_msg void OnSmbscanoptionsRpcbindings();
	afx_msg void OnSmbscanoptionsSessions();
	afx_msg void OnSmbscanoptionsServices();
	afx_msg void OnSmbscanoptionsRegistry();
	afx_msg void OnNetbiossharesEnumerateshares();
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CWinfingerprintDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;
	HCURSOR m_crLink ;
	void WSAErrorHandler(char *function);
	// Generated message map functions
	//{{AFX_MSG(CWinfingerprintDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	virtual void OnOK();
	afx_msg void OnHlp();
	afx_msg void OnBrowse();
	afx_msg void OnRichEditExLink(NMHDR* in_pNotifyHeader, LRESULT* out_pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnFileClear();
public:
	afx_msg void OnTcpPing();
public:
	afx_msg void OnTcpTraceroute();
public:
	afx_msg void OnUsersEnumerateusers();
public:
	afx_msg void OnSmbscanoptionsGroups();
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_WINFINGERPRINTDLG_H__1EB9813A_4889_42A1_A42B_2C8A16A921E3__INCLUDED_)