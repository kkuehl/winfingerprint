/* 
   $Id: winfingerprint.h,v 1.7 2005/01/04 02:09:29 vacuum Exp $
   winfingerprint.h : main header file for the WINFINGERPRINT application
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

#if !defined(AFX_WINFINGERPRINT_H__8BC42682_965B_42FA_B616_6A99F62948D8__INCLUDED_)
#define AFX_WINFINGERPRINT_H__8BC42682_965B_42FA_B616_6A99F62948D8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CWinfingerprintApp:
// See winfingerprint.cpp for the implementation of this class
//

class CWinfingerprintApp : public CWinApp
{
public:
	CWinfingerprintApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CWinfingerprintApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CWinfingerprintApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_WINFINGERPRINT_H__8BC42682_965B_42FA_B616_6A99F62948D8__INCLUDED_)
