#pragma once
#include "wfpengine.h"
#include <iads.h>			// ADSI Property Methods
#include <adshlp.h>			// ADsGetObject Support

#pragma comment (lib,"activeds") // Active Directory Support
#pragma comment (lib,"adsiid")   // Active Directory Support

class CWfpADSI :
	public CWfpEngine
{
public:
	CWfpADSI(void);
	~CWfpADSI(void);
	virtual bool Groups_get(void);
	bool OperatingSystem_get(void);
	bool NetBIOSShares_get(void);
	virtual bool Services_get(void);
	bool Sessions_get(void);
	bool Users_get(void);
private:
	bool Services_Users_Groups(int type);
};
