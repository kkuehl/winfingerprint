#pragma once
#include "wfpengine.h"
//#include <comdef.h>


class CWfpWMI :
	public CWfpEngine
{
public:
	CWfpWMI(void);
	~CWfpWMI(void);
	bool OperatingSystem_get(void);
	bool PatchLevel_get(void);
	bool NetBIOSShares_get(void);
	virtual bool Services_get(void);
	bool Sessions_get(void);
	bool Transports_get(void);
	bool Users_get(void);
	virtual bool Groups_get(void);
};
