#pragma once
#include "wfpengine.h"
#include <Lm.h>
#include <Lmserver.h>

class CWfpNET :
	public CWfpEngine
{
public:
	CWfpNET(void);
	~CWfpNET(void);
	bool Disks_get(void);
	bool EventLog_get(void);
	bool Groups_get(void);
	bool GroupMembers_get(LPWSTR Group);
	bool IPC_Session_Connect(void);
	bool IPC_Session_Disconnect(void);
	bool LocalGroups_get(void);
	bool OperatingSystem_get(void);
	bool PasswordPolicy_get(void);
	bool NetBIOSShares_get(void);
	virtual bool Services_get(void);
	bool Sessions_get(void);
	bool Time_get(void);
	bool Transports_get(void);
	bool Users_get(void);
private:
	bool NET_Machines_Users_Groups(DWORD level);
};
