/*	EID Authentication
    Copyright (C) 2009 Vincent Le Toux

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <windows.h>
#include <Msiquery.h>
#include <lm.h>
#include <stdio.h>

#pragma comment(lib,"Msi.lib")
#pragma comment(lib,"Netapi32")

#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/AutoLogon.h"

BOOL LsaEIDRemoveAllStoredCredential();
DWORD GetRidFromUsername(LPTSTR szUsername);

typedef VOID (*PFN_LOCAL_ACCOUNT)(__in PCWSTR szName, __in DWORD dwRid, __in_opt PVOID pContext);

// calls pfnAccount for each local user account
static BOOL ForEachLocalAccount(__in PFN_LOCAL_ACCOUNT pfnAccount, __in_opt PVOID pContext)
{
	NET_API_STATUS Status;
	DWORD dwResume = 0;
	do
	{
		PUSER_INFO_20 pUserInfo = NULL;
		DWORD dwEntriesRead = 0, dwTotalEntries = 0;
		Status = NetUserEnum(NULL, 20, FILTER_NORMAL_ACCOUNT, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResume);
		if (Status != NERR_Success && Status != ERROR_MORE_DATA)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			return FALSE;
		}
		for (DWORD dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			pfnAccount(pUserInfo[dwI].usri20_name, pUserInfo[dwI].usri20_user_id, pContext);
		}
		if (pUserInfo) NetApiBufferFree(pUserInfo);
	} while (Status == ERROR_MORE_DATA);
	return TRUE;
}

// rundll32 has no console : the output goes to the file named by EID_AUTOLOGON_OUT (UTF-8)
static HANDLE OpenOutput()
{
	WCHAR szPath[MAX_PATH];
	DWORD dwLen = GetEnvironmentVariableW(L"EID_AUTOLOGON_OUT", szPath, ARRAYSIZE(szPath));
	if (dwLen == 0 || dwLen >= ARRAYSIZE(szPath))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EID_AUTOLOGON_OUT missing or too long");
		return INVALID_HANDLE_VALUE;
	}
	return CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static VOID WriteOutputLine(__in HANDLE hOut, __in PCWSTR szFormat, ...)
{
	WCHAR szLine[512];
	CHAR szUtf8[1536];
	va_list ap;
	va_start(ap, szFormat);
	_vsnwprintf_s(szLine, ARRAYSIZE(szLine), _TRUNCATE, szFormat, ap);
	va_end(ap);
	wcscat_s(szLine, ARRAYSIZE(szLine), L"\r\n");
	int iLen = WideCharToMultiByte(CP_UTF8, 0, szLine, -1, szUtf8, (int) sizeof(szUtf8), NULL, NULL);
	if (iLen > 1)
	{
		DWORD dwWritten;
		WriteFile(hOut, szUtf8, iLen - 1, &dwWritten, NULL);
	}
}

// "saved", "none" or the error which prevented the check
static VOID WritePinState(__in HANDLE hOut, __in PCWSTR szName, __in DWORD dwRid)
{
	if (EIDIsAutoLogonPinStored(dwRid))
	{
		WriteOutputLine(hOut, L"%s\t0x%X\tsaved", szName, dwRid);
	}
	else if (GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		WriteOutputLine(hOut, L"%s\t0x%X\tnone", szName, dwRid);
	}
	else
	{
		WriteOutputLine(hOut, L"%s\t0x%X\terror 0x%08X", szName, dwRid, GetLastError());
	}
}

static VOID ListAccount(__in PCWSTR szName, __in DWORD dwRid, __in_opt PVOID pContext)
{
	WritePinState((HANDLE) pContext, szName, dwRid);
}

static VOID ClearAccount(__in PCWSTR szName, __in DWORD dwRid, __in_opt PVOID pContext)
{
	UNREFERENCED_PARAMETER(pContext);
	if (EIDForgetUserAutoLogonPin(dwRid))
	{
		EIDAuditEvent(EVENTLOG_INFORMATION_TYPE, EID_EVENT_PIN_ADMIN,
			L"An administrator cleared the tap sign-in PIN of %s (RID 0x%X).", szName, dwRid);
	}
}

extern "C"
{
	
	void NTAPI DllRegister()
	{
		EIDAuthenticationPackageDllRegister();
		EIDCredentialProviderDllRegister();
		EIDPasswordChangeNotificationDllRegister();
		EIDConfigurationWizardDllRegister();
		RegisterTheSecurityPackage();
		EIDRegisterEventSource();
	}

	void NTAPI DllUnRegister()
	{
		EIDAuthenticationPackageDllUnRegister();
		EIDCredentialProviderDllUnRegister();
		EIDPasswordChangeNotificationDllUnRegister();
		EIDConfigurationWizardDllUnRegister();
		UnRegisterTheSecurityPackage();
		// the PINs stored for the tap sign-in must not outlive the program
		ForEachLocalAccount(ClearAccount, NULL);
		EIDSetAutoLogonPin(NULL);
		EIDUnRegisterEventSource();
	}

	void NTAPI DllEnableLogging()
	{
		if (!EnableLogging())
		{
			MessageBoxWin32(GetLastError());
		}
		else
		{
			MessageBoxWin32(0);
		}
	}

	// rundll32 EIDAuthenticationPackage.dll,SetAutoLogonPin
	// the PIN is read from the EID_AUTOLOGON_PIN environment variable (not from the
	// command line, which is visible to every user). No UI : used by provisioning scripts.
	void NTAPI SetAutoLogonPin()
	{
		WCHAR szPin[65];
		DWORD dwLen = GetEnvironmentVariableW(L"EID_AUTOLOGON_PIN", szPin, ARRAYSIZE(szPin));
		if (dwLen == 0 || dwLen >= ARRAYSIZE(szPin))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EID_AUTOLOGON_PIN missing or too long");
		}
		else if (!EIDSetAutoLogonPin(szPin))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDSetAutoLogonPin 0x%08x",GetLastError());
		}
		else
		{
			EIDAuditEvent(EVENTLOG_INFORMATION_TYPE, EID_EVENT_PIN_ADMIN, L"An administrator set the station tap sign-in PIN.");
		}
		SecureZeroMemory(szPin, sizeof(szPin));
	}

	void NTAPI ClearAutoLogonPin()
	{
		if (!EIDSetAutoLogonPin(NULL))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDSetAutoLogonPin 0x%08x",GetLastError());
		}
		else
		{
			EIDAuditEvent(EVENTLOG_INFORMATION_TYPE, EID_EVENT_PIN_ADMIN, L"An administrator cleared the station tap sign-in PIN.");
		}
	}

	// rundll32 EIDAuthenticationPackage.dll,ListAutoLogonPins
	// writes "<account> TAB <rid> TAB saved|none|error" for the station and each local account
	// to the file named by EID_AUTOLOGON_OUT. Never writes a PIN.
	void NTAPI ListAutoLogonPins()
	{
		HANDLE hOut = OpenOutput();
		if (hOut == INVALID_HANDLE_VALUE)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OpenOutput 0x%08x",GetLastError());
			return;
		}
		WritePinState(hOut, L"(station)", 0);
		ForEachLocalAccount(ListAccount, hOut);
		CloseHandle(hOut);
	}

	// rundll32 EIDAuthenticationPackage.dll,ClearUserAutoLogonPin
	// clears the PIN learnt for the account named by EID_AUTOLOGON_USER ("*" : every local account).
	// The next sign-in of the user with the PIN saves it again (offboarding : unenroll the card too).
	void NTAPI ClearUserAutoLogonPin()
	{
		WCHAR szUser[UNLEN+1];
		DWORD dwLen = GetEnvironmentVariableW(L"EID_AUTOLOGON_USER", szUser, ARRAYSIZE(szUser));
		if (dwLen == 0 || dwLen >= ARRAYSIZE(szUser))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EID_AUTOLOGON_USER missing or too long");
			return;
		}
		if (wcscmp(szUser, L"*") == 0)
		{
			ForEachLocalAccount(ClearAccount, NULL);
			return;
		}
		DWORD dwRid = GetRidFromUsername(szUser);
		if (!dwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unknown account %s",szUser);
			return;
		}
		ClearAccount(szUser, dwRid, NULL);
	}

	void NTAPI DllDisableLogging()
	{
		if (!DisableLogging())
		{
			MessageBoxWin32(GetLastError());
		}
		else
		{
			MessageBoxWin32(0);
		}
	}

	int NTAPI Commit(MSIHANDLE hInstall)
	{
		UNREFERENCED_PARAMETER(hInstall);
		/*EIDAuthenticationPackageDllRegister();
		EIDCredentialProviderDllRegister();
		EIDPasswordChangeNotificationDllRegister();
		EIDConfigurationWizardDllRegister();*/
		DWORD dwError = 0;
		int ret = ERROR_INSTALL_FAILURE;
		__try
		{
			if (!RegisterTheSecurityPackage())
			{
				dwError = GetLastError();
				__leave;
			}
			ret = ERROR_SUCCESS;
		}
		__finally
		{
			if (dwError == ERROR_FAIL_NOACTION_REBOOT)
			{
				// a deferred action cannot order a reboot through MSI functions (setmode, set property, ...)
				// hopefully, Wix has a immediate action which checks an ATOM to set the reboot flag
				GlobalAddAtom(TEXT("WcaDeferredActionRequiresReboot"));
				ret = ERROR_SUCCESS;
			}
			else if (dwError != 0)
			{
				MessageBoxWin32(dwError);
			}
		}
		return ret;
	}

	int NTAPI Uninstall(MSIHANDLE hInstall)
	{
		UNREFERENCED_PARAMETER(hInstall);
		/*EIDAuthenticationPackageDllUnRegister();
		EIDCredentialProviderDllUnRegister();
		EIDPasswordChangeNotificationDllUnRegister();
		EIDConfigurationWizardDllUnRegister();*/
		DWORD dwError = 0;
		int ret = ERROR_INSTALL_FAILURE;
		__try
		{
			if (!LsaEIDRemoveAllStoredCredential())
			{
				dwError = GetLastError();
				__leave;
			}
			// this function is unimplemented and trigger the reboot,
			// but call it anyway
			if (!UnRegisterTheSecurityPackage())
			{
				dwError = GetLastError();
				__leave;
			}
			ret = ERROR_SUCCESS;
		}
		__finally
		{
			if (dwError == ERROR_FAIL_NOACTION_REBOOT)
			{
				GlobalAddAtom(TEXT("WcaDeferredActionRequiresReboot"));
				ret = ERROR_SUCCESS;
			}
			else if (dwError != 0)
			{
				MessageBoxWin32(dwError);
			}
		}
		return ret;
	}
}