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
#pragma comment(lib,"Crypt32")

#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/AutoLogon.h"

BOOL LsaEIDRemoveAllStoredCredential();
BOOL LsaEIDRemoveStoredCredential(__in_opt PWSTR szUsername);
BOOL LsaEIDHasStoredCredential(__in_opt PWSTR szUsername);
BOOL LsaEIDExportStoredCredential(__in PWSTR szUsername, __out PBYTE* ppbData, __out PDWORD pcbData);
BOOL LsaEIDImportStoredCredential(__in PWSTR szUsername, __in_bcount(cbData) PBYTE pbData, __in DWORD cbData);
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
	// CREATE_NEW : never write through a file or link planted at that path (we run as SYSTEM)
	return CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
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

// "<account> TAB <rid> TAB saved|none|error TAB card|-|stale"
static VOID WritePinState(__in HANDLE hOut, __in PCWSTR szName, __in DWORD dwRid)
{
	WCHAR szPin[32];
	PCWSTR szCard = L"-";
	if (EIDIsAutoLogonPinStored(dwRid))
	{
		wcscpy_s(szPin, ARRAYSIZE(szPin), L"saved");
	}
	else if (GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		wcscpy_s(szPin, ARRAYSIZE(szPin), L"none");
	}
	else
	{
		swprintf_s(szPin, ARRAYSIZE(szPin), L"error 0x%08X", GetLastError());
	}
	if (dwRid && LsaEIDHasStoredCredential((PWSTR) szName))
	{
		szCard = EIDIsPasswordStale(dwRid) ? L"card (password changed)" : L"card";
	}
	WriteOutputLine(hOut, L"%s\t0x%X\t%s\t%s", szName, dwRid, szPin, szCard);
}

// card copy file (ExportUserCard / ImportUserCard), ASCII lines :
//   EIDCARD1
//   account=<account name, UTF-8>
//   credential=<base64 of the stored credential : certificate + key wrapped for the card + encrypted password>
//   pin=<saved tap sign-in PIN, UTF-8>   (only when exported with the PIN)
// The pin line is a secret : the file must travel admin to admin and be deleted after the import.
#define CARD_FILE_HEADER "EIDCARD1"
#define CARD_FILE_MAXSIZE 65536
#define CARD_PIN_MAXLEN 64   // AUTOLOGON_PIN_MAXLEN in AutoLogon.cpp

static BOOL WriteUtf8(__in HANDLE hFile, __in PCSTR szKey, __in PCWSTR szValue)
{
	CHAR szBuffer[1024];
	int iLen = sprintf_s(szBuffer, ARRAYSIZE(szBuffer), "%s=", szKey);
	int iValue = WideCharToMultiByte(CP_UTF8, 0, szValue, -1, szBuffer + iLen, ARRAYSIZE(szBuffer) - iLen - 2, NULL, NULL);
	if (iLen < 0 || iValue <= 0)
	{
		SecureZeroMemory(szBuffer, sizeof(szBuffer));
		return FALSE;
	}
	iLen += iValue - 1;
	szBuffer[iLen++] = '\r';
	szBuffer[iLen++] = '\n';
	DWORD dwWritten;
	BOOL fReturn = WriteFile(hFile, szBuffer, iLen, &dwWritten, NULL);
	SecureZeroMemory(szBuffer, sizeof(szBuffer));
	return fReturn;
}

static BOOL WriteCardFile(__in HANDLE hFile, __in PCWSTR szUser, __in PBYTE pbData, __in DWORD cbData, __in_opt PCWSTR szPin)
{
	DWORD dwB64 = 0, dwWritten;
	if (!CryptBinaryToStringA(pbData, cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwB64))
	{
		return FALSE;
	}
	PSTR szB64 = (PSTR) EIDAlloc(dwB64);
	if (!szB64)
	{
		return FALSE;
	}
	BOOL fReturn = CryptBinaryToStringA(pbData, cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, szB64, &dwB64)
		&& WriteFile(hFile, CARD_FILE_HEADER "\r\n", (DWORD) strlen(CARD_FILE_HEADER "\r\n"), &dwWritten, NULL)
		&& WriteUtf8(hFile, "account", szUser)
		&& WriteFile(hFile, "credential=", 11, &dwWritten, NULL)
		&& WriteFile(hFile, szB64, (DWORD) strlen(szB64), &dwWritten, NULL)
		&& WriteFile(hFile, "\r\n", 2, &dwWritten, NULL)
		&& (!szPin || WriteUtf8(hFile, "pin", szPin));
	EIDFree(szB64);
	return fReturn;
}

// reads the card copy file named by EID_AUTOLOGON_IN. *pszText receives the whole file (to zero and free),
// the other pointers point into it; szPin is NULL when the file holds no PIN.
static DWORD ReadCardFile(__out PSTR* pszText, __out PSTR* pszAccount, __out PSTR* pszCredential, __out PSTR* pszPin)
{
	WCHAR szPath[MAX_PATH];
	*pszText = *pszAccount = *pszCredential = *pszPin = NULL;
	DWORD dwLen = GetEnvironmentVariableW(L"EID_AUTOLOGON_IN", szPath, ARRAYSIZE(szPath));
	if (dwLen == 0 || dwLen >= ARRAYSIZE(szPath))
	{
		return ERROR_BAD_ARGUMENTS;
	}
	HANDLE hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return GetLastError();
	}
	DWORD dwSize = GetFileSize(hFile, NULL), dwRead = 0, dwError = 0;
	PSTR szText = NULL;
	if (dwSize == INVALID_FILE_SIZE || dwSize == 0 || dwSize > CARD_FILE_MAXSIZE)
	{
		dwError = ERROR_INVALID_DATA;
	}
	else if (!(szText = (PSTR) EIDAlloc(dwSize + 1)))
	{
		dwError = GetLastError();
	}
	else if (!ReadFile(hFile, szText, dwSize, &dwRead, NULL) || dwRead != dwSize)
	{
		dwError = ERROR_READ_FAULT;
	}
	CloseHandle(hFile);
	if (dwError)
	{
		if (szText) EIDFree(szText);
		return dwError;
	}
	szText[dwSize] = '\0';
	*pszText = szText;
	BOOL fHeader = FALSE;
	PSTR szContext = NULL;
	for (PSTR szLine = strtok_s(szText, "\r\n", &szContext); szLine; szLine = strtok_s(NULL, "\r\n", &szContext))
	{
		if (!fHeader)
		{
			if (strcmp(szLine, CARD_FILE_HEADER) != 0)
			{
				return ERROR_INVALID_DATA;
			}
			fHeader = TRUE;
		}
		else if (strncmp(szLine, "account=", 8) == 0) *pszAccount = szLine + 8;
		else if (strncmp(szLine, "credential=", 11) == 0) *pszCredential = szLine + 11;
		else if (strncmp(szLine, "pin=", 4) == 0) *pszPin = szLine + 4;
	}
	return (fHeader && *pszCredential && (*pszCredential)[0]) ? 0 : ERROR_INVALID_DATA;
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
		// v0.3.0 : nothing in lsass anymore (LSA protection can stay on). An upgrade from
		// v0.2.0 removes the authentication and notification packages and the wizard.
		EIDAuthenticationPackageDllUnRegister();
		EIDPasswordChangeNotificationDllUnRegister();
		EIDConfigurationWizardDllUnRegister();
		EIDCredentialProviderDllRegister();
		EIDRegisterEventSource();
	}

	void NTAPI DllUnRegister()
	{
		EIDAuthenticationPackageDllUnRegister();
		EIDCredentialProviderDllUnRegister();
		EIDPasswordChangeNotificationDllUnRegister();
		EIDConfigurationWizardDllUnRegister();
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

	// rundll32 EIDAuthenticationPackage.dll,RemoveUserCard
	// unenrolls the card of the account named by EID_AUTOLOGON_USER and forgets its PIN (offboarding)
	void NTAPI RemoveUserCard()
	{
		WCHAR szUser[UNLEN+1];
		DWORD dwLen = GetEnvironmentVariableW(L"EID_AUTOLOGON_USER", szUser, ARRAYSIZE(szUser));
		if (dwLen == 0 || dwLen >= ARRAYSIZE(szUser))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EID_AUTOLOGON_USER missing or too long");
			return;
		}
		DWORD dwRid = GetRidFromUsername(szUser);
		if (!dwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unknown account %s",szUser);
			return;
		}
		ClearAccount(szUser, dwRid, NULL);
		EIDSetPasswordStale(dwRid, FALSE);
		if (LsaEIDRemoveStoredCredential(szUser))
		{
			EIDAuditEvent(EVENTLOG_INFORMATION_TYPE, EID_EVENT_PIN_ADMIN,
				L"An administrator removed the card of %s (RID 0x%X).", szUser, dwRid);
		}
	}

	// rundll32 EIDAuthenticationPackage.dll,ExportUserCard
	// writes the card copy file of the account named by EID_AUTOLOGON_USER to EID_AUTOLOGON_OUT
	// (CREATE_NEW), with its saved tap sign-in PIN when EID_AUTOLOGON_WITHPIN=1. Needs SYSTEM.
	void NTAPI ExportUserCard()
	{
		WCHAR szUser[UNLEN+1], szWithPin[4];
		PBYTE pbData = NULL;
		DWORD cbData = 0;
		PWSTR szPin = NULL;
		DWORD dwLen = GetEnvironmentVariableW(L"EID_AUTOLOGON_USER", szUser, ARRAYSIZE(szUser));
		if (dwLen == 0 || dwLen >= ARRAYSIZE(szUser))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EID_AUTOLOGON_USER missing or too long");
			return;
		}
		DWORD dwRid = GetRidFromUsername(szUser);
		if (!dwRid || !LsaEIDExportStoredCredential(szUser, &pbData, &cbData))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No card to export for %s 0x%08x", szUser, GetLastError());
			return;
		}
		dwLen = GetEnvironmentVariableW(L"EID_AUTOLOGON_WITHPIN", szWithPin, ARRAYSIZE(szWithPin));
		BOOL fWithPin = (dwLen == 1 && szWithPin[0] == L'1');
		if (fWithPin && (!EIDIsAutoLogonPinStored(dwRid) || !EIDGetAutoLogonPin(dwRid, &szPin)))
		{
			szPin = NULL;
		}
		HANDLE hOut = OpenOutput();
		if (hOut == INVALID_HANDLE_VALUE)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OpenOutput 0x%08x",GetLastError());
		}
		else
		{
			if (!WriteCardFile(hOut, szUser, pbData, cbData, szPin))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WriteCardFile 0x%08x",GetLastError());
			}
			else
			{
				EIDAuditEvent(EVENTLOG_INFORMATION_TYPE, EID_EVENT_PIN_ADMIN,
					L"An administrator exported the card of %s (RID 0x%X) %s.", szUser, dwRid,
					szPin ? L"with its saved PIN" : L"without a PIN");
			}
			CloseHandle(hOut);
		}
		if (szPin)
		{
			SecureZeroMemory(szPin, wcslen(szPin) * sizeof(WCHAR));
			EIDFree(szPin);
		}
		SecureZeroMemory(pbData, cbData);
		EIDFree(pbData);
	}

	// rundll32 EIDAuthenticationPackage.dll,ImportUserCard
	// enrolls the card of the copy file EID_AUTOLOGON_IN for the account named by EID_AUTOLOGON_USER
	// (default : the account in the file) and saves its PIN when the file has one. The card must be
	// trusted here and not enrolled for another account. Writes "OK" or "ERROR 0x..." to
	// EID_AUTOLOGON_OUT. Needs SYSTEM.
	void NTAPI ImportUserCard()
	{
		WCHAR szUser[UNLEN+1];
		WCHAR szPin[CARD_PIN_MAXLEN + 1];
		PSTR szText = NULL, szAccount = NULL, szCredential = NULL, szFilePin = NULL;
		PBYTE pbData = NULL;
		DWORD cbData = 0, dwRid = 0;
		BOOL fPin = FALSE;
		szPin[0] = L'\0';
		DWORD dwError = ReadCardFile(&szText, &szAccount, &szCredential, &szFilePin);
		__try
		{
			if (dwError)
			{
				__leave;
			}
			DWORD dwLen = GetEnvironmentVariableW(L"EID_AUTOLOGON_USER", szUser, ARRAYSIZE(szUser));
			if (dwLen >= ARRAYSIZE(szUser))
			{
				dwError = ERROR_BAD_ARGUMENTS;
				__leave;
			}
			if (dwLen == 0 && (!szAccount || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szAccount, -1, szUser, ARRAYSIZE(szUser))))
			{
				dwError = ERROR_BAD_ARGUMENTS;
				__leave;
			}
			dwRid = GetRidFromUsername(szUser);
			if (!dwRid)
			{
				dwError = ERROR_NONE_MAPPED;
				__leave;
			}
			if (szFilePin && szFilePin[0])
			{
				if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szFilePin, -1, szPin, ARRAYSIZE(szPin)))
				{
					dwError = ERROR_INVALID_DATA;
					__leave;
				}
				fPin = TRUE;
			}
			if (!CryptStringToBinaryA(szCredential, 0, CRYPT_STRING_BASE64, NULL, &cbData, NULL, NULL)
				|| !(pbData = (PBYTE) EIDAlloc(cbData))
				|| !CryptStringToBinaryA(szCredential, 0, CRYPT_STRING_BASE64, pbData, &cbData, NULL, NULL))
			{
				dwError = ERROR_INVALID_DATA;
				__leave;
			}
			if (!LsaEIDImportStoredCredential(szUser, pbData, cbData))
			{
				dwError = GetLastError();
				if (!dwError) dwError = ERROR_INVALID_DATA;
				__leave;
			}
			EIDSetPasswordStale(dwRid, FALSE);
			if (fPin && !EIDSetUserAutoLogonPin(dwRid, szPin))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDSetUserAutoLogonPin 0x%08x", dwError);
			}
			EIDAuditEvent(EVENTLOG_INFORMATION_TYPE, EID_EVENT_PIN_ADMIN,
				L"An administrator imported the card of %s (RID 0x%X) from another computer %s.", szUser, dwRid,
				fPin && !dwError ? L"with its saved PIN" : L"without a PIN");
		}
		__finally
		{
			SecureZeroMemory(szPin, sizeof(szPin));
			if (pbData)
			{
				SecureZeroMemory(pbData, cbData);
				EIDFree(pbData);
			}
			if (szText)
			{
				SecureZeroMemory(szText, strlen(szText));
				EIDFree(szText);
			}
		}
		HANDLE hOut = OpenOutput();
		if (hOut != INVALID_HANDLE_VALUE)
		{
			if (dwError)
			{
				WriteOutputLine(hOut, L"ERROR 0x%08X", dwError);
			}
			else
			{
				WriteOutputLine(hOut, L"OK %s", szUser);
			}
			CloseHandle(hOut);
		}
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
			// v0.3.0 : no security package to register
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