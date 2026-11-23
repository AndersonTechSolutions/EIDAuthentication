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

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Ntsecapi.h>

#include "EidCardLibrary.h"
#include "Tracing.h"
#include "AutoLogon.h"

#pragma comment(lib,"advapi32")

#include "GPO.h"

#define AUTOLOGON_PIN_SECRET L"L$_EID_AutoLogonPin"
#define AUTOLOGON_PIN_MAXLEN 64

// secret of the computer, or of a user when dwRid != 0
static VOID InitSecretName(__in DWORD dwRid, __out_ecount(64) PWSTR szName, __out PLSA_UNICODE_STRING plusSecretName)
{
	if (dwRid)
	{
		swprintf_s(szName, 64, L"%s_%08X", AUTOLOGON_PIN_SECRET, dwRid);
	}
	else
	{
		wcscpy_s(szName, 64, AUTOLOGON_PIN_SECRET);
	}
	plusSecretName->Buffer = szName;
	plusSecretName->Length = (USHORT) (wcslen(szName) * sizeof(WCHAR));
	plusSecretName->MaximumLength = plusSecretName->Length;
}

static BOOL StorePin(__in DWORD dwRid, __in_opt PCWSTR szPin)
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_HANDLE LsaPolicyHandle = NULL;
	LSA_UNICODE_STRING lusSecretName;
	LSA_UNICODE_STRING lusSecretData;
	WCHAR szName[64];
	NTSTATUS ntsResult;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	__try
	{
		if (szPin && (wcslen(szPin) == 0 || wcslen(szPin) > AUTOLOGON_PIN_MAXLEN))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Invalid PIN length");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		ntsResult = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_CREATE_SECRET, &LsaPolicyHandle);
		if (STATUS_SUCCESS != ntsResult)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaOpenPolicy", ntsResult);
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		}
		InitSecretName(dwRid, szName, &lusSecretName);
		if (szPin)
		{
			lusSecretData.Buffer = (PWSTR) szPin;
			lusSecretData.Length = (USHORT) (wcslen(szPin) * sizeof(WCHAR));
			lusSecretData.MaximumLength = lusSecretData.Length;
			ntsResult = LsaStorePrivateData(LsaPolicyHandle, &lusSecretName, &lusSecretData);
		}
		else
		{
			ntsResult = LsaStorePrivateData(LsaPolicyHandle, &lusSecretName, NULL);
		}
		if (STATUS_SUCCESS != ntsResult && !(szPin == NULL && STATUS_OBJECT_NAME_NOT_FOUND == ntsResult))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaStorePrivateData", ntsResult);
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Auto logon PIN %s for rid 0x%x", szPin ? L"set" : L"cleared", dwRid);
		fReturn = TRUE;
	}
	__finally
	{
		if (LsaPolicyHandle) LsaClose(LsaPolicyHandle);
	}
	SetLastError(dwError);
	return fReturn;
}

static BOOL RetrievePin(__in DWORD dwRid, __out PWSTR* pszPin)
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_HANDLE LsaPolicyHandle = NULL;
	LSA_UNICODE_STRING lusSecretName;
	PLSA_UNICODE_STRING pData = NULL;
	WCHAR szName[64];
	NTSTATUS ntsResult;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	*pszPin = NULL;
	__try
	{
		ntsResult = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_GET_PRIVATE_INFORMATION, &LsaPolicyHandle);
		if (STATUS_SUCCESS != ntsResult)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaOpenPolicy", ntsResult);
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		}
		InitSecretName(dwRid, szName, &lusSecretName);
		ntsResult = LsaRetrievePrivateData(LsaPolicyHandle, &lusSecretName, &pData);
		if (STATUS_SUCCESS != ntsResult)
		{
			if (STATUS_OBJECT_NAME_NOT_FOUND != ntsResult)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaRetrievePrivateData", ntsResult);
			}
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		}
		if (!pData || pData->Length == 0 || pData->Length > AUTOLOGON_PIN_MAXLEN * sizeof(WCHAR))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Invalid auto logon PIN");
			dwError = ERROR_INVALID_DATA;
			__leave;
		}
		*pszPin = (PWSTR) EIDAlloc(pData->Length + sizeof(WCHAR));
		if (!*pszPin)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", dwError);
			__leave;
		}
		memcpy(*pszPin, pData->Buffer, pData->Length);
		(*pszPin)[pData->Length / sizeof(WCHAR)] = L'\0';
		fReturn = TRUE;
	}
	__finally
	{
		if (pData)
		{
			SecureZeroMemory(pData->Buffer, pData->Length);
			LsaFreeMemory(pData);
		}
		if (LsaPolicyHandle) LsaClose(LsaPolicyHandle);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL EIDSetAutoLogonPin(__in_opt PCWSTR szPin)
{
	return StorePin(0, szPin);
}

BOOL EIDSetUserAutoLogonPin(__in DWORD dwRid, __in_opt PCWSTR szPin)
{
	if (!dwRid)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	return StorePin(dwRid, szPin);
}

BOOL EIDGetAutoLogonPin(__in DWORD dwRid, __out PWSTR* pszPin)
{
	if (dwRid && RetrievePin(dwRid, pszPin))
	{
		return TRUE;
	}
	return RetrievePin(0, pszPin);
}

BOOL EIDHasAutoLogonPin(__in DWORD dwRid)
{
	PWSTR szPin = NULL;
	if (!EIDGetAutoLogonPin(dwRid, &szPin))
	{
		return FALSE;
	}
	SecureZeroMemory(szPin, wcslen(szPin) * sizeof(WCHAR));
	EIDFree(szPin);
	return TRUE;
}

VOID EIDLearnUserAutoLogonPin(__in DWORD dwRid, __in PCWSTR szPin)
{
	PWSTR szStoredPin = NULL;
	if (!dwRid || !szPin || !szPin[0] || !GetPolicyValue(AutoLogonOnCardInsert))
	{
		return;
	}
	BOOL fChanged = FALSE;
	// write only when it changed (the PIN can come from the secret itself)
	if (RetrievePin(dwRid, &szStoredPin))
	{
		BOOL fSame = (wcscmp(szStoredPin, szPin) == 0);
		SecureZeroMemory(szStoredPin, wcslen(szStoredPin) * sizeof(WCHAR));
		EIDFree(szStoredPin);
		if (fSame)
		{
			return;
		}
		fChanged = TRUE;
	}
	if (!StorePin(dwRid, szPin))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to learn the PIN of rid 0x%x : 0x%08x", dwRid, GetLastError());
		return;
	}
	EIDAuditEvent(EVENTLOG_INFORMATION_TYPE, EID_EVENT_PIN_LEARNT,
		L"Saved the tap sign-in PIN of account RID 0x%X after a PIN sign-in (%s).",
		dwRid, fChanged ? L"the PIN changed" : L"first PIN sign-in on this computer");
}

BOOL EIDIsAutoLogonPinStored(__in DWORD dwRid)
{
	PWSTR szPin = NULL;
	if (!RetrievePin(dwRid, &szPin))
	{
		return FALSE;
	}
	SecureZeroMemory(szPin, wcslen(szPin) * sizeof(WCHAR));
	EIDFree(szPin);
	return TRUE;
}

BOOL EIDForgetUserAutoLogonPin(__in DWORD dwRid)
{
	if (!dwRid || !EIDIsAutoLogonPinStored(dwRid))
	{
		return FALSE;
	}
	return StorePin(dwRid, NULL);
}

#define EID_EVENT_KEY L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" EID_EVENT_SOURCE
// no message file of our own : the one of .NET (part of Windows) formats every event id as "%1"
#define EID_EVENT_MESSAGE_FILE L"%SystemRoot%\\Microsoft.NET\\Framework64\\v4.0.30319\\EventLogMessages.dll"

VOID EIDAuditEvent(__in WORD wType, __in DWORD dwEventId, __in PCWSTR szFormat, ...)
{
	WCHAR szMessage[512];
	va_list ap;
	va_start(ap, szFormat);
	_vsnwprintf_s(szMessage, ARRAYSIZE(szMessage), _TRUNCATE, szFormat, ap);
	va_end(ap);
	HANDLE hEventLog = RegisterEventSourceW(NULL, EID_EVENT_SOURCE);
	if (!hEventLog)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by RegisterEventSource", GetLastError());
		return;
	}
	LPCWSTR rgszStrings[1] = {szMessage};
	if (!ReportEventW(hEventLog, wType, 0, dwEventId, NULL, 1, 0, rgszStrings, NULL))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by ReportEvent", GetLastError());
	}
	DeregisterEventSource(hEventLog);
}

BOOL EIDRegisterEventSource()
{
	HKEY hKey = NULL;
	DWORD dwTypes = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
	LONG lStatus = RegCreateKeyExW(HKEY_LOCAL_MACHINE, EID_EVENT_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
	if (ERROR_SUCCESS == lStatus)
	{
		lStatus = RegSetValueExW(hKey, L"EventMessageFile", 0, REG_EXPAND_SZ, (PBYTE) EID_EVENT_MESSAGE_FILE, (DWORD) sizeof(EID_EVENT_MESSAGE_FILE));
		if (ERROR_SUCCESS == lStatus)
		{
			lStatus = RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD, (PBYTE) &dwTypes, sizeof(dwTypes));
		}
		RegCloseKey(hKey);
	}
	if (ERROR_SUCCESS != lStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to register the event source 0x%08x", lStatus);
	}
	SetLastError(lStatus);
	return ERROR_SUCCESS == lStatus;
}

BOOL EIDUnRegisterEventSource()
{
	LONG lStatus = RegDeleteKeyW(HKEY_LOCAL_MACHINE, EID_EVENT_KEY);
	if (ERROR_FILE_NOT_FOUND == lStatus)
	{
		lStatus = ERROR_SUCCESS;
	}
	SetLastError(lStatus);
	return ERROR_SUCCESS == lStatus;
}
