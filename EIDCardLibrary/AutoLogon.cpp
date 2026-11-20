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
#include <Ntsecapi.h>

#include "EidCardLibrary.h"
#include "Tracing.h"
#include "AutoLogon.h"

#pragma comment(lib,"advapi32")

#define AUTOLOGON_PIN_SECRET L"L$_EID_AutoLogonPin"
#define AUTOLOGON_PIN_MAXLEN 64

static VOID InitSecretName(PLSA_UNICODE_STRING plusSecretName)
{
	plusSecretName->Buffer = (PWSTR) AUTOLOGON_PIN_SECRET;
	plusSecretName->Length = (USHORT) (wcslen(AUTOLOGON_PIN_SECRET) * sizeof(WCHAR));
	plusSecretName->MaximumLength = plusSecretName->Length;
}

BOOL EIDSetAutoLogonPin(__in_opt PCWSTR szPin)
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_HANDLE LsaPolicyHandle = NULL;
	LSA_UNICODE_STRING lusSecretName;
	LSA_UNICODE_STRING lusSecretData;
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
		InitSecretName(&lusSecretName);
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
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Auto logon PIN %s", szPin ? L"set" : L"cleared");
		fReturn = TRUE;
	}
	__finally
	{
		if (LsaPolicyHandle) LsaClose(LsaPolicyHandle);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL EIDGetAutoLogonPin(__out PWSTR* pszPin)
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_HANDLE LsaPolicyHandle = NULL;
	LSA_UNICODE_STRING lusSecretName;
	PLSA_UNICODE_STRING pData = NULL;
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
		InitSecretName(&lusSecretName);
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

BOOL EIDHasAutoLogonPin()
{
	PWSTR szPin = NULL;
	if (!EIDGetAutoLogonPin(&szPin))
	{
		return FALSE;
	}
	SecureZeroMemory(szPin, wcslen(szPin) * sizeof(WCHAR));
	EIDFree(szPin);
	return TRUE;
}
