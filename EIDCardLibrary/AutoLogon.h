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

#pragma once

/** Auto logon on card insertion (AndersonTech kiosk mode)

When the AutoLogonOnCardInsert policy is set, the credential provider logs on as soon as
an enrolled card is inserted, with a PIN stored in a LSA secret (readable only by SYSTEM
and the administrators) :
- the PIN of the user, learnt by the authentication package at the first successful PIN
  logon of this user on this computer (one PIN per employee, same on every station)
- else the PIN of the computer, set by SetAutoLogonPin (all the badges share it)
The possession of the card is then enough to log on.
*/

// set the PIN of the computer. NULL removes it.
BOOL EIDSetAutoLogonPin(__in_opt PCWSTR szPin);
// set the PIN learnt for a user. NULL removes it.
BOOL EIDSetUserAutoLogonPin(__in DWORD dwRid, __in_opt PCWSTR szPin);
// PIN of the user (dwRid != 0), else PIN of the computer.
// The caller must SecureZeroMemory and EIDFree it.
BOOL EIDGetAutoLogonPin(__in DWORD dwRid, __out PWSTR* pszPin);
BOOL EIDHasAutoLogonPin(__in DWORD dwRid);
// called by the authentication package after a successful PIN logon
VOID EIDLearnUserAutoLogonPin(__in DWORD dwRid, __in PCWSTR szPin);
// removes the PIN learnt for a user. TRUE when one was stored.
BOOL EIDForgetUserAutoLogonPin(__in DWORD dwRid);
// the stored password of a user was refused by Windows (changed elsewhere, e.g. by JumpCloud) :
// the tile asks for the new one instead of retrying it at each insertion
BOOL EIDIsPasswordStale(__in DWORD dwRid);
VOID EIDSetPasswordStale(__in DWORD dwRid, __in BOOL fStale);
// a PIN is stored for this user (dwRid != 0) or for the computer (dwRid == 0), no fallback.
// FALSE with ERROR_FILE_NOT_FOUND when there is none.
BOOL EIDIsAutoLogonPinStored(__in DWORD dwRid);

/** Audit trail : events of the Application log, source "EIDAuthentication"
(the message file of .NET displays the text of each event as is) */
#define EID_EVENT_SOURCE L"EIDAuthentication"
#define EID_EVENT_LOGON_TAP_OK		1000
#define EID_EVENT_LOGON_TAP_FAILED	1001
#define EID_EVENT_LOGON_PIN_OK		1002
#define EID_EVENT_LOGON_PIN_FAILED	1003
#define EID_EVENT_PIN_LEARNT		1010
#define EID_EVENT_PIN_FORGOTTEN		1011
#define EID_EVENT_CARD_ENROLLED		1012
#define EID_EVENT_PASSWORD_UPDATED	1013
#define EID_EVENT_PIN_ADMIN			1020
VOID EIDAuditEvent(__in WORD wType, __in DWORD dwEventId, __in PCWSTR szFormat, ...);
BOOL EIDRegisterEventSource();
BOOL EIDUnRegisterEventSource();
