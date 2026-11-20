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
