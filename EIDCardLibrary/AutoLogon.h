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

The PIN of the badges is stored once per computer in a LSA secret, readable only
by SYSTEM and the administrators. When the AutoLogonOnCardInsert policy is set,
the credential provider uses it to log on as soon as an enrolled card is inserted :
the possession of the card is then enough to log on.
*/

// set the PIN used for auto logon. NULL removes it.
BOOL EIDSetAutoLogonPin(__in_opt PCWSTR szPin);
// retrieve the PIN. The caller must SecureZeroMemory and EIDFree it.
BOOL EIDGetAutoLogonPin(__out PWSTR* pszPin);
BOOL EIDHasAutoLogonPin();
