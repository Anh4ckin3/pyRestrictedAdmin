# pyRestrictedAdmin

pyRestrictedAdmin is a Python tool to perform many actions on the **DisableRestrictedAdmin** registry key on a remote Windows machine with the impacket lib. Handling this registry key allows Pass-The-Hash (PTH) on RDP. Normally, modifying this registry value is done via PowerShell or cmd.exe. However, in some situations, a shell cannot be obtained on the machine. With this script, you can enable Restricted Admin remotely in an OPSEC-safe way.

## Articles and ressources :

- [RestrictedAdmin CSharp](https://github.com/GhostPack/RestrictedAdmin)
- [PTH on RDP (for french)](https://www.xmco.fr/audit-fr-fr/pass-the-hash-protocol-rdp/)
- [Abusing RDP’s Remote Credential Guard with Rubeus PTT](https://www.pentestpartners.com/security-blog/abusing-rdps-remote-credential-guard-with-rubeus-ptt/)

## Installation   

### dependencies  
```bash
git clone https://github.com/Anh4ckin3/pyRestrictedAdmin
cd restrictedadmin-manager
pip install -r requirements.txt
```

## Usage 

This tool takes part of the impacket lib, the syntax of the tool is the same as impacket.

- Action read : See the value of the registry key and deduce if PTH is is possible or not
```bash
python pyRestrictedAdmin.py -action enable <DOMAIN.LOCAL>/<USER>:'<PASSWORD>'@<TARGET_IP>
```

- Action disable : Set value to 1, PTH will be no longer possible
```
python pyRestrictedAdmin.py -action disable <DOMAIN.LOCAL>/<USER>:'<PASSWORD>'@<TARGET_IP>
```

- Action enable : Set value to 0, that will enable the security option "RestricedAdmin" and allow PTH on RDP
```bash
python pyRestrictedAdmin.py -action enable <DOMAIN.LOCAL>/<USER>:'<PASSWORD>'@<TARGET_IP>
```
---
> [!NOTE]
> Soon, PR on impacket
> PR on nxc is done [PR #617](https://github.com/Pennyw0rth/NetExec/pull/617)

